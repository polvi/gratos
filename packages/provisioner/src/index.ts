import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie } from 'hono/cookie';
import { CloudflareCustomHostnames } from './cf-api';
import { discoverDomainConnect, buildApplyUrl, signDomainConnectRequest } from './domain-connect';

import type { AuthRPC } from '../../gratos-multi/src/index';

type Env = {
    DB: D1Database;
    CF_API_TOKEN: string;
    CF_ZONE_ID: string;
    CORS_ALLOW_ORIGIN?: string;
    AUTH: Service<AuthRPC>;
    AUTH_TENANT: string;
    DC_SIGNING_KEY?: string;
    PROVISIONER_BASE_URL?: string;
    SIGNUP_BASE_URL?: string;
};

type Variables = {
    identityId: string;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// CORS
app.use('/*', (c, next) => {
    const origins = (c.env.CORS_ALLOW_ORIGIN || 'http://localhost:4322').split(',');
    return cors({
        origin: origins,
        allowHeaders: ['Content-Type'],
        allowMethods: ['POST', 'GET', 'OPTIONS', 'DELETE'],
        maxAge: 600,
        credentials: true,
    })(c, next);
});

// Auth middleware — validates session via gratos-multi RPC service binding
const authMiddleware = async (c: any, next: any) => {
    const sessionId = getCookie(c, 'session_id');
    if (!sessionId) {
        return c.json({ error: 'Not authenticated' }, 401);
    }

    const tenant = c.env.AUTH_TENANT || 'localhost';
    const userId = await c.env.AUTH.resolveSession(tenant, sessionId);
    if (!userId) {
        return c.json({ error: 'Session expired' }, 401);
    }

    c.set('identityId', userId);
    await next();
};

/** Generate a short random token for unique CNAME challenges */
function generateToken(): string {
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    // Base32-like encoding: lowercase alphanumeric, no ambiguous chars
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    let token = '';
    for (const b of bytes) {
        token += alphabet[b % alphabet.length];
    }
    return token;
}

type DnsLookupResult = {
    cname: string | null;
    other: Array<{ type: string; value: string }>;
};

const DNS_TYPE_NAMES: Record<number, string> = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA',
};

/** Look up DNS records for a hostname via Cloudflare DNS-over-HTTPS.
 *  Returns CNAME target if found, plus any other records (A, AAAA, etc). */
async function lookupDNS(hostname: string): Promise<DnsLookupResult> {
    const result: DnsLookupResult = { cname: null, other: [] };

    // Query CNAME first
    try {
        const res = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`,
            { headers: { 'Accept': 'application/dns-json' } }
        );
        if (res.ok) {
            const data = await res.json() as { Answer?: { type: number; data: string }[] };
            const cname = data.Answer?.find((r: any) => r.type === 5);
            if (cname) {
                result.cname = cname.data.replace(/\.$/, '');
                return result;
            }
        }
    } catch { /* continue */ }

    // No direct CNAME — check A/AAAA which may include CNAME chain hops
    const seen = new Set<string>();
    for (const qtype of ['A', 'AAAA']) {
        try {
            const res = await fetch(
                `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${qtype}`,
                { headers: { 'Accept': 'application/dns-json' } }
            );
            if (res.ok) {
                const data = await res.json() as { Answer?: { type: number; data: string; name: string }[] };
                if (data.Answer) {
                    for (const r of data.Answer) {
                        const value = r.data.replace(/\.$/, '');
                        // A/AAAA responses include CNAME hops in the chain
                        if (r.type === 5 && !result.cname) {
                            result.cname = value;
                        } else {
                            const key = `${r.type}:${value}`;
                            if (!seen.has(key)) {
                                seen.add(key);
                                result.other.push({
                                    type: DNS_TYPE_NAMES[r.type] || `TYPE${r.type}`,
                                    value,
                                });
                            }
                        }
                    }
                }
            }
        } catch { /* continue */ }
    }

    // If we found a CNAME in the chain, clear the other records
    // since they're just the resolved values of the CNAME target
    if (result.cname) {
        result.other = [];
    }

    return result;
}

/** Advance a pending claim through the state machine.
 *  Returns a result object describing what happened. Used by both
 *  the /activate endpoint and the scheduled reconciliation loop.
 */
type AdvanceResult =
    | { status: 'waiting_for_dns'; domain: string; dns_lookup: string; dns_expected: string; dns_actual: string | null; dns_found: Array<{ type: string; value: string }> }
    | { status: 'dns_mismatch'; domain: string; dns_lookup: string; dns_expected: string; dns_actual: string }
    | { status: 'provisioning'; domain: string }
    | { status: 'claimed'; id: string; domain: string; claimed_at: number }
    | { status: 'error'; error: string; code?: number };

async function advanceClaim(claim: any, env: Env): Promise<AdvanceResult> {
    const expectedTarget = `${claim.token}.cname.authgravity.net`;
    const hostname = `authgravity.${claim.domain}`;
    const dns = await lookupDNS(hostname);

    if (dns.cname !== expectedTarget) {
        if (dns.cname) {
            // CNAME exists but points to wrong target
            return {
                status: 'dns_mismatch',
                domain: claim.domain,
                dns_lookup: hostname,
                dns_expected: expectedTarget,
                dns_actual: dns.cname,
            };
        }
        // No CNAME — return whatever records we did find
        return {
            status: 'waiting_for_dns',
            domain: claim.domain,
            dns_lookup: hostname,
            dns_expected: expectedTarget,
            dns_actual: null,
            dns_found: dns.other,
        };
    }

    // --- Create CF custom hostname (if not already) ---
    if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) {
        return { status: 'error', error: 'CF API not configured', code: 500 };
    }

    const cf = new CloudflareCustomHostnames(env.CF_API_TOKEN, env.CF_ZONE_ID);

    if (!claim.cf_hostname_id) {
        let cfHostnameId: string;

        const existing = await cf.findByHostname(hostname);
        if (existing) {
            cfHostnameId = existing.id;
        } else {
            let result;
            try {
                result = await cf.create(hostname);
            } catch (err) {
                console.error('CF API request failed:', err);
                return { status: 'error', error: 'CF API request failed', code: 502 };
            }

            if (!result.success) {
                console.error('CF API error:', JSON.stringify(result.errors));
                return { status: 'error', error: 'CF API error', code: 502 };
            }
            cfHostnameId = result.result.id;
        }

        await env.DB.prepare(
            'UPDATE pending_claims SET cf_hostname_id = ? WHERE id = ?'
        ).bind(cfHostnameId, claim.id).run();
        claim.cf_hostname_id = cfHostnameId;
    }

    // --- Check CF hostname status ---
    const cfResult = await cf.get(claim.cf_hostname_id);
    if (!cfResult.success || cfResult.result.status !== 'active') {
        return { status: 'provisioning', domain: claim.domain };
    }

    // --- CF active — finalize and claim domain ---
    const existingClaimed = await env.DB.prepare(
        'SELECT id FROM domains WHERE domain = ?'
    ).bind(claim.domain).first();
    if (existingClaimed) {
        return { status: 'error', error: 'Domain already claimed by another identity', code: 409 };
    }

    // Re-verify CNAME hasn't changed
    const finalDns = await lookupDNS(`authgravity.${claim.domain}`);
    if (finalDns.cname !== expectedTarget) {
        return { status: 'error', error: 'CNAME target changed during provisioning', code: 403 };
    }

    // Collect losing claims
    const { results: losingClaims } = await env.DB.prepare(
        'SELECT id, cf_hostname_id FROM pending_claims WHERE domain = ? AND id != ?'
    ).bind(claim.domain, claim.id).all();

    const domainId = crypto.randomUUID();
    const claimedAt = Date.now();

    await env.DB.batch([
        env.DB.prepare(
            'INSERT INTO domains (id, identity_id, domain, cf_hostname_id, claimed_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(domainId, claim.identity_id, claim.domain, claim.cf_hostname_id, claimedAt),
        env.DB.prepare(
            'DELETE FROM pending_claims WHERE domain = ?'
        ).bind(claim.domain),
    ]);

    // Clean up losing claims' CF hostnames
    if (losingClaims) {
        for (const loser of losingClaims as any[]) {
            if (loser.cf_hostname_id) {
                try {
                    await cf.delete(loser.cf_hostname_id);
                } catch (err) {
                    console.error(`Failed to delete CF hostname for losing claim ${loser.id}:`, err);
                }
            }
        }
    }

    return { status: 'claimed', id: domainId, domain: claim.domain, claimed_at: claimedAt };
}

app.get('/', (c) => c.text('Gratos Provisioner Running'));

// =============================================
// Anonymous routes — claim ID is the bearer token
// =============================================

// --- POST /claims — EnterDomain: create pending claim with unique CNAME token ---
// Multiple claims for the same domain can coexist (different tokens).
// Only DNS owner can set the right CNAME, so only they progress.
app.post('/claims', async (c) => {
    const { domain } = await c.req.json();

    if (!domain || typeof domain !== 'string') {
        return c.json({ error: 'Invalid or missing "domain"' }, 400);
    }

    const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
        return c.json({ error: 'Invalid domain format' }, 400);
    }

    // OneDomainOneOwner: reject if already claimed
    const existingClaimed = await c.env.DB.prepare(
        'SELECT id FROM domains WHERE domain = ?'
    ).bind(domain).first();
    if (existingClaimed) {
        return c.json({ error: 'Domain already claimed' }, 409);
    }

    // No check for existing pending claims — multiple allowed per spec

    const id = crypto.randomUUID();
    const token = generateToken();
    const createdAt = Date.now();

    await c.env.DB.prepare(
        'INSERT INTO pending_claims (id, domain, token, created_at) VALUES (?, ?, ?, ?)'
    ).bind(id, domain, token, createdAt).run();

    return c.json({
        id,
        domain,
        token,
        cname_name: 'authgravity',
        cname_target: `${token}.cname.authgravity.net`,
        status: 'pending',
        created_at: createdAt,
    }, 201);
});

// --- GET /claims/:id — Get claim status, no auth (claim ID is secret) ---
app.get('/claims/:id', async (c) => {
    const claimId = c.req.param('id');

    // Check pending_claims first
    const pending = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ?'
    ).bind(claimId).first() as any;

    if (pending) {
        return c.json({
            id: pending.id,
            domain: pending.domain,
            token: pending.token,
            cname_name: 'authgravity',
            cname_target: `${pending.token}.cname.authgravity.net`,
            status: 'pending',
            has_identity: !!pending.identity_id,
            created_at: pending.created_at,
        });
    }

    // Check domains table
    const claimed = await c.env.DB.prepare(
        'SELECT * FROM domains WHERE id = ?'
    ).bind(claimId).first() as any;

    if (claimed) {
        return c.json({
            id: claimed.id,
            domain: claimed.domain,
            status: 'claimed',
            has_identity: true,
            claimed_at: claimed.claimed_at,
        });
    }

    return c.json({ error: 'Claim not found' }, 404);
});

// --- GET /claims/:id/domain-connect — Check if Domain Connect is available ---
app.get('/claims/:id/domain-connect', async (c) => {
    const claimId = c.req.param('id');

    const claim = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ?'
    ).bind(claimId).first() as any;

    if (!claim) {
        return c.json({ error: 'Claim not found' }, 404);
    }

    const discovery = await discoverDomainConnect(claim.domain);
    if (!discovery.supported) {
        return c.json({ supported: false });
    }

    const target = `${claim.token}.cname.authgravity.net`;
    const provisionerBase = c.env.PROVISIONER_BASE_URL || `https://${c.req.header('host')}`;
    const redirectUri = `${provisionerBase}/claims/${claimId}/domain-connect/callback`;

    let applyUrl = buildApplyUrl(discovery.settings, claim.domain, target, redirectUri);

    // Sign the request if we have a signing key
    if (c.env.DC_SIGNING_KEY) {
        try {
            const urlObj = new URL(applyUrl);
            const sig = await signDomainConnectRequest(urlObj.search.slice(1), c.env.DC_SIGNING_KEY);
            urlObj.searchParams.set('sig', sig);
            urlObj.searchParams.set('key', 'domainconnect.authgravity.org');
            applyUrl = urlObj.toString();
        } catch (err) {
            console.error('Failed to sign Domain Connect request:', err);
            // Continue without signature — unsigned flow still works for many providers
        }
    }

    return c.json({
        supported: true,
        apply_url: applyUrl,
        provider_name: discovery.settings.providerName,
    });
});

// --- GET /claims/:id/domain-connect/callback — DNS provider redirects here after approval ---
app.get('/claims/:id/domain-connect/callback', async (c) => {
    const claimId = c.req.param('id');

    const claim = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ?'
    ).bind(claimId).first() as any;

    if (!claim) {
        return c.text('Claim not found', 404);
    }

    const signupBase = c.env.SIGNUP_BASE_URL || 'https://authgravity.org';
    return c.redirect(`${signupBase}/signup?claim_id=${claimId}&dc=success`);
});

// =============================================
// Authenticated routes
// =============================================

// --- POST /claims/:id/activate — Drive the full claim lifecycle ---
// Client polls this. Also runs server-side on the cron tick via advanceClaim().
// States: waiting_for_dns → dns_mismatch → provisioning → claimed
app.post('/claims/:id/activate', authMiddleware, async (c) => {
    const identityId = c.get('identityId');
    const claimId = c.req.param('id');

    // Check if already claimed
    const existingDomain = await c.env.DB.prepare(
        'SELECT * FROM domains WHERE id = ?'
    ).bind(claimId).first() as any;
    if (existingDomain) {
        return c.json({ status: 'claimed', domain: existingDomain.domain, claimed_at: existingDomain.claimed_at });
    }

    const claim = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ?'
    ).bind(claimId).first() as any;

    if (!claim) {
        return c.json({ error: 'Claim not found' }, 404);
    }

    // Associate identity if not yet bound
    if (!claim.identity_id) {
        await c.env.DB.prepare(
            'UPDATE pending_claims SET identity_id = ? WHERE id = ?'
        ).bind(identityId, claimId).run();
        claim.identity_id = identityId;
    } else if (claim.identity_id !== identityId) {
        return c.json({ error: 'Claim owned by another identity' }, 403);
    }

    const result = await advanceClaim(claim, c.env);

    if (result.status === 'error') {
        return c.json({ error: result.error }, result.code || 500);
    }

    return c.json(result);
});

// --- DELETE /claims/:id — Cancel claim, requires auth ---
app.delete('/claims/:id', authMiddleware, async (c) => {
    const identityId = c.get('identityId');
    const claimId = c.req.param('id');

    const claim = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ? AND identity_id = ?'
    ).bind(claimId, identityId).first() as any;

    if (!claim) {
        return c.json({ error: 'Claim not found' }, 404);
    }

    if (claim.cf_hostname_id) {
        const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
        await cf.delete(claim.cf_hostname_id);
    }

    await c.env.DB.prepare('DELETE FROM pending_claims WHERE id = ?').bind(claimId).run();

    return c.json({ success: true });
});

// --- DELETE /domains/:id — Remove a claimed domain, requires auth ---
app.delete('/domains/:id', authMiddleware, async (c) => {
    const identityId = c.get('identityId');
    const domainId = c.req.param('id');

    const domain = await c.env.DB.prepare(
        'SELECT * FROM domains WHERE id = ? AND identity_id = ?'
    ).bind(domainId, identityId).first() as any;

    if (!domain) {
        return c.json({ error: 'Domain not found' }, 404);
    }

    if (domain.cf_hostname_id) {
        const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
        try {
            await cf.delete(domain.cf_hostname_id);
        } catch (err) {
            console.error(`Failed to delete CF hostname for domain ${domain.id}:`, err);
        }
    }

    await c.env.DB.prepare('DELETE FROM domains WHERE id = ?').bind(domainId).run();

    return c.json({ success: true });
});

// --- GET /domains — List caller's domains, requires auth ---
app.get('/domains', authMiddleware, async (c) => {
    const identityId = c.get('identityId');

    const { results: pending } = await c.env.DB.prepare(
        'SELECT id, domain, token, created_at FROM pending_claims WHERE identity_id = ?'
    ).bind(identityId).all();

    const { results: claimed } = await c.env.DB.prepare(
        'SELECT id, domain, claimed_at FROM domains WHERE identity_id = ?'
    ).bind(identityId).all();

    return c.json({
        pending: (pending || []).map((r: any) => ({
            id: r.id,
            domain: r.domain,
            status: 'pending',
            cname_name: 'authgravity',
            cname_target: `${r.token}.cname.authgravity.net`,
            created_at: r.created_at,
        })),
        claimed: (claimed || []).map((r: any) => ({
            id: r.id,
            domain: r.domain,
            status: 'active',
            cname_name: 'authgravity',
            claimed_at: r.claimed_at,
        })),
    });
});

// --- Scheduled handler ---
// 1. Advance claims that have an identity bound (DNS verified → provision → claim)
// 2. Expire stale unbound claims (no identity = anonymous, never authenticated)
// 3. Reconcile: DB is source of truth — delete any CF custom hostname not in DB
const UNBOUND_CLAIM_TTL_MS = 60 * 60 * 1000; // 1 hour for claims without an identity

async function handleScheduled(env: Env) {
    const cf = new CloudflareCustomHostnames(env.CF_API_TOKEN, env.CF_ZONE_ID);

    // --- Phase 1: Advance bound claims ---
    // Claims with an identity can be auto-advanced even if the user navigated away.
    const { results: boundClaims } = await env.DB.prepare(
        'SELECT * FROM pending_claims WHERE identity_id IS NOT NULL'
    ).all();

    if (boundClaims && boundClaims.length > 0) {
        for (const claim of boundClaims as any[]) {
            try {
                const result = await advanceClaim(claim, env);
                if (result.status === 'claimed') {
                    console.log(`Scheduled: auto-claimed ${claim.domain} for identity ${claim.identity_id}`);
                } else if (result.status === 'error') {
                    console.log(`Scheduled: advance failed for ${claim.domain}: ${result.error}`);
                }
            } catch (err) {
                console.error(`Scheduled: error advancing claim ${claim.id}:`, err);
            }
        }
    }

    // --- Phase 2: Expire stale unbound claims ---
    // Claims without an identity (user never authenticated) get cleaned up.
    const cutoff = Date.now() - UNBOUND_CLAIM_TTL_MS;

    const { results: expired } = await env.DB.prepare(
        'SELECT id, cf_hostname_id FROM pending_claims WHERE identity_id IS NULL AND created_at < ?'
    ).bind(cutoff).all();

    if (expired && expired.length > 0) {
        for (const claim of expired as any[]) {
            if (claim.cf_hostname_id) {
                try {
                    await cf.delete(claim.cf_hostname_id);
                } catch (err) {
                    console.error(`Failed to delete CF hostname for expired claim ${claim.id}:`, err);
                }
            }
            await env.DB.prepare('DELETE FROM pending_claims WHERE id = ?').bind(claim.id).run();
        }
    }

    // --- Phase 3: Reconcile CF state against DB ---
    // DB is the source of truth. Any CF custom hostname not tracked in
    // pending_claims or domains must be deleted.
    const knownCfIds = new Set<string>();

    const { results: pendingRows } = await env.DB.prepare(
        'SELECT cf_hostname_id FROM pending_claims WHERE cf_hostname_id IS NOT NULL'
    ).all();
    for (const r of (pendingRows || []) as any[]) {
        knownCfIds.add(r.cf_hostname_id);
    }

    const { results: domainRows } = await env.DB.prepare(
        'SELECT cf_hostname_id FROM domains WHERE cf_hostname_id IS NOT NULL'
    ).all();
    for (const r of (domainRows || []) as any[]) {
        knownCfIds.add(r.cf_hostname_id);
    }

    let cfHostnames: import('./cf-api').CustomHostname[];
    try {
        cfHostnames = await cf.listAll();
    } catch (err) {
        console.error('Failed to list CF custom hostnames for reconciliation:', err);
        return;
    }

    for (const h of cfHostnames) {
        if (!knownCfIds.has(h.id)) {
            console.log(`Reconcile: deleting orphaned CF hostname ${h.id} (${h.hostname})`);
            try {
                await cf.delete(h.id);
            } catch (err) {
                console.error(`Reconcile: failed to delete CF hostname ${h.id}:`, err);
            }
        }
    }
}

export default {
    fetch: app.fetch,
    scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
        ctx.waitUntil(handleScheduled(env));
    },
};
