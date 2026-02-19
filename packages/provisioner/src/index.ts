import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie } from 'hono/cookie';
import { CloudflareCustomHostnames } from './cf-api';

import type { AuthRPC } from '../../gratos-multi/src/index';

type Env = {
    DB: D1Database;
    CF_API_TOKEN: string;
    CF_ZONE_ID: string;
    CORS_ALLOW_ORIGIN?: string;
    AUTH: Service<AuthRPC>;
    AUTH_TENANT: string;
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

/** Resolve CNAME target for a hostname via Cloudflare DNS-over-HTTPS */
async function resolveCNAME(hostname: string): Promise<string | null> {
    const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`,
        { headers: { 'Accept': 'application/dns-json' } }
    );
    if (!res.ok) return null;
    const data = await res.json() as { Answer?: { type: number; data: string }[] };
    // Type 5 = CNAME
    const cname = data.Answer?.find((r: any) => r.type === 5);
    if (!cname) return null;
    // DNS returns trailing dot, normalize
    return cname.data.replace(/\.$/, '');
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
        cname_name: 'letsident',
        cname_target: `${token}.cname.letsident.net`,
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
        let cfStatus = null;
        let validationRecords = null;

        if (pending.cf_hostname_id) {
            const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
            const result = await cf.get(pending.cf_hostname_id);
            if (result.success) {
                cfStatus = result.result.status;
                validationRecords = result.result.ssl?.validation_records || null;
            }
        }

        return c.json({
            id: pending.id,
            domain: pending.domain,
            token: pending.token,
            cname_name: 'letsident',
            cname_target: `${pending.token}.cname.letsident.net`,
            status: pending.cf_hostname_id ? 'provisioned' : 'pending',
            cf_status: cfStatus,
            validation_records: validationRecords,
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
            cf_status: 'active',
            has_identity: true,
            claimed_at: claimed.claimed_at,
        });
    }

    return c.json({ error: 'Claim not found' }, 404);
});

// =============================================
// Authenticated routes
// =============================================

// --- POST /claims/:id/provision — ProvisionCF: requires auth, creates unique CF hostname ---
app.post('/claims/:id/provision', authMiddleware, async (c) => {
    const identityId = c.get('identityId');
    const claimId = c.req.param('id');

    const claim = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ?'
    ).bind(claimId).first() as any;

    if (!claim) {
        return c.json({ error: 'Claim not found' }, 404);
    }

    if (claim.cf_hostname_id) {
        return c.json({ error: 'Already provisioned' }, 409);
    }

    // Associate identity if not yet bound
    if (!claim.identity_id) {
        await c.env.DB.prepare(
            'UPDATE pending_claims SET identity_id = ? WHERE id = ?'
        ).bind(identityId, claimId).run();
    } else if (claim.identity_id !== identityId) {
        return c.json({ error: 'Claim owned by another identity' }, 403);
    }

    if (!c.env.CF_API_TOKEN || !c.env.CF_ZONE_ID) {
        console.error('CF_API_TOKEN or CF_ZONE_ID not configured');
        return c.json({ error: 'CF API not configured' }, 500);
    }

    // Stable hostname: letsident.{domain}
    // User sets CNAME target to {token}.cname.letsident.net to prove ownership
    const hostname = `letsident.${claim.domain}`;

    const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
    let cfHostnameId: string;

    // Idempotent: reuse existing CF hostname if one already exists for this domain
    const existing = await cf.findByHostname(hostname);
    if (existing) {
        cfHostnameId = existing.id;
    } else {
        let result;
        try {
            result = await cf.create(hostname);
        } catch (err) {
            console.error('CF API request failed:', err);
            return c.json({ error: 'CF API request failed', details: String(err) }, 502);
        }

        if (!result.success) {
            console.error('CF API error:', JSON.stringify(result.errors));
            return c.json({ error: 'CF API error', details: result.errors }, 502);
        }
        cfHostnameId = result.result.id;
    }

    await c.env.DB.prepare(
        'UPDATE pending_claims SET cf_hostname_id = ? WHERE id = ?'
    ).bind(cfHostnameId, claimId).run();

    return c.json({
        id: claimId,
        domain: claim.domain,
        hostname,
        status: 'provisioned',
        cf_hostname_id: cfHostnameId,
    });
});

// --- POST /claims/:id/finalize — ClaimDomain: requires auth + CF validated ---
// On success, cleans up ALL other pending claims for this domain (losers).
app.post('/claims/:id/finalize', authMiddleware, async (c) => {
    const identityId = c.get('identityId');
    const claimId = c.req.param('id');

    const claim = await c.env.DB.prepare(
        'SELECT * FROM pending_claims WHERE id = ? AND identity_id = ?'
    ).bind(claimId, identityId).first() as any;

    if (!claim) {
        return c.json({ error: 'Claim not found or not associated with your identity' }, 404);
    }

    // ValidatedImpliesProvisioned
    if (!claim.cf_hostname_id) {
        return c.json({ error: 'Claim not yet provisioned' }, 400);
    }

    // OneDomainOneOwner: check no one else claimed it first
    const existingClaimed = await c.env.DB.prepare(
        'SELECT id FROM domains WHERE domain = ?'
    ).bind(claim.domain).first();
    if (existingClaimed) {
        return c.json({ error: 'Domain already claimed by another identity' }, 409);
    }

    // ClaimedImpliesCFValidated
    const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
    const result = await cf.get(claim.cf_hostname_id);

    if (!result.success || result.result.status !== 'active') {
        return c.json({
            error: 'CF hostname not yet validated',
            cf_status: result.result?.status || 'unknown',
        }, 400);
    }

    // SingleCNAMEPerDomain: verify the CNAME target matches this claim's token
    const expectedTarget = `${claim.token}.cname.letsident.net`;
    const actualTarget = await resolveCNAME(`letsident.${claim.domain}`);
    if (actualTarget !== expectedTarget) {
        return c.json({
            error: 'CNAME target does not match this claim',
            expected: expectedTarget,
            actual: actualTarget,
        }, 403);
    }

    // Collect losing claims for this domain (all except winner)
    const { results: losingClaims } = await c.env.DB.prepare(
        'SELECT id, cf_hostname_id FROM pending_claims WHERE domain = ? AND id != ?'
    ).bind(claim.domain, claimId).all();

    // NoPendingAndClaimed + NoOrphanedCFResources: atomic move + cleanup losers
    const domainId = crypto.randomUUID();
    const claimedAt = Date.now();

    const statements = [
        c.env.DB.prepare(
            'INSERT INTO domains (id, identity_id, domain, cf_hostname_id, claimed_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(domainId, identityId, claim.domain, claim.cf_hostname_id, claimedAt),
        // Delete ALL pending claims for this domain (winner + losers)
        c.env.DB.prepare(
            'DELETE FROM pending_claims WHERE domain = ?'
        ).bind(claim.domain),
    ];

    await c.env.DB.batch(statements);

    // Clean up losing claims' CF hostnames (best-effort, after DB commit)
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

    return c.json({
        id: domainId,
        domain: claim.domain,
        status: 'claimed',
        claimed_at: claimedAt,
    });
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

// --- GET /claims — List caller's claims, requires auth ---
app.get('/claims', authMiddleware, async (c) => {
    const identityId = c.get('identityId');

    const { results: pending } = await c.env.DB.prepare(
        'SELECT id, domain, token, cf_hostname_id, created_at FROM pending_claims WHERE identity_id = ?'
    ).bind(identityId).all();

    const { results: claimed } = await c.env.DB.prepare(
        'SELECT id, domain, cf_hostname_id, claimed_at FROM domains WHERE identity_id = ?'
    ).bind(identityId).all();

    return c.json({
        pending: (pending || []).map((r: any) => ({
            ...r,
            cname_name: 'letsident',
            cname_target: `${r.token}.cname.letsident.net`,
            status: r.cf_hostname_id ? 'provisioned' : 'pending',
        })),
        claimed: (claimed || []).map((r: any) => ({
            ...r,
            status: 'claimed',
        })),
    });
});

// --- Scheduled handler (ExpireClaim) ---
// Aggressive GC since pending claims don't block anyone
const CLAIM_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function handleScheduled(env: Env) {
    const cutoff = Date.now() - CLAIM_TTL_MS;

    const { results } = await env.DB.prepare(
        'SELECT id, cf_hostname_id FROM pending_claims WHERE created_at < ?'
    ).bind(cutoff).all();

    if (!results || results.length === 0) return;

    const cf = new CloudflareCustomHostnames(env.CF_API_TOKEN, env.CF_ZONE_ID);

    for (const claim of results as any[]) {
        // NoOrphanedCFResources: delete CF hostname before removing claim
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

export default {
    fetch: app.fetch,
    scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
        ctx.waitUntil(handleScheduled(env));
    },
};
