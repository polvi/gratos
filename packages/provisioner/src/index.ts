import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie } from 'hono/cookie';
import { CloudflareCustomHostnames } from './cf-api';

type Env = {
    DB: D1Database;
    AUTH_KV: KVNamespace;
    CF_API_TOKEN: string;
    CF_ZONE_ID: string;
    CF_CNAME_TARGET?: string;
    CORS_ALLOW_ORIGIN?: string;
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

// Auth middleware — reads session from shared AUTH_KV
const authMiddleware = async (c: any, next: any) => {
    const sessionId = getCookie(c, 'session_id');
    if (!sessionId) {
        return c.json({ error: 'Not authenticated' }, 401);
    }

    const identityId = await c.env.AUTH_KV.get(`session:${sessionId}`);
    if (!identityId) {
        return c.json({ error: 'Session expired' }, 401);
    }

    c.set('identityId', identityId);
    await next();
};

app.get('/', (c) => c.text('Gratos Provisioner Running'));

// =============================================
// Anonymous routes — claim ID is the bearer token
// =============================================

// --- POST /claims — EnterDomain: create pending claim, DB only, no CF ---
app.post('/claims', async (c) => {
    const { domain } = await c.req.json();

    if (!domain || typeof domain !== 'string') {
        return c.json({ error: 'Invalid or missing "domain"' }, 400);
    }

    const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
        return c.json({ error: 'Invalid domain format' }, 400);
    }

    const existingClaimed = await c.env.DB.prepare(
        'SELECT id FROM domains WHERE domain = ?'
    ).bind(domain).first();
    if (existingClaimed) {
        return c.json({ error: 'Domain already claimed' }, 409);
    }

    const existingPending = await c.env.DB.prepare(
        'SELECT id FROM pending_claims WHERE domain = ?'
    ).bind(domain).first();
    if (existingPending) {
        return c.json({ error: 'Domain already has a pending claim' }, 409);
    }

    const id = crypto.randomUUID();
    const createdAt = Date.now();

    await c.env.DB.prepare(
        'INSERT INTO pending_claims (id, domain, created_at) VALUES (?, ?, ?)'
    ).bind(id, domain, createdAt).run();

    return c.json({
        id,
        domain,
        status: 'pending',
        cname_target: c.env.CF_CNAME_TARGET || 'gratos-worker-prod.workers.dev',
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
            status: pending.cf_hostname_id ? 'provisioned' : 'pending',
            cf_status: cfStatus,
            validation_records: validationRecords,
            has_identity: !!pending.identity_id,
            cname_target: c.env.CF_CNAME_TARGET || 'gratos-worker-prod.workers.dev',
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

// --- POST /claims/:id/provision — ProvisionCF: requires auth, creates CF hostname ---
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

    const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
    let result;
    try {
        result = await cf.create(`letsident.${claim.domain}`);
    } catch (err) {
        console.error('CF API request failed:', err);
        return c.json({ error: 'CF API request failed', details: String(err) }, 502);
    }

    if (!result.success) {
        console.error('CF API error:', JSON.stringify(result.errors));
        return c.json({ error: 'CF API error', details: result.errors }, 502);
    }

    await c.env.DB.prepare(
        'UPDATE pending_claims SET cf_hostname_id = ? WHERE id = ?'
    ).bind(result.result.id, claimId).run();

    return c.json({
        id: claimId,
        domain: claim.domain,
        status: 'provisioned',
        cf_hostname_id: result.result.id,
        validation_records: result.result.ssl?.validation_records || null,
    });
});

// --- POST /claims/:id/finalize — ClaimDomain: requires auth + CF validated ---
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

    // ClaimedImpliesCFValidated
    const cf = new CloudflareCustomHostnames(c.env.CF_API_TOKEN, c.env.CF_ZONE_ID);
    const result = await cf.get(claim.cf_hostname_id);

    if (!result.success || result.result.status !== 'active') {
        return c.json({
            error: 'CF hostname not yet validated',
            cf_status: result.result?.status || 'unknown',
        }, 400);
    }

    // NoPendingAndClaimed: atomic move
    const domainId = crypto.randomUUID();
    const claimedAt = Date.now();

    await c.env.DB.batch([
        c.env.DB.prepare(
            'INSERT INTO domains (id, identity_id, domain, cf_hostname_id, claimed_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(domainId, identityId, claim.domain, claim.cf_hostname_id, claimedAt),
        c.env.DB.prepare(
            'DELETE FROM pending_claims WHERE id = ?'
        ).bind(claimId),
    ]);

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
        'SELECT id, domain, cf_hostname_id, created_at FROM pending_claims WHERE identity_id = ?'
    ).bind(identityId).all();

    const { results: claimed } = await c.env.DB.prepare(
        'SELECT id, domain, cf_hostname_id, claimed_at FROM domains WHERE identity_id = ?'
    ).bind(identityId).all();

    return c.json({
        pending: (pending || []).map((r: any) => ({
            ...r,
            status: r.cf_hostname_id ? 'provisioned' : 'pending',
        })),
        claimed: (claimed || []).map((r: any) => ({
            ...r,
            status: 'claimed',
        })),
    });
});

// --- Scheduled handler (ExpireClaim) ---
const CLAIM_TTL_MS = 30 * 60 * 1000; // 30 minutes

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
            await cf.delete(claim.cf_hostname_id);
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
