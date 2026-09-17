import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { resolveTenant, validateSandboxRpId, withSandboxRpId, hostMatchesRpId, type TenantInfo } from './tenant';
import { authRoutes } from './auth';
import { sessionRoutes, getSessionId } from './session';
import { keyRoutes } from './keys';
import { getUser } from './db';
import { parseSessionValue, resolveSession } from './sessions';
import { sha256Hex } from './hash';
import { SURFACE_PATHS, renderSurface, validateReturnTo } from './surfaces';
import { aauthRoutes } from './aauth/routes';
import { expireSweep } from './aauth/missions';

import type { AuthzRPC } from '../../gratos-authz/src/index';

export type Env = {
    DB: D1Database;
    KV: KVNamespace;
    // gratos-authz worker (no public route); mounted at /authz + /v1/authz/*,
    // plus control-plane RPC (grantTenantOwners/cleanupTenant).
    AUTHZ: Service<AuthzRPC>;
    // Wrangler secret wrapping the per-tenant PS signing keys at rest (AES-GCM
    // KEK). Unset in dev/CI → a fixed dev KEK keeps clone-and-dev zero-setup.
    PS_KEK?: string;
};

export type Variables = {
    userId: string;
    tenantInfo: TenantInfo;
};

/**
 * Resolve the tenant for a request, applying a sandbox's stored custom rp_id.
 * Memoised on the context so the CORS layer and the route dispatcher share one
 * D1 lookup; non-sandbox tenants never touch the database.
 */
async function tenantFor(c: {
    req: { url: string };
    env: Env;
    get: (k: 'tenantInfo') => TenantInfo | undefined;
    set: (k: 'tenantInfo', v: TenantInfo) => void;
}): Promise<TenantInfo> {
    const cached = c.get('tenantInfo');
    if (cached) return cached;
    let info = resolveTenant(new URL(c.req.url));
    if (info.sandbox && info.sandboxId) {
        try {
            const row = await c.env.DB.prepare('SELECT rp_id FROM sandboxes WHERE id = ?')
                .bind(info.tenant)
                .first<{ rp_id: string | null }>();
            info = withSandboxRpId(info, row?.rp_id);
        } catch {
            // column/table may not exist yet in older deployments; keep default rpId
        }
    }
    c.set('tenantInfo', info);
    return info;
}

/**
 * RPC entrypoint for service bindings.
 * Other workers call AUTH.resolveSession(tenant, sessionId) to validate sessions.
 */
export class AuthRPC extends WorkerEntrypoint<Env> {
    /**
     * Resolve a session to a user ID.
     * Returns the user ID if valid, or null if expired/invalid.
     */
    async resolveSession(tenant: string, sessionId: string): Promise<string | null> {
        const session = parseSessionValue(await this.env.KV.get(`session:${tenant}:${sessionId}`));
        if (!session) return null;

        const user = await getUser(this.env.DB, tenant, session.userId);
        if (!user) return null;

        return (user as any).id;
    }

    /**
     * Delete throwaway sandbox pools older than maxAgeMs (default 7 days).
     * Removes users + public_keys for each expired sandbox tenant, then the
     * sandbox record itself. KV sessions expire on their own TTL.
     * Intended to be called from the provisioner's scheduled cron.
     */
    async sweepSandboxes(maxAgeMs: number = 7 * 24 * 60 * 60 * 1000): Promise<{ swept: number }> {
        const cutoff = Date.now() - maxAgeMs;
        // Only anonymous sandboxes are throwaway; owned ones (user_id set)
        // persist until deleted from the dashboard.
        const { results } = await this.env.DB.prepare(
            "SELECT id FROM sandboxes WHERE created_at < ? AND id LIKE 'sandbox.%' AND user_id IS NULL"
        ).bind(cutoff).all();

        let swept = 0;
        for (const row of (results || []) as Array<{ id: string }>) {
            const tenant = row.id;
            await this.env.DB.prepare('DELETE FROM public_keys WHERE tenant = ?').bind(tenant).run();
            await this.env.DB.prepare('DELETE FROM users WHERE tenant = ?').bind(tenant).run();
            await this.env.DB.prepare('DELETE FROM sandboxes WHERE id = ?').bind(tenant).run();
            await deleteAauthTenant(this.env.DB, tenant);
            try {
                await this.env.AUTHZ.cleanupTenant(tenant);
            } catch (e) {
                console.error('authz cleanup failed for swept sandbox', tenant, e);
            }
            swept++;
        }
        return { swept };
    }

    /**
     * Expire overdue AAuth mission proposals. Called from the provisioner's
     * scheduled cron alongside sweepSandboxes.
     */
    async sweepAauth(): Promise<{ expired: number }> {
        return { expired: await expireSweep(this.env.DB) };
    }

    /**
     * Owned sandboxes and their root-pool owners, for the provisioner's
     * authz-ownership reconcile (self-heals failed mint-time grants).
     */
    async listOwnedSandboxes(): Promise<Array<{ tenant: string; userId: string }>> {
        const { results } = await this.env.DB.prepare(
            'SELECT id, user_id FROM sandboxes WHERE user_id IS NOT NULL'
        ).all();
        return ((results || []) as Array<{ id: string; user_id: string }>).map((r) => ({
            tenant: r.id,
            userId: r.user_id,
        }));
    }

    /**
     * Get user count and active session count for a tenant.
     */
    async getTenantStats(tenant: string): Promise<{ users: number; sessions: number }> {
        const userCount = await this.env.DB.prepare(
            'SELECT COUNT(*) as count FROM users WHERE tenant = ?'
        ).bind(tenant).first() as any;

        let sessions = 0;
        let cursor: string | undefined;
        do {
            const list = await this.env.KV.list({
                prefix: `session:${tenant}:`,
                cursor,
            });
            sessions += list.keys.length;
            cursor = list.list_complete ? undefined : (list.cursor as string);
        } while (cursor);

        return {
            users: userCount?.count ?? 0,
            sessions,
        };
    }
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('/*', async (c, next) => {
    const tenantInfo = await tenantFor(c);

    // Dynamic CORS: allow origins on the same tenant domain
    return cors({
        origin: (origin) => {
            try {
                const host = new URL(origin).hostname;
                if (host === tenantInfo.tenant || host.endsWith('.' + tenantInfo.tenant)) {
                    return origin;
                }
                // Sandbox tenants are driven from a developer's local app, or
                // from the sandbox's custom RP ID host when one was minted.
                if (
                    tenantInfo.sandbox &&
                    (host === 'localhost' || host === '127.0.0.1' || hostMatchesRpId(host, tenantInfo.rpId))
                ) {
                    return origin;
                }
            } catch {
                // invalid origin
            }
            // Allow localhost in dev
            if (tenantInfo.tenant === 'localhost') return origin;
            return '';
        },
        allowHeaders: ['Content-Type', 'Authorization'],
        allowMethods: ['POST', 'GET', 'OPTIONS', 'DELETE', 'PUT'],
        exposeHeaders: ['Content-Length'],
        maxAge: 600,
        credentials: true,
    })(c, next);
});

// Health check
app.get('/', (c) => c.json({ status: 'ok' }));

/**
 * Discovery document for this host. An agent pointed at a domain fetches
 * `<host>/.well-known/authgravity` and learns the endpoint + the single
 * `llms.txt` to read — no prompt needs to spell any of this out.
 */
function wellKnown(endpoint: string, tenant: string) {
    return {
        service: 'authgravity',
        tenant,
        endpoint,
        llms_txt: `${endpoint}/llms.txt`,
        console: `${endpoint}/authz`,
        // AAuth Person Server discovery (spec-fixed path, served per host).
        aauth: `${endpoint}/.well-known/aauth-person.json`,
        auth: {
            register_options: '/v1/register/options',
            register_verify: '/v1/register/verify',
            login_options: '/v1/login/options',
            login_verify: '/v1/login/verify',
            whoami: '/v1/whoami',
            logout: '/v1/logout',
            credentials: '/v1/credentials',
        },
        // Hosted end-user surfaces (return_to=<app url> on each).
        surfaces: {
            login: '/login',
            register: '/register',
            recover: '/recover',
            account: '/account',
            logout: '/logout',
        },
        authz: '/v1/authz',
    };
}

// Domain/root auth hosts (no path prefix). Sandbox hosts carry the id in the
// path and are handled inside the tenant router below.
app.get('/.well-known/authgravity', (c) => {
    const url = new URL(c.req.url);
    return c.json(wellKnown(url.origin, resolveTenant(url).tenant), 200, {
        'Cache-Control': 'no-cache',
    });
});


/**
 * Resolve the requester's user id for the tenant of the current request
 * (session cookie or Bearer). Used by the sandbox management endpoints; the
 * dash calls them on its own auth endpoint, so the tenant is e.g.
 * authgravity.org and the user is a dash account.
 */
async function resolveRequestUser(c: any): Promise<string | null> {
    const sessionId = getSessionId(c);
    if (!sessionId) return null;
    const tenantInfo = resolveTenant(new URL(c.req.url));
    const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
    return session?.userId ?? null;
}

// Mint an instant, zero-DNS sandbox auth endpoint. Unauthenticated so a coding
// agent / CLI can call it directly; with a valid session the sandbox is owned
// by that user (listed in the dashboard, exempt from the anonymous sweep). The
// wildcard route makes the returned host live immediately; the isolated user
// pool is created lazily on first register.
app.post('/sandbox', async (c) => {
    // Light per-IP rate limit to bound abuse of the public mint endpoint.
    // Key on a hash of the IP so no raw IP is ever written to KV (privacy rule:
    // use the public IP in the moment, never store it).
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const rlKey = `sandbox_rl:${await sha256Hex(ip)}`;
    const count = parseInt((await c.env.KV.get(rlKey)) || '0', 10);
    if (count >= 30) {
        return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
    }
    await c.env.KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

    // Optional custom WebAuthn RP ID (default localhost). The body is optional
    // and may be empty, so parse leniently.
    let rpId: string | null = null;
    const rawBody = await c.req.text();
    if (rawBody.trim()) {
        let body: { rp_id?: unknown };
        try {
            body = JSON.parse(rawBody);
        } catch {
            return c.json({ error: 'Invalid JSON body' }, 400);
        }
        if (body.rp_id !== undefined) {
            rpId = validateSandboxRpId(body.rp_id);
            if (!rpId) {
                return c.json(
                    { error: 'Invalid rp_id: expected a registrable hostname (not an AuthGravity domain)' },
                    400
                );
            }
        }
    }

    const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
    const url = new URL(c.req.url);
    const isDev =
        url.hostname === 'localhost' ||
        url.hostname === '127.0.0.1' ||
        url.hostname.endsWith('.localhost');

    // Single custom-domain host (auto-certified, no ACM/wildcard); the sandbox
    // id lives in the path: https://sandbox.authgravity.org/<id>
    const sandboxHost = isDev
        ? `sandbox.localhost${url.port ? ':' + url.port : ''}`
        : 'sandbox.authgravity.org';
    const endpoint = `${url.protocol}//${sandboxHost}/${id}`;
    const tenant = `${isDev ? 'sandbox.localhost' : 'sandbox.authgravity.org'}/${id}`;

    // Record the tenant for TTL cleanup / ownership (best-effort).
    const ownerId = await resolveRequestUser(c);
    try {
        await c.env.DB.prepare('INSERT INTO sandboxes (id, created_at, user_id, rp_id) VALUES (?, ?, ?, ?)')
            .bind(tenant, Date.now(), ownerId, rpId)
            .run();
    } catch (e) {
        // A custom rp_id only works if it was persisted; the default needs no row.
        if (rpId) {
            console.error('sandbox insert failed with rp_id', tenant, e);
            return c.json({ error: 'Could not persist sandbox rp_id' }, 500);
        }
        // table may not exist yet in older deployments; non-fatal
    }

    // Owned sandboxes get a control-plane ownership tuple so the owner can
    // manage the pool's authz from the dash. Best-effort: the provisioner's
    // cron reconcile self-heals a failed grant.
    if (ownerId) {
        try {
            await c.env.AUTHZ.grantTenantOwners([{ tenant, userId: ownerId }]);
        } catch (e) {
            console.error('authz owner grant failed for sandbox', tenant, e);
        }
    }

    return c.json({ id, endpoint, mode: 'sandbox', owned: !!ownerId, rp_id: rpId ?? 'localhost' });
});

// List the requester's owned sandboxes.
app.get('/sandboxes', async (c) => {
    const userId = await resolveRequestUser(c);
    if (!userId) return c.json({ error: 'Not authenticated' }, 401);

    const { results } = await c.env.DB.prepare(
        'SELECT id, created_at FROM sandboxes WHERE user_id = ? ORDER BY created_at DESC'
    ).bind(userId).all();

    const url = new URL(c.req.url);
    const sandboxes = ((results || []) as Array<{ id: string; created_at: number }>).map((row) => {
        const slash = row.id.indexOf('/');
        const host = row.id.slice(0, slash);
        const sid = row.id.slice(slash + 1);
        const endpoint = host.endsWith('.localhost')
            ? `${url.protocol}//${host}${url.port ? ':' + url.port : ''}/${sid}`
            : `https://${host}/${sid}`;
        return { id: sid, tenant: row.id, endpoint, created_at: row.created_at };
    });

    return c.json({ sandboxes });
});

// Delete an owned sandbox and its isolated user pool (mirrors sweepSandboxes).
app.delete('/sandboxes/:sid', async (c) => {
    const userId = await resolveRequestUser(c);
    if (!userId) return c.json({ error: 'Not authenticated' }, 401);

    const sid = c.req.param('sid');
    if (!/^[a-z0-9]{6,32}$/.test(sid)) {
        return c.json({ error: 'Invalid sandbox id' }, 400);
    }

    const row = await c.env.DB.prepare(
        'SELECT id FROM sandboxes WHERE user_id = ? AND id LIKE ?'
    ).bind(userId, `%/${sid}`).first() as { id: string } | null;
    if (!row) return c.json({ error: 'Sandbox not found' }, 404);

    const tenant = row.id;
    await c.env.DB.prepare('DELETE FROM public_keys WHERE tenant = ?').bind(tenant).run();
    await c.env.DB.prepare('DELETE FROM users WHERE tenant = ?').bind(tenant).run();
    await c.env.DB.prepare('DELETE FROM sandboxes WHERE id = ?').bind(tenant).run();
    await deleteAauthTenant(c.env.DB, tenant);
    try {
        await c.env.AUTHZ.cleanupTenant(tenant);
    } catch (e) {
        console.error('authz cleanup failed for sandbox', tenant, e);
    }

    return c.json({ success: true });
});

/** Remove a tenant's AAuth state (keys, grants, missions, log) with its pool. */
async function deleteAauthTenant(db: D1Database, tenant: string): Promise<void> {
    try {
        await db.prepare('DELETE FROM ps_keys WHERE tenant = ?').bind(tenant).run();
        await db.prepare('DELETE FROM aauth_grants WHERE tenant = ?').bind(tenant).run();
        await db.prepare('DELETE FROM aauth_missions WHERE tenant = ?').bind(tenant).run();
        await db.prepare('DELETE FROM aauth_mission_log WHERE tenant = ?').bind(tenant).run();
    } catch {
        // tables may not exist yet in older deployments; non-fatal
    }
}

// Mount tenant-scoped routes per request
app.all('/*', async (c, next) => {
    const url = new URL(c.req.url);
    const tenantInfo = await tenantFor(c);

    const auth = authRoutes(tenantInfo);
    const session = sessionRoutes(tenantInfo);
    const keys = keyRoutes(tenantInfo);

    // For path-based sandbox tenants, strip the "/<id>" prefix so the existing
    // auth/session routes (mounted at root) match "/v1/register/options" etc.
    let req = c.req.raw;
    if (tenantInfo.sandbox && tenantInfo.sandboxId) {
        const u = new URL(c.req.url);
        u.pathname = u.pathname.slice(tenantInfo.sandboxPrefix!.length) || '/';
        req = new Request(u.toString(), c.req.raw);
    }

    // Sandbox discovery: the id-prefixed host resolves here after stripping.
    // The advertised endpoint keeps the "/<id>" so agents fetch the right host.
    const path = new URL(req.url).pathname;
    if (path === '/.well-known/authgravity') {
        const endpoint =
            tenantInfo.sandbox && tenantInfo.sandboxId
                ? `${url.origin}/${tenantInfo.sandboxId}`
                : url.origin;
        return c.json(wellKnown(endpoint, tenantInfo.tenant), 200, { 'Cache-Control': 'no-cache' });
    }

    // AAuth Person Server: spec-fixed discovery + /v1/aauth/* API. Served on
    // every tenant host (root, sandboxes, claimed domains) like /v1/authz.
    if (path === '/.well-known/aauth-person.json' || path === '/v1/aauth' || path.startsWith('/v1/aauth/')) {
        return aauthRoutes(tenantInfo).fetch(req, c.env);
    }

    // Hosted end-user auth surfaces (/login, /register, /logout, /recover).
    // Served here (not top-level) so the sandbox "/<id>" prefix is already
    // stripped from `path`. `/demo` is kept as an alias → /login.
    if (SURFACE_PATHS.has(path)) {
        if (path === '/demo') {
            const dest = new URL(c.req.url);
            dest.pathname = dest.pathname.replace(/\/demo$/, '/login');
            return c.redirect(dest.pathname + dest.search, 302);
        }
        const returnTo = validateReturnTo(url.searchParams.get('return_to'), tenantInfo.tenant, url.hostname);
        // Never cache auth surfaces: they're per-request (return_to) and must
        // always reflect the deployed version.
        return c.html(renderSurface(path, returnTo), 200, { 'Cache-Control': 'no-store' });
    }

    // Authz routes are served by the gratos-authz worker (which has no public
    // route of its own). Forward with the resolved tenant + user as trusted
    // headers; inbound X-Gratos-* headers are stripped so they can't be forged.
    if (path === '/authz' || path === '/llms.txt' || path === '/v1/authz' || path.startsWith('/v1/authz/')) {
        const headers = new Headers(req.headers);
        for (const key of [...headers.keys()]) {
            if (key.toLowerCase().startsWith('x-gratos-')) headers.delete(key);
        }
        headers.set('X-Gratos-Tenant', tenantInfo.tenant);
        // Sandbox pools: tell authz whether the pool is owned or anonymous
        // (anonymous pools are open to manage). Set only when the sandboxes
        // row exists — a missing row fails closed to managed mode.
        if (tenantInfo.sandbox) {
            const row = (await c.env.DB.prepare('SELECT user_id FROM sandboxes WHERE id = ?')
                .bind(tenantInfo.tenant)
                .first()) as { user_id: string | null } | null;
            if (row) {
                headers.set('X-Gratos-Sandbox', row.user_id ? 'owned' : 'anonymous');
            }
        }
        const sessionId = getSessionId(c);
        if (sessionId) {
            const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
            if (session && (await getUser(c.env.DB, tenantInfo.tenant, session.userId))) {
                headers.set('X-Gratos-User', session.userId);
                headers.set('X-Gratos-Amr', session.amr);
            }
        }
        return c.env.AUTHZ.fetch(new Request(req, { headers }));
    }

    // Try auth routes first, then key routes, then session routes
    const authResponse = await auth.fetch(req, c.env, c.executionCtx);
    if (authResponse.status !== 404) return authResponse;

    const keyResponse = await keys.fetch(req, c.env, c.executionCtx);
    if (keyResponse.status !== 404) return keyResponse;

    const sessionResponse = await session.fetch(req, c.env, c.executionCtx);
    if (sessionResponse.status !== 404) return sessionResponse;

    return next();
});

export default app;
