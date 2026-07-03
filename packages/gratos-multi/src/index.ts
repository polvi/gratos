import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { resolveTenant } from './tenant';
import { authRoutes } from './auth';
import { sessionRoutes, getSessionId } from './session';
import { getUser } from './db';

export type Env = {
    DB: D1Database;
    KV: KVNamespace;
};

export type Variables = {
    userId: string;
};

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
        const userId = await this.env.KV.get(`session:${tenant}:${sessionId}`);
        if (!userId) return null;

        const user = await getUser(this.env.DB, tenant, userId);
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
            swept++;
        }
        return { swept };
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
    const url = new URL(c.req.url);
    const tenantInfo = resolveTenant(url);

    // Dynamic CORS: allow origins on the same tenant domain
    return cors({
        origin: (origin) => {
            try {
                const host = new URL(origin).hostname;
                if (host === tenantInfo.tenant || host.endsWith('.' + tenantInfo.tenant)) {
                    return origin;
                }
                // Sandbox tenants are driven from a developer's local app.
                if (tenantInfo.sandbox && (host === 'localhost' || host === '127.0.0.1')) {
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

// Demo page — self-contained auth demo served from the authgravity subdomain
app.get('/demo', (c) => {
    const url = new URL(c.req.url);
    const apiBaseUrl = url.origin;
    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Auth Demo</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: #fafafa; color: #18181b; }
    .container { max-width: 480px; margin: 3rem auto; padding: 0 1.5rem; }
    h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem; }
    p { color: #52525b; line-height: 1.6; margin-bottom: 1.5rem; }
    .card { background: #fff; border: 1px solid #e4e4e7; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
    .card h2 { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; }
    #auth-root button {
      display: block; width: 100%; padding: 0.625rem; margin-bottom: 0.5rem;
      border: 1px solid #d4d4d8; border-radius: 0.375rem;
      font-size: 1rem; font-weight: 600; cursor: pointer; background: #fff;
    }
    #auth-root button:hover { background: #f4f4f5; }
    .user-info { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 0.5rem; padding: 1rem; }
    .user-info p { color: #15803d; margin: 0; }
    code { background: #f4f4f5; padding: 0.125rem 0.375rem; border-radius: 0.25rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Auth Demo</h1>
    <p>This page is served from <code>${url.hostname}</code>. Try registering a passkey or signing in.</p>
    <div id="auth-root"></div>
  </div>
  <script type="module">
    import { render, h } from 'https://esm.sh/preact@10.28.2';
    import { useState, useEffect } from 'https://esm.sh/preact@10.28.2/hooks';
    import { startRegistration, startAuthentication } from 'https://esm.sh/@simplewebauthn/browser@13.2.2';

    const API = '${apiBaseUrl}';

    function App() {
      const [user, setUser] = useState(null);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState('');

      const checkSession = async () => {
        try {
          const res = await fetch(API + '/v1/whoami', { credentials: 'include' });
          if (res.ok) {
            const data = await res.json();
            setUser(data);
          }
        } catch {}
        setLoading(false);
      };

      useEffect(() => { checkSession(); }, []);

      const register = async () => {
        setError('');
        try {
          // The passkey label defaults to "Me" (set server-side, never stored).
          const optRes = await fetch(API + '/v1/register/options', { credentials: 'include' });
          const opts = await optRes.json();
          const cred = await startRegistration({ optionsJSON: opts });
          const verRes = await fetch(API + '/v1/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(cred),
          });
          if (verRes.ok) { await checkSession(); }
          else { const d = await verRes.json(); setError(d.error || 'Registration failed'); }
        } catch (e) { setError(String(e)); }
      };

      const login = async () => {
        setError('');
        try {
          const optRes = await fetch(API + '/v1/login/options', { credentials: 'include' });
          const opts = await optRes.json();
          const cred = await startAuthentication({ optionsJSON: opts });
          const verRes = await fetch(API + '/v1/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(cred),
          });
          if (verRes.ok) { await checkSession(); }
          else { const d = await verRes.json(); setError(d.error || 'Login failed'); }
        } catch (e) { setError(String(e)); }
      };

      const logout = async () => {
        await fetch(API + '/v1/logout', { method: 'POST', credentials: 'include' });
        setUser(null);
      };

      if (loading) return h('p', null, 'Loading...');

      if (user) return h('div', { class: 'card' },
        h('div', { class: 'user-info' },
          h('p', null, 'Signed in as ', h('strong', null, user.user_id || user.id)),
        ),
        h('button', { onClick: logout, style: 'margin-top: 1rem' }, 'Sign Out'),
      );

      return h('div', null,
        h('h1', { style: 'font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem;' }, 'Welcome'),
        h('p', null, 'Sign in or create an account with a passkey.'),
        h('div', { style: 'display: flex; flex-direction: column; gap: 1rem;' },
          h('button', { onClick: () => register(), style: 'background: #18181b; color: white; border: none;' }, 'Create Account'),
          h('p', { style: 'text-align: center; color: #a1a1aa; font-size: 0.875rem; margin: 0;' }, 'or'),
          h('button', { onClick: login }, 'Login'),
        ),
        error && h('p', { style: 'color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem;' }, error),
      );
    }

    render(h(App), document.getElementById('auth-root'));
  </script>
</body>
</html>`);
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
    const userId = await c.env.KV.get(`session:${tenantInfo.tenant}:${sessionId}`);
    return userId || null;
}

// Mint an instant, zero-DNS sandbox auth endpoint. Unauthenticated so a coding
// agent / CLI can call it directly; with a valid session the sandbox is owned
// by that user (listed in the dashboard, exempt from the anonymous sweep). The
// wildcard route makes the returned host live immediately; the isolated user
// pool is created lazily on first register.
app.post('/sandbox', async (c) => {
    // Light per-IP rate limit to bound abuse of the public mint endpoint.
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const rlKey = `sandbox_rl:${ip}`;
    const count = parseInt((await c.env.KV.get(rlKey)) || '0', 10);
    if (count >= 30) {
        return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
    }
    await c.env.KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

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
        await c.env.DB.prepare('INSERT INTO sandboxes (id, created_at, user_id) VALUES (?, ?, ?)')
            .bind(tenant, Date.now(), ownerId)
            .run();
    } catch {
        // table may not exist yet in older deployments; non-fatal
    }

    return c.json({ id, endpoint, mode: 'sandbox', owned: !!ownerId });
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

    return c.json({ success: true });
});

// Mount tenant-scoped routes per request
app.all('/*', async (c, next) => {
    const url = new URL(c.req.url);
    const tenantInfo = resolveTenant(url);

    const auth = authRoutes(tenantInfo);
    const session = sessionRoutes(tenantInfo);

    // For path-based sandbox tenants, strip the "/<id>" prefix so the existing
    // auth/session routes (mounted at root) match "/v1/register/options" etc.
    let req = c.req.raw;
    if (tenantInfo.sandbox && tenantInfo.sandboxId) {
        const u = new URL(c.req.url);
        u.pathname = u.pathname.slice(tenantInfo.sandboxPrefix!.length) || '/';
        req = new Request(u.toString(), c.req.raw);
    }

    // Try auth routes first, then session routes
    const authResponse = await auth.fetch(req, c.env);
    if (authResponse.status !== 404) return authResponse;

    const sessionResponse = await session.fetch(req, c.env);
    if (sessionResponse.status !== 404) return sessionResponse;

    return next();
});

export default app;
