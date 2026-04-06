import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { resolveTenant } from './tenant';
import { authRoutes } from './auth';
import { sessionRoutes } from './session';
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
  <title>Gratos Auth Demo</title>
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
          const res = await fetch(API + '/whoami', { credentials: 'include' });
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
          const optRes = await fetch(API + '/register/options', { credentials: 'include' });
          const opts = await optRes.json();
          const cred = await startRegistration({ optionsJSON: opts });
          const verRes = await fetch(API + '/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ response: cred, userId: opts.userId }),
          });
          if (verRes.ok) { await checkSession(); }
          else { const d = await verRes.json(); setError(d.error || 'Registration failed'); }
        } catch (e) { setError(String(e)); }
      };

      const login = async () => {
        setError('');
        try {
          const optRes = await fetch(API + '/login/options', { credentials: 'include' });
          const opts = await optRes.json();
          const cred = await startAuthentication({ optionsJSON: opts });
          const verRes = await fetch(API + '/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ response: cred, challengeId: opts.challengeId }),
          });
          if (verRes.ok) { await checkSession(); }
          else { const d = await verRes.json(); setError(d.error || 'Login failed'); }
        } catch (e) { setError(String(e)); }
      };

      const logout = async () => {
        await fetch(API + '/logout', { method: 'POST', credentials: 'include' });
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
        h('div', { class: 'card' },
          h('h2', null, 'Get started'),
          h('button', { onClick: register }, 'Register a Passkey'),
          h('button', { onClick: login }, 'Sign In'),
        ),
        error && h('p', { style: 'color: #ef4444; font-size: 0.875rem; margin-top: 0.5rem;' }, error),
      );
    }

    render(h(App), document.getElementById('auth-root'));
  </script>
</body>
</html>`);
});

// Mount tenant-scoped routes per request
app.all('/*', async (c, next) => {
    const url = new URL(c.req.url);
    const tenantInfo = resolveTenant(url);

    const auth = authRoutes(tenantInfo);
    const session = sessionRoutes(tenantInfo);

    // Try auth routes first, then session routes
    const authResponse = await auth.fetch(c.req.raw, c.env);
    if (authResponse.status !== 404) return authResponse;

    const sessionResponse = await session.fetch(c.req.raw, c.env);
    if (sessionResponse.status !== 404) return sessionResponse;

    return next();
});

export default app;
