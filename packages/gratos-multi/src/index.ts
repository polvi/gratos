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
