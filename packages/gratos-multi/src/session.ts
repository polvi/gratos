import { Hono } from 'hono';
import { getCookie, deleteCookie } from 'hono/cookie';

import type { Env, Variables } from './index';
import type { TenantInfo } from './tenant';
import { getUser } from './db';

/**
 * Resolve session ID from cookie or Authorization Bearer header.
 */
function getSessionId(c: any): string | undefined {
    const cookieSession = getCookie(c, 'session_id');
    if (cookieSession) return cookieSession;

    const authHeader = c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
        return authHeader.slice(7);
    }

    return undefined;
}

export function sessionRoutes(tenantInfo: TenantInfo) {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();

    app.get('/whoami', async (c) => {
        const sessionId = getSessionId(c);
        if (!sessionId) {
            return c.json({ error: 'Not authenticated' }, 401);
        }

        const userId = await c.env.KV.get(`session:${tenantInfo.tenant}:${sessionId}`);
        if (!userId) {
            return c.json({ error: 'Session expired' }, 401);
        }

        const user = await getUser(c.env.DB, tenantInfo.tenant, userId);
        if (!user) {
            return c.json({ error: 'User not found' }, 404);
        }

        return c.json({ user_id: (user as any).id });
    });

    app.post('/logout', async (c) => {
        const sessionId = getSessionId(c);
        if (sessionId) {
            await c.env.KV.delete(`session:${tenantInfo.tenant}:${sessionId}`);
            deleteCookie(c, 'session_id', {
                path: '/',
                domain: tenantInfo.cookieDomain,
            });
        }
        return c.json({ success: true });
    });

    return app;
}
