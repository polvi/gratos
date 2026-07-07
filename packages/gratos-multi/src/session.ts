import { Hono } from 'hono';
import { getCookie, deleteCookie } from 'hono/cookie';

import type { Env, Variables } from './index';
import type { TenantInfo } from './tenant';
import { getUser } from './db';
import { resolveSession } from './sessions';

/**
 * Resolve session ID from cookie or Authorization Bearer header.
 */
export function getSessionId(c: any): string | undefined {
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

    const whoami = async (c: any) => {
        const sessionId = getSessionId(c);
        if (!sessionId) {
            return c.json({ error: 'Not authenticated' }, 401);
        }

        const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
        if (!session) {
            return c.json({ error: 'Session expired' }, 401);
        }

        const user = await getUser(c.env.DB, tenantInfo.tenant, session.userId);
        if (!user) {
            return c.json({ error: 'User not found' }, 404);
        }

        return c.json({ user_id: (user as any).id, amr: session.amr });
    };

    const logout = async (c: any) => {
        const sessionId = getSessionId(c);
        if (sessionId) {
            await c.env.KV.delete(`session:${tenantInfo.tenant}:${sessionId}`);
            deleteCookie(c, 'session_id', {
                path: '/',
                domain: tenantInfo.cookieDomain,
            });
        }
        return c.json({ success: true });
    };

    app.get('/v1/whoami', whoami);
    app.post('/v1/logout', logout);

    return app;
}
