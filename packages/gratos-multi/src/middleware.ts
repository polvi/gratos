import { getCookie } from 'hono/cookie';
import type { Context, Next } from 'hono';
import type { Env, Variables } from './index';
import type { TenantInfo } from './tenant';

/**
 * Resolve session ID from cookie or Authorization Bearer header.
 */
function getSessionId(c: Context): string | undefined {
    // Check cookie first
    const cookieSession = getCookie(c, 'session_id');
    if (cookieSession) return cookieSession;

    // Fall back to Bearer token
    const authHeader = c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
        return authHeader.slice(7);
    }

    return undefined;
}

/**
 * Auth middleware that checks for a valid session (cookie or Bearer).
 * Sets userId on context if authenticated.
 */
export function authMiddleware(tenantInfo: TenantInfo) {
    return async (c: Context<{ Bindings: Env; Variables: Variables }>, next: Next) => {
        const sessionId = getSessionId(c);
        if (!sessionId) {
            return c.json({ error: 'Not authenticated' }, 401);
        }

        const userId = await c.env.KV.get(`session:${tenantInfo.tenant}:${sessionId}`);
        if (!userId) {
            return c.json({ error: 'Session expired' }, 401);
        }

        c.set('userId', userId);
        await next();
    };
}

export { getSessionId };
