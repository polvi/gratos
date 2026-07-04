// This worker has no public route: every request arrives through the AUTHZ
// service binding from gratos-multi, which resolves the tenant from the Host
// and the user from the session cookie/Bearer, then forwards them as these
// headers. They are trusted because nothing else can reach this worker.

import type { Context, Next } from 'hono';

export const TENANT_HEADER = 'X-Gratos-Tenant';
export const USER_HEADER = 'X-Gratos-User';
// For sandbox tenants only: 'owned' | 'anonymous', from gratos-multi's
// sandboxes table. Absent (e.g. missing row) means fail-closed: managed mode.
export const SANDBOX_HEADER = 'X-Gratos-Sandbox';

export type Variables = {
    tenant: string;
    userId?: string;
    sandboxMode?: 'owned' | 'anonymous';
    /** Set by the on-behalf owner gate: full manage rights on `tenant`. */
    superuser?: boolean;
};

/** Require the trusted tenant header on every request (console page included). */
export async function trustedContext(c: Context, next: Next) {
    const tenant = c.req.header(TENANT_HEADER);
    if (!tenant) {
        // Direct access (no gratos-multi in front) — refuse.
        return c.json({ error: 'Forbidden' }, 403);
    }
    c.set('tenant', tenant);
    const userId = c.req.header(USER_HEADER);
    if (userId) c.set('userId', userId);
    const sandbox = c.req.header(SANDBOX_HEADER);
    if (sandbox === 'owned' || sandbox === 'anonymous') c.set('sandboxMode', sandbox);
    await next();
}

/** API routes additionally require an authenticated user. */
export async function requireUser(c: Context, next: Next) {
    if (!c.get('userId')) {
        return c.json({ error: 'Not authenticated' }, 401);
    }
    await next();
}
