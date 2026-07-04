import { Hono } from 'hono';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { authzRoutes, runCheck, Env } from './routes';
import { requireUser, trustedContext, Variables } from './middleware';
import { loadSchema } from './schema';
import { consolePage } from './console';

export type { Env };

/**
 * RPC entrypoint for service bindings. Read-only: same-account workers are
 * trusted callers, but tuple/schema writes stay behind the session-gated HTTP
 * API so every mutation is attributable to a tenant user.
 */
export class AuthzRPC extends WorkerEntrypoint<Env> {
    /**
     * Evaluate a permission check, e.g.
     * check('example.com', 'document:readme', 'view', 'user:<uuid>').
     */
    async check(tenant: string, object: string, permission: string, subject: string): Promise<boolean> {
        const schema = await loadSchema(this.env.DB, tenant);
        return runCheck(this.env.DB, tenant, schema?.doc ?? null, object, permission, subject);
    }
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('/*', trustedContext);

// Management console: served on the tenant's own host, so visitors log in as
// tenant-pool users with first-party cookies. The page itself is public; every
// API call it makes is session-gated.
app.get('/authz', (c) => c.html(consolePage()));

// Unauthenticated endpoint index, so curling the advertised API base answers
// instead of 404ing. No tenant data — just the route map.
app.get('/v1/authz', (c) =>
    c.json({
        service: 'gratos-authz',
        docs: 'https://authgravity.org/docs',
        console: '/authz',
        endpoints: [
            'POST /v1/authz/bootstrap',
            'GET /v1/authz/status',
            'POST /v1/authz/check',
            'POST /v1/authz/relationships',
            'GET /v1/authz/relationships',
            'GET /v1/authz/schema',
            'PUT /v1/authz/schema',
        ],
    })
);

app.use('/v1/authz/*', requireUser);
app.route('/', authzRoutes);

export default app;
