import { Hono } from 'hono';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { authzRoutes, runCheck, Env } from './routes';
import { requireUser, trustedContext, Variables } from './middleware';
import { loadSchema } from './schema';
import { grantOwnerTuples, deleteTenantData, OwnerGrant } from './tuples';
import { consolePage } from './console';

export type { Env };

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

/**
 * RPC entrypoint for service bindings (same-account workers are trusted).
 * Serves both the RPC methods and, via fetch(), the HTTP app — so one
 * binding with entrypoint "AuthzRPC" covers gratos-multi's forwarding too.
 *
 * The write methods are the ONLY way control-plane (gratos_tenant) tuples
 * are created or destroyed; onboarding calls them (provisioner on domain
 * claim, gratos-multi on owned-sandbox mint) and teardown/cron reconcile
 * keeps them in sync.
 */
export class AuthzRPC extends WorkerEntrypoint<Env> {
    async fetch(request: Request): Promise<Response> {
        return app.fetch(request, this.env, this.ctx);
    }

    /**
     * Evaluate a permission check, e.g.
     * check('example.com', 'document:readme', 'view', 'user:<uuid>').
     */
    async check(tenant: string, object: string, permission: string, subject: string): Promise<boolean> {
        const schema = await loadSchema(this.env.DB, tenant);
        return runCheck(this.env.DB, tenant, schema?.doc ?? null, object, permission, subject);
    }

    /**
     * Idempotently record tenant owners in the root control-plane space.
     * Entries targeting the root tenant itself are refused (nothing may mint
     * control-plane power over the control plane).
     */
    async grantTenantOwners(entries: OwnerGrant[]): Promise<{ written: number }> {
        const safe = entries.filter((e) => e.tenant && e.userId && e.tenant !== this.env.ROOT_TENANT);
        if (safe.length === 0) return { written: 0 };
        return grantOwnerTuples(this.env.DB, this.env.ROOT_TENANT, safe);
    }

    /**
     * Full authz teardown for a deleted tenant: its relationships + schema
     * and its control-plane ownership tuples. Refuses the root tenant —
     * that would destroy the entire control plane.
     */
    async cleanupTenant(tenantKey: string): Promise<void> {
        if (!tenantKey || tenantKey === this.env.ROOT_TENANT) {
            throw new Error('cleanupTenant: refusing root/empty tenant');
        }
        await deleteTenantData(this.env.DB, this.env.ROOT_TENANT, tenantKey);
    }
}

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
            'GET /v1/authz/status',
            'POST /v1/authz/check',
            'POST /v1/authz/relationships',
            'GET /v1/authz/relationships',
            'GET /v1/authz/schema',
            'PUT /v1/authz/schema',
            'GET|PUT|POST /v1/authz/tenants/:tenant/(status|schema|relationships|check) — owner management, root session',
        ],
    })
);

app.use('/v1/authz/*', requireUser);
app.route('/', authzRoutes);

export default app;
