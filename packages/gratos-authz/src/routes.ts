// /v1/authz/* API routes. All require a valid tenant session (enforced by the
// middleware chain in index.ts). Mutations are allowed for exactly two
// callers: the tenant's owner acting through the on-behalf routes
// (/v1/authz/tenants/:target/*, gated by the root-space control plane), and
// any authenticated user of an ANONYMOUS sandbox (throwaway pools are open).
// Tenant-pool users on managed tenants get reads + checks only.

import { Context, Hono } from 'hono';
import { ApiError, parseObjectRef, parseSubjectRef } from './model';
import { SchemaDocument, TENANT_OBJECT_TYPE, loadSchema, saveSchema, validateSchema } from './schema';
import { checkPermission, newBudget } from './check';
import { D1TupleStore, MAX_UPDATES, RelUpdate, applyUpdates, readRelationships } from './tuples';
import type { Variables } from './middleware';

export type Env = {
    DB: D1Database;
    /** Tenant key of the control-plane space: authgravity.org (prod) / localhost (dev). */
    ROOT_TENANT: string;
};

type Ctx = Context<{ Bindings: Env; Variables: Variables }>;

export async function runCheck(
    db: D1Database,
    tenant: string,
    schema: SchemaDocument | null,
    object: string,
    permission: string,
    subject: string
): Promise<boolean> {
    const budget = newBudget();
    const store = new D1TupleStore(db, tenant, budget);
    const result = await checkPermission(
        store,
        schema,
        budget,
        parseObjectRef(object),
        permission,
        parseSubjectRef(subject)
    );
    return result.allowed;
}

function canManage(c: Ctx): boolean {
    return c.get('superuser') === true || c.get('sandboxMode') === 'anonymous';
}

function requireManage(c: Ctx) {
    if (!canManage(c)) {
        throw new ApiError(403, 'managed by the tenant owner — use the AuthGravity dashboard');
    }
}

// --- shared handlers (tenant comes from context: host-derived, or the
// on-behalf target after the owner gate rewrites it) ---

async function handleStatus(c: Ctx) {
    const tenant = c.get('tenant');
    const schema = await loadSchema(c.env.DB, tenant);
    return c.json({
        user_id: c.get('userId'),
        mode: c.get('sandboxMode') === 'anonymous' ? 'open-sandbox' : 'managed',
        can_manage: canManage(c),
        schema_version: schema?.version ?? null,
    });
}

async function handleCheck(c: Ctx) {
    const tenant = c.get('tenant');
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body.permission !== 'string') {
        throw new ApiError(400, 'body must be {object, permission, subject}');
    }
    // Control-plane objects are not observable over HTTP (they would let any
    // root-pool user probe the customer -> owner map).
    const obj = parseObjectRef(body.object);
    if (obj.type === TENANT_OBJECT_TYPE) {
        throw new ApiError(400, `${TENANT_OBJECT_TYPE} is not checkable via the API`);
    }
    const schema = await loadSchema(c.env.DB, tenant);
    const allowed = await runCheck(c.env.DB, tenant, schema?.doc ?? null, body.object, body.permission, body.subject);
    return c.json({ allowed });
}

async function handleWriteRels(c: Ctx) {
    const tenant = c.get('tenant');
    requireManage(c);
    const body = await c.req.json().catch(() => null);
    if (!body || !Array.isArray(body.updates)) {
        throw new ApiError(400, 'body must be {updates: [{op, object, relation, subject}]}');
    }
    if (body.updates.length > MAX_UPDATES) {
        throw new ApiError(400, `too many updates (max ${MAX_UPDATES})`);
    }

    const updates: RelUpdate[] = body.updates.map((u: any, i: number) => {
        if (!u || (u.op !== 'touch' && u.op !== 'create' && u.op !== 'delete')) {
            throw new ApiError(400, `updates[${i}].op must be "touch", "create" or "delete"`);
        }
        if (typeof u.relation !== 'string') {
            throw new ApiError(400, `updates[${i}].relation must be a string`);
        }
        return {
            op: u.op,
            object: parseObjectRef(u.object, `updates[${i}].object`),
            relation: u.relation,
            subject: parseSubjectRef(u.subject, `updates[${i}].subject`),
        };
    });

    const schema = await loadSchema(c.env.DB, tenant);
    const result = await applyUpdates(c.env.DB, tenant, schema?.doc ?? null, updates);
    return c.json(result);
}

async function handleReadRels(c: Ctx) {
    const tenant = c.get('tenant');
    const q = c.req.query();
    if (q.object_type === TENANT_OBJECT_TYPE || q.subject_type === TENANT_OBJECT_TYPE) {
        throw new ApiError(400, `${TENANT_OBJECT_TYPE} is not readable via the API`);
    }
    const limit = Math.min(Math.max(parseInt(q.limit || '100', 10) || 100, 1), 1000);
    const filter = {
        object_type: q.object_type,
        object_id: q.object_id,
        relation: q.relation,
        subject_type: q.subject_type,
        subject_id: q.subject_id,
        subject_relation: q.subject_relation,
    };
    const result = await readRelationships(c.env.DB, tenant, filter, limit, q.cursor);
    return c.json(result);
}

async function handleGetSchema(c: Ctx) {
    const tenant = c.get('tenant');
    const stored = await loadSchema(c.env.DB, tenant);
    if (!stored) return c.json({ error: 'no schema' }, 404);
    return c.json({ schema: stored.doc, version: stored.version, updated_at: stored.updatedAt });
}

async function handlePutSchema(c: Ctx) {
    const tenant = c.get('tenant');
    requireManage(c);
    const body = await c.req.json().catch(() => null);
    if (!body) throw new ApiError(400, 'body must be a schema document');

    const result = validateSchema(body);
    if (!result.ok) {
        throw new ApiError(400, 'invalid schema', result.errors);
    }
    const version = await saveSchema(c.env.DB, tenant, result.doc);
    return c.json({ ok: true, version });
}

// --- on-behalf owner gate ---

/**
 * Wrap a handler for /v1/authz/tenants/:target/* — the caller must hold a
 * ROOT_TENANT session (dash pool) and manage on the control-plane object
 * gratos_tenant:<target>. On success the context is retargeted at the tenant
 * with full manage rights.
 */
function onBehalf(handler: (c: Ctx) => Promise<Response>) {
    return async (c: Ctx) => {
        if (c.get('tenant') !== c.env.ROOT_TENANT) {
            throw new ApiError(403, 'tenant management requires a session on the root auth endpoint');
        }
        let target = c.req.param('target' as never) as string;
        // Sandbox tenant keys contain '/', sent percent-encoded; cover both
        // router decode behaviors (tenant keys never contain a literal '%').
        if (target.includes('%')) target = decodeURIComponent(target);
        if (!target || target === c.env.ROOT_TENANT) {
            throw new ApiError(403, 'this tenant cannot be managed via the API');
        }
        const userId = c.get('userId')!;
        const allowed = await runCheck(
            c.env.DB,
            c.env.ROOT_TENANT,
            null,
            `${TENANT_OBJECT_TYPE}:${target}`,
            'manage',
            `user:${userId}`
        );
        if (!allowed) {
            throw new ApiError(403, "you don't manage this tenant");
        }
        c.set('tenant', target);
        c.set('superuser', true);
        c.set('sandboxMode', undefined);
        return handler(c);
    };
}

export const authzRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

authzRoutes.onError((err, c) => {
    if (err instanceof ApiError) {
        return c.json({ error: err.message, ...(err.details ? { details: err.details } : {}) }, err.status);
    }
    console.error('authz error:', err);
    return c.json({ error: 'Internal error' }, 500);
});

// Tenant-host routes (tenant = the request's own host).
authzRoutes.get('/v1/authz/status', handleStatus);
authzRoutes.post('/v1/authz/check', handleCheck);
authzRoutes.post('/v1/authz/relationships', handleWriteRels);
authzRoutes.get('/v1/authz/relationships', handleReadRels);
authzRoutes.get('/v1/authz/schema', handleGetSchema);
authzRoutes.put('/v1/authz/schema', handlePutSchema);

// On-behalf management routes (caller = root-pool tenant owner).
authzRoutes.get('/v1/authz/tenants/:target/status', onBehalf(handleStatus));
authzRoutes.post('/v1/authz/tenants/:target/check', onBehalf(handleCheck));
authzRoutes.post('/v1/authz/tenants/:target/relationships', onBehalf(handleWriteRels));
authzRoutes.get('/v1/authz/tenants/:target/relationships', onBehalf(handleReadRels));
authzRoutes.get('/v1/authz/tenants/:target/schema', onBehalf(handleGetSchema));
authzRoutes.put('/v1/authz/tenants/:target/schema', onBehalf(handlePutSchema));
