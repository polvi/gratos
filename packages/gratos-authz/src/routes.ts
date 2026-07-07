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
import { generateSchemaForDomain } from './generate';
import { isServiceToken, listTokens, mintToken, revokeToken, verifyToken } from './tokens';
import type { Variables } from './middleware';

export type Env = {
    DB: D1Database;
    /** Tenant key of the control-plane space: authgravity.org (prod) / localhost (dev). */
    ROOT_TENANT: string;
    /** Workers AI, for schema generation. */
    AI: Ai;
    /** Browser Rendering crawl API credentials (CF_API_TOKEN is a secret;
     *  without it generation falls back to fetching the homepage). */
    CF_ACCOUNT_ID?: string;
    CF_API_TOKEN?: string;
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
    return c.get('superuser') === true || c.get('sandboxMode') === 'anonymous' || c.get('service') === true;
}

function requireManage(c: Ctx) {
    if (!canManage(c)) {
        throw new ApiError(403, 'managed by the tenant owner — use the AuthGravity dashboard');
    }
}

/**
 * Recognize `Authorization: Bearer agk_...` service tokens on tenant-host
 * routes. Session bearers are resolved upstream by gratos-multi; the agk_
 * prefix never collides with a session id (UUIDs). Tenant scoping is the
 * boundary: the token must belong to the tenant of the current request.
 */
export async function serviceTokenAuth(c: Ctx, next: () => Promise<void>) {
    if (!c.get('userId')) {
        const auth = c.req.header('Authorization');
        const bearer = auth?.startsWith('Bearer ') ? auth.slice(7).trim() : undefined;
        if (bearer && isServiceToken(bearer)) {
            const verified = await verifyToken(c.env.DB, c.get('tenant'), bearer);
            if (!verified) {
                return c.json({ error: 'Invalid service token for this tenant' }, 401);
            }
            c.set('service', true);
            c.executionCtx?.waitUntil?.(verified.touch());
        }
    }
    await next();
}

// --- shared handlers (tenant comes from context: host-derived, or the
// on-behalf target after the owner gate rewrites it) ---

async function handleStatus(c: Ctx) {
    const tenant = c.get('tenant');
    const schema = await loadSchema(c.env.DB, tenant);
    return c.json({
        user_id: c.get('userId') ?? null,
        auth: c.get('service') ? 'service' : 'session',
        mode: c.get('sandboxMode') === 'anonymous' ? 'open-sandbox' : 'managed',
        can_manage: canManage(c),
        schema_version: schema?.version ?? null,
    });
}

const MAX_CHECK_ITEMS = 50;

async function handleCheck(c: Ctx) {
    const tenant = c.get('tenant');
    const body = await c.req.json().catch(() => null);
    if (!body) {
        throw new ApiError(400, 'body must be {object, permission, subject?} or {items: [...]}');
    }
    const schema = await loadSchema(c.env.DB, tenant);
    const userId = c.get('userId');

    // subject omitted or "self" = the session user — one round trip both
    // authenticates and authorizes, and the caller gets the uuid back.
    const resolveSubject = (subject: unknown, label: string): string => {
        if (subject === undefined || subject === null || subject === 'self') {
            if (!userId) {
                throw new ApiError(400, `${label}subject is required when authenticating with a service token`);
            }
            return `user:${userId}`;
        }
        if (typeof subject !== 'string') throw new ApiError(400, `${label}subject must be a string`);
        return subject;
    };

    const checkOne = async (item: any, label: string): Promise<boolean> => {
        if (!item || typeof item.permission !== 'string') {
            throw new ApiError(400, `${label}permission must be a string`);
        }
        // Control-plane objects are not observable over HTTP (they would let
        // any root-pool user probe the customer -> owner map).
        const obj = parseObjectRef(item.object, `${label}object`);
        if (obj.type === TENANT_OBJECT_TYPE) {
            throw new ApiError(400, `${TENANT_OBJECT_TYPE} is not checkable via the API`);
        }
        return runCheck(
            c.env.DB,
            tenant,
            schema?.doc ?? null,
            item.object,
            item.permission,
            resolveSubject(item.subject, label)
        );
    };

    // Batch: {items: [{object, permission, subject?}]} — evaluated
    // concurrently, each with its own query budget; one bad item reports its
    // error in place instead of failing the batch.
    if (Array.isArray(body.items)) {
        if (body.items.length === 0) throw new ApiError(400, 'items must be non-empty');
        if (body.items.length > MAX_CHECK_ITEMS) {
            throw new ApiError(400, `too many items (max ${MAX_CHECK_ITEMS})`);
        }
        const results = await Promise.all(
            body.items.map(async (item: any, i: number) => {
                try {
                    return { allowed: await checkOne(item, `items[${i}].`) };
                } catch (e) {
                    if (e instanceof ApiError) return { allowed: false, error: e.message };
                    throw e;
                }
            })
        );
        return c.json({ results, ...(userId ? { user_id: userId } : {}) });
    }

    const allowed = await checkOne(body, '');
    return c.json({ allowed, ...(userId ? { user_id: userId } : {}) });
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

/**
 * Crawl the tenant's site and draft an authz schema + human-readable
 * description with AI. Returns the draft only — the owner reviews it and
 * applies it via the normal PUT /schema.
 */
async function handleGenerateSchema(c: Ctx) {
    const tenant = c.get('tenant');
    requireManage(c);
    // Sandbox tenant keys (sandbox.authgravity.org/<id>) are not crawlable sites.
    if (tenant.includes('/')) {
        throw new ApiError(400, 'schema generation needs a crawlable site — only domain tenants are supported');
    }
    const draft = await generateSchemaForDomain(c.env, tenant);
    return c.json(draft);
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
    // Service tokens write relationships, not schemas — schema changes stay
    // with the owner (dash) or open sandboxes.
    if (c.get('service') && !c.get('superuser') && c.get('sandboxMode') !== 'anonymous') {
        throw new ApiError(403, 'schema changes are owner-only — use the AuthGravity dashboard');
    }
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
        if (c.get('tenant') !== c.env.ROOT_TENANT || !c.get('userId')) {
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

// --- service-token management (owner-only, so mounted on-behalf only) ---

async function handleMintToken(c: Ctx) {
    const tenant = c.get('tenant');
    const body = await c.req.json().catch(() => ({}));
    const name = typeof body?.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 64) : 'default';
    const minted = await mintToken(c.env.DB, tenant, name);
    // The secret is returned exactly once; only its hash is stored.
    return c.json(minted, 201);
}

async function handleListTokens(c: Ctx) {
    return c.json({ tokens: await listTokens(c.env.DB, c.get('tenant')) });
}

async function handleRevokeToken(c: Ctx) {
    const id = c.req.param('id' as never) as string;
    const revoked = await revokeToken(c.env.DB, c.get('tenant'), id);
    if (!revoked) throw new ApiError(404, 'token not found');
    return c.json({ revoked: true });
}

// On-behalf management routes (caller = root-pool tenant owner).
authzRoutes.get('/v1/authz/tenants/:target/status', onBehalf(handleStatus));
authzRoutes.post('/v1/authz/tenants/:target/tokens', onBehalf(handleMintToken));
authzRoutes.get('/v1/authz/tenants/:target/tokens', onBehalf(handleListTokens));
authzRoutes.delete('/v1/authz/tenants/:target/tokens/:id', onBehalf(handleRevokeToken));
authzRoutes.post('/v1/authz/tenants/:target/check', onBehalf(handleCheck));
authzRoutes.post('/v1/authz/tenants/:target/relationships', onBehalf(handleWriteRels));
authzRoutes.get('/v1/authz/tenants/:target/relationships', onBehalf(handleReadRels));
authzRoutes.get('/v1/authz/tenants/:target/schema', onBehalf(handleGetSchema));
authzRoutes.put('/v1/authz/tenants/:target/schema', onBehalf(handlePutSchema));
authzRoutes.post('/v1/authz/tenants/:target/generate-schema', onBehalf(handleGenerateSchema));
