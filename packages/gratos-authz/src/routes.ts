// /v1/authz/* API routes. All require a valid tenant session (enforced by the
// middleware chain in index.ts); mutations additionally require the caller to
// hold the `manage` permission on the built-in gratos_authz:root object.

import { Hono } from 'hono';
import { ApiError, parseObjectRef, parseSubjectRef } from './model';
import { BUILTIN_OBJECT, SchemaDocument, loadSchema, saveSchema, validateSchema } from './schema';
import { checkPermission, newBudget } from './check';
import { D1TupleStore, MAX_UPDATES, RelUpdate, applyUpdates, readRelationships } from './tuples';
import type { Variables } from './middleware';

export type Env = {
    DB: D1Database;
};

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

async function requireManage(db: D1Database, tenant: string, schema: SchemaDocument | null, userId: string) {
    const allowed = await runCheck(
        db,
        tenant,
        schema,
        `${BUILTIN_OBJECT.type}:${BUILTIN_OBJECT.id}`,
        'manage',
        `user:${userId}`
    );
    if (!allowed) {
        throw new ApiError(403, 'admin required — bootstrap first or ask an admin for the admin relation');
    }
}

async function countAdmins(db: D1Database, tenant: string): Promise<number> {
    const row = await db
        .prepare(
            `SELECT COUNT(*) AS count FROM relationships
             WHERE tenant = ? AND object_type = ? AND object_id = ? AND relation = 'admin'`
        )
        .bind(tenant, BUILTIN_OBJECT.type, BUILTIN_OBJECT.id)
        .first<{ count: number }>();
    return row?.count ?? 0;
}

export const authzRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

authzRoutes.onError((err, c) => {
    if (err instanceof ApiError) {
        return c.json({ error: err.message, ...(err.details ? { details: err.details } : {}) }, err.status);
    }
    console.error('authz error:', err);
    return c.json({ error: 'Internal error' }, 500);
});

// Tenant + caller status, used by the console.
authzRoutes.get('/v1/authz/status', async (c) => {
    const tenant = c.get('tenant');
    const userId = c.get('userId')!;
    const [admins, schema] = await Promise.all([countAdmins(c.env.DB, tenant), loadSchema(c.env.DB, tenant)]);
    const admin =
        admins > 0 && (await runCheck(c.env.DB, tenant, schema?.doc ?? null, 'gratos_authz:root', 'manage', `user:${userId}`));
    return c.json({
        user_id: userId,
        bootstrapped: admins > 0,
        admins,
        admin,
        schema_version: schema?.version ?? null,
    });
});

// First valid session in the tenant becomes admin, atomically, while the
// admin set is empty. Deleting the last admin tuple deliberately reopens this.
authzRoutes.post('/v1/authz/bootstrap', async (c) => {
    const tenant = c.get('tenant');
    const userId = c.get('userId')!;
    const result = await c.env.DB.prepare(
        `INSERT INTO relationships
             (tenant, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_at)
         SELECT ?1, ?2, ?3, 'admin', 'user', ?4, '', ?5
         WHERE NOT EXISTS (
             SELECT 1 FROM relationships
             WHERE tenant = ?1 AND object_type = ?2 AND object_id = ?3 AND relation = 'admin'
         )`
    )
        .bind(tenant, BUILTIN_OBJECT.type, BUILTIN_OBJECT.id, userId, Date.now())
        .run();

    if ((result.meta?.changes ?? 0) === 0) {
        return c.json({ error: 'already bootstrapped' }, 409);
    }
    return c.json({ bootstrapped: true, admin: userId });
});

authzRoutes.post('/v1/authz/check', async (c) => {
    const tenant = c.get('tenant');
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body.permission !== 'string') {
        throw new ApiError(400, 'body must be {object, permission, subject}');
    }
    const schema = await loadSchema(c.env.DB, tenant);
    const allowed = await runCheck(c.env.DB, tenant, schema?.doc ?? null, body.object, body.permission, body.subject);
    return c.json({ allowed });
});

authzRoutes.post('/v1/authz/relationships', async (c) => {
    const tenant = c.get('tenant');
    const userId = c.get('userId')!;
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
    await requireManage(c.env.DB, tenant, schema?.doc ?? null, userId);
    const result = await applyUpdates(c.env.DB, tenant, schema?.doc ?? null, updates);
    return c.json(result);
});

authzRoutes.get('/v1/authz/relationships', async (c) => {
    const tenant = c.get('tenant');
    const q = c.req.query();
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
});

authzRoutes.get('/v1/authz/schema', async (c) => {
    const tenant = c.get('tenant');
    const stored = await loadSchema(c.env.DB, tenant);
    if (!stored) return c.json({ error: 'no schema' }, 404);
    return c.json({ schema: stored.doc, version: stored.version, updated_at: stored.updatedAt });
});

authzRoutes.put('/v1/authz/schema', async (c) => {
    const tenant = c.get('tenant');
    const userId = c.get('userId')!;
    const body = await c.req.json().catch(() => null);
    if (!body) throw new ApiError(400, 'body must be a schema document');

    const current = await loadSchema(c.env.DB, tenant);
    await requireManage(c.env.DB, tenant, current?.doc ?? null, userId);

    const result = validateSchema(body);
    if (!result.ok) {
        throw new ApiError(400, 'invalid schema', result.errors);
    }
    const version = await saveSchema(c.env.DB, tenant, result.doc);
    return c.json({ ok: true, version });
});
