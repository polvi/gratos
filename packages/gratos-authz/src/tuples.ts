// All relationship-tuple SQL: check-time lookups (TupleStore), writes, reads.

import { ApiError, ObjectRef, SubjectRef, fmtObject, fmtSubject } from './model';
import { SchemaDocument, TENANT_OBJECT_TYPE, typeDef } from './schema';

// Caps enforced at read time (writes can't practically be capped per-relation).
export const MAX_USERSETS_PER_RELATION = 100;
export const MAX_ARROW_PARENTS = 25;

export type Budget = { queries: number; maxQueries: number };

export type RelationLookup = { direct: boolean; usersets: SubjectRef[] };

/** Check-time reads, abstracted so the evaluator is unit-testable. */
export interface TupleStore {
    /** Direct-subject probe + subject-set collection for one object#relation. */
    relationLookup(obj: ObjectRef, relation: string, subject: SubjectRef): Promise<RelationLookup>;
    /** Direct subjects of obj#via (arrow traversal). */
    listParents(obj: ObjectRef, via: string): Promise<SubjectRef[]>;
}

export class D1TupleStore implements TupleStore {
    constructor(
        private db: D1Database,
        private tenant: string,
        private budget: Budget
    ) {}

    private spend() {
        if (++this.budget.queries > this.budget.maxQueries) {
            throw new ApiError(422, 'check budget exceeded');
        }
    }

    async relationLookup(obj: ObjectRef, relation: string, subject: SubjectRef): Promise<RelationLookup> {
        this.spend();
        // One D1 round trip: point probe for the subject + subject-set scan.
        const [direct, usersets] = await this.db.batch([
            this.db
                .prepare(
                    `SELECT 1 AS hit FROM relationships
                     WHERE tenant = ? AND object_type = ? AND object_id = ? AND relation = ?
                       AND subject_type = ? AND subject_id = ? AND subject_relation = ?
                     LIMIT 1`
                )
                .bind(this.tenant, obj.type, obj.id, relation, subject.type, subject.id, subject.relation ?? ''),
            this.db
                .prepare(
                    `SELECT subject_type, subject_id, subject_relation FROM relationships
                     WHERE tenant = ? AND object_type = ? AND object_id = ? AND relation = ?
                       AND subject_relation != ''
                     LIMIT ${MAX_USERSETS_PER_RELATION + 1}`
                )
                .bind(this.tenant, obj.type, obj.id, relation),
        ]);
        const rows = (usersets.results ?? []) as Array<{
            subject_type: string;
            subject_id: string;
            subject_relation: string;
        }>;
        if (rows.length > MAX_USERSETS_PER_RELATION) {
            throw new ApiError(422, `relation fan-out exceeded on ${fmtObject(obj)}#${relation}`);
        }
        return {
            direct: (direct.results ?? []).length > 0,
            usersets: rows.map((r) => ({ type: r.subject_type, id: r.subject_id, relation: r.subject_relation })),
        };
    }

    async listParents(obj: ObjectRef, via: string): Promise<SubjectRef[]> {
        this.spend();
        const result = await this.db
            .prepare(
                `SELECT subject_type, subject_id FROM relationships
                 WHERE tenant = ? AND object_type = ? AND object_id = ? AND relation = ?
                   AND subject_relation = ''
                 LIMIT ${MAX_ARROW_PARENTS + 1}`
            )
            .bind(this.tenant, obj.type, obj.id, via)
            .all<{ subject_type: string; subject_id: string }>();
        const rows = result.results ?? [];
        if (rows.length > MAX_ARROW_PARENTS) {
            throw new ApiError(422, `arrow fan-out exceeded on ${fmtObject(obj)}#${via}`);
        }
        return rows.map((r) => ({ type: r.subject_type, id: r.subject_id }));
    }
}

// --- writes ---

export type RelUpdate = {
    op: 'touch' | 'create' | 'delete';
    object: ObjectRef;
    relation: string;
    subject: SubjectRef;
};

export const MAX_UPDATES = 100;

/**
 * Validate one update against the tenant schema (+ built-in constraints).
 * Exported for unit tests.
 */
export function validateUpdate(schema: SchemaDocument | null, u: RelUpdate): string | null {
    const at = `${fmtObject(u.object)}#${u.relation}@${fmtSubject(u.subject)}`;

    // gratos_* types are control-plane/reserved: never writable over HTTP.
    // gratos_tenant ownership tuples are written only via trusted RPC.
    if (u.object.type === TENANT_OBJECT_TYPE) {
        return `${at}: ${TENANT_OBJECT_TYPE} is written only by the control plane`;
    }
    if (u.object.type.startsWith('gratos_')) {
        return `${at}: "${u.object.type}" is reserved`;
    }
    if (u.subject.type.startsWith('gratos_')) {
        return `${at}: "${u.subject.type}" may not be a subject`;
    }

    const def = typeDef(schema, u.object.type);
    if (!def) return `${at}: unknown object type "${u.object.type}"`;
    const rel = (def.relations ?? {})[u.relation];
    if (!rel) return `${at}: "${u.relation}" is not a relation on ${u.object.type}`;

    const allowed = rel.subjects.some(
        (ref) => ref.type === u.subject.type && (ref.relation ?? undefined) === u.subject.relation
    );
    if (!allowed) return `${at}: subject ${fmtSubject(u.subject)} not allowed by ${u.object.type}#${u.relation}`;
    return null;
}

export async function applyUpdates(
    db: D1Database,
    tenant: string,
    schema: SchemaDocument | null,
    updates: RelUpdate[]
): Promise<{ written: number; deleted: number }> {
    if (updates.length === 0) throw new ApiError(400, 'updates must be non-empty');
    if (updates.length > MAX_UPDATES) throw new ApiError(400, `too many updates (max ${MAX_UPDATES})`);

    const details = updates.map((u) => validateUpdate(schema, u)).filter((e): e is string => e !== null);
    if (details.length) throw new ApiError(400, 'invalid updates', details);

    const now = Date.now();
    const stmts = updates.map((u) => {
        const key = [tenant, u.object.type, u.object.id, u.relation, u.subject.type, u.subject.id, u.subject.relation ?? ''];
        switch (u.op) {
            case 'touch':
                return db
                    .prepare(
                        `INSERT OR IGNORE INTO relationships
                         (tenant, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
                    )
                    .bind(...key, now);
            case 'create':
                return db
                    .prepare(
                        `INSERT INTO relationships
                         (tenant, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
                    )
                    .bind(...key, now);
            case 'delete':
                return db
                    .prepare(
                        `DELETE FROM relationships
                         WHERE tenant = ? AND object_type = ? AND object_id = ? AND relation = ?
                           AND subject_type = ? AND subject_id = ? AND subject_relation = ?`
                    )
                    .bind(...key);
        }
    });

    let results: D1Result[];
    try {
        results = await db.batch(stmts); // one transaction: any failure rolls back all
    } catch (e) {
        if (e instanceof Error && /UNIQUE constraint/.test(e.message)) {
            throw new ApiError(409, 'create conflicts with an existing relationship');
        }
        throw e;
    }

    let written = 0;
    let deleted = 0;
    results.forEach((r, i) => {
        const changes = r.meta?.changes ?? 0;
        if (updates[i].op === 'delete') deleted += changes;
        else written += changes;
    });
    return { written, deleted };
}

// --- control-plane writes (trusted RPC only; bypass validateUpdate) ---

export type OwnerGrant = { tenant: string; userId: string };

/** Idempotently grant gratos_tenant:<tenant>#owner@user:<userId> tuples in the root space. */
export async function grantOwnerTuples(
    db: D1Database,
    rootTenant: string,
    entries: OwnerGrant[]
): Promise<{ written: number }> {
    const now = Date.now();
    let written = 0;
    for (let i = 0; i < entries.length; i += 50) {
        const chunk = entries.slice(i, i + 50);
        const results = await db.batch(
            chunk.map((e) =>
                db
                    .prepare(
                        `INSERT OR IGNORE INTO relationships
                         (tenant, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_at)
                         VALUES (?, ?, ?, 'owner', 'user', ?, '', ?)`
                    )
                    .bind(rootTenant, TENANT_OBJECT_TYPE, e.tenant, e.userId, now)
            )
        );
        for (const r of results) written += r.meta?.changes ?? 0;
    }
    return { written };
}

/** Full teardown for a deleted tenant: its authz data + its control-plane tuples. */
export async function deleteTenantData(db: D1Database, rootTenant: string, tenantKey: string): Promise<void> {
    await db.batch([
        db.prepare('DELETE FROM relationships WHERE tenant = ?').bind(tenantKey),
        db
            .prepare('DELETE FROM relationships WHERE tenant = ? AND object_type = ? AND object_id = ?')
            .bind(rootTenant, TENANT_OBJECT_TYPE, tenantKey),
        db.prepare('DELETE FROM schemas WHERE tenant = ?').bind(tenantKey),
    ]);
}

// --- filtered reads ---

export type RelFilter = {
    object_type?: string;
    object_id?: string;
    relation?: string;
    subject_type?: string;
    subject_id?: string;
    subject_relation?: string;
};

export type RelRow = { object: string; relation: string; subject: string; created_at: number };

const PK_COLS = ['object_type', 'object_id', 'relation', 'subject_type', 'subject_id', 'subject_relation'] as const;

export async function readRelationships(
    db: D1Database,
    tenant: string,
    filter: RelFilter,
    limit: number,
    cursor?: string
): Promise<{ relationships: RelRow[]; cursor: string | null }> {
    if (!filter.object_type && !filter.subject_type) {
        throw new ApiError(400, 'at least one of object_type or subject_type is required');
    }

    const where: string[] = ['tenant = ?'];
    const binds: unknown[] = [tenant];
    for (const col of PK_COLS) {
        const v = filter[col];
        if (v !== undefined) {
            where.push(`${col} = ?`);
            binds.push(v);
        }
    }

    if (cursor) {
        let last: string[];
        try {
            last = JSON.parse(atob(cursor));
            if (!Array.isArray(last) || last.length !== PK_COLS.length) throw new Error();
        } catch {
            throw new ApiError(400, 'invalid cursor');
        }
        where.push(`(${PK_COLS.join(', ')}) > (${PK_COLS.map(() => '?').join(', ')})`);
        binds.push(...last);
    }

    const result = await db
        .prepare(
            `SELECT object_type, object_id, relation, subject_type, subject_id, subject_relation, created_at
             FROM relationships WHERE ${where.join(' AND ')}
             ORDER BY ${PK_COLS.join(', ')}
             LIMIT ${limit + 1}`
        )
        .bind(...binds)
        .all<{
            object_type: string;
            object_id: string;
            relation: string;
            subject_type: string;
            subject_id: string;
            subject_relation: string;
            created_at: number;
        }>();

    const rows = result.results ?? [];
    const page = rows.slice(0, limit);
    const relationships = page.map((r) => ({
        object: `${r.object_type}:${r.object_id}`,
        relation: r.relation,
        subject: r.subject_relation
            ? `${r.subject_type}:${r.subject_id}#${r.subject_relation}`
            : `${r.subject_type}:${r.subject_id}`,
        created_at: r.created_at,
    }));

    let next: string | null = null;
    if (rows.length > limit) {
        const lastRow = page[page.length - 1];
        next = btoa(JSON.stringify(PK_COLS.map((c) => lastRow[c])));
    }
    return { relationships, cursor: next };
}
