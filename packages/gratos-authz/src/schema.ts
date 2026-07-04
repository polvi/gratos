// Tenant schema documents: SpiceDB-style object definitions expressed as JSON.
//
// A definition declares relations (which subject types may be written into
// tuples) and permissions (userset-rewrite expressions evaluated at check
// time). Example:
//
// { "definitions": { "document": {
//     "relations":   { "viewer": { "subjects": [{ "type": "user" },
//                                               { "type": "group", "relation": "member" }] },
//                      "parent": { "subjects": [{ "type": "folder" }] } },
//     "permissions": { "view": { "union": [{ "rel": "viewer" },
//                                          { "arrow": { "via": "parent", "permission": "view" } }] } } } } }

import { NAME_RE } from './model';

export type SchemaDocument = {
    definitions: Record<string, TypeDefinition>;
};

export type TypeDefinition = {
    relations?: Record<string, RelationDef>;
    permissions?: Record<string, PermissionExpr>;
};

export type RelationDef = {
    subjects: SubjectTypeRef[];
};

/** relation present => subject sets of that relation allowed (e.g. group#member). */
export type SubjectTypeRef = { type: string; relation?: string };

export type PermissionExpr =
    | { rel: string }
    | { arrow: { via: string; permission: string } }
    | { union: PermissionExpr[] }
    | { intersection: PermissionExpr[] }
    | { exclusion: { base: PermissionExpr; subtract: PermissionExpr } };

// Built-in definitions merged into every tenant's effective schema.
// `gratos_authz:root` is the singleton object gating this service itself:
// bootstrap writes the first root#admin tuple; schema/tuple writes require
// the `manage` permission on it. Tenants cannot redefine built-ins.
export const BUILTIN_OBJECT = { type: 'gratos_authz', id: 'root' } as const;
export const BUILTIN_DEFS: Record<string, TypeDefinition> = {
    user: {},
    gratos_authz: {
        relations: {
            admin: { subjects: [{ type: 'user' }] },
        },
        permissions: {
            manage: { rel: 'admin' },
        },
    },
};

const RESERVED_PREFIX = 'gratos_';

const LIMITS = {
    maxDefinitions: 100,
    maxMembersPerType: 100, // relations + permissions
    maxExprNodes: 50,
    maxDocumentBytes: 64 * 1024,
};

export function isReservedType(name: string): boolean {
    return name === 'user' || name.startsWith(RESERVED_PREFIX);
}

/** Effective definition for a type: tenant schema first, then built-ins. */
export function typeDef(doc: SchemaDocument | null, type: string): TypeDefinition | null {
    if (BUILTIN_DEFS[type]) return BUILTIN_DEFS[type];
    return doc?.definitions[type] ?? null;
}

type ValidationResult = { ok: true; doc: SchemaDocument } | { ok: false; errors: string[] };

export function validateSchema(input: unknown): ValidationResult {
    const errors: string[] = [];

    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        return { ok: false, errors: ['schema must be a JSON object'] };
    }
    const root = input as Record<string, unknown>;
    for (const key of Object.keys(root)) {
        if (key !== 'definitions') errors.push(`unknown key "${key}" at top level`);
    }
    if (typeof root.definitions !== 'object' || root.definitions === null || Array.isArray(root.definitions)) {
        errors.push('"definitions" must be an object');
        return { ok: false, errors };
    }

    if (JSON.stringify(input).length > LIMITS.maxDocumentBytes) {
        errors.push(`schema document exceeds ${LIMITS.maxDocumentBytes} bytes`);
    }

    const defs = root.definitions as Record<string, unknown>;
    const typeNames = Object.keys(defs);
    if (typeNames.length > LIMITS.maxDefinitions) {
        errors.push(`too many definitions (max ${LIMITS.maxDefinitions})`);
    }

    // First pass: shape + names, so the second pass can resolve references.
    for (const typeName of typeNames) {
        if (!NAME_RE.test(typeName)) {
            errors.push(`type name "${typeName}" is invalid`);
            continue;
        }
        if (isReservedType(typeName)) {
            errors.push(`type name "${typeName}" is reserved`);
            continue;
        }
        const def = defs[typeName];
        if (typeof def !== 'object' || def === null || Array.isArray(def)) {
            errors.push(`${typeName}: definition must be an object`);
            continue;
        }
        for (const key of Object.keys(def)) {
            if (key !== 'relations' && key !== 'permissions') {
                errors.push(`${typeName}: unknown key "${key}"`);
            }
        }
    }
    if (errors.length) return { ok: false, errors };

    const doc = input as SchemaDocument;

    const relationNames = (t: TypeDefinition) => Object.keys(t.relations ?? {});
    const permissionNames = (t: TypeDefinition) => Object.keys(t.permissions ?? {});

    // Resolve a subject type against tenant defs + built-ins ('user' only —
    // gratos_authz may not be referenced by tenant schemas).
    const subjectTypeDef = (type: string): TypeDefinition | null => {
        if (type === 'user') return BUILTIN_DEFS.user;
        if (isReservedType(type)) return null;
        return doc.definitions[type] ?? null;
    };

    for (const [typeName, def] of Object.entries(doc.definitions)) {
        const rels = def.relations ?? {};
        const perms = def.permissions ?? {};

        if (relationNames(def).length + permissionNames(def).length > LIMITS.maxMembersPerType) {
            errors.push(`${typeName}: too many relations+permissions (max ${LIMITS.maxMembersPerType})`);
        }

        if (def.relations !== undefined && (typeof def.relations !== 'object' || Array.isArray(def.relations))) {
            errors.push(`${typeName}: "relations" must be an object`);
            continue;
        }
        if (def.permissions !== undefined && (typeof def.permissions !== 'object' || Array.isArray(def.permissions))) {
            errors.push(`${typeName}: "permissions" must be an object`);
            continue;
        }

        // Relations and permissions share one namespace ({rel: x} resolves either).
        for (const name of permissionNames(def)) {
            if (name in rels) errors.push(`${typeName}: "${name}" is both a relation and a permission`);
        }

        for (const [relName, rel] of Object.entries(rels)) {
            const loc = `${typeName}.${relName}`;
            if (!NAME_RE.test(relName)) {
                errors.push(`${loc}: relation name is invalid`);
                continue;
            }
            if (typeof rel !== 'object' || rel === null || Array.isArray(rel)) {
                errors.push(`${loc}: relation must be an object with "subjects"`);
                continue;
            }
            for (const key of Object.keys(rel)) {
                if (key !== 'subjects') errors.push(`${loc}: unknown key "${key}"`);
            }
            if (!Array.isArray(rel.subjects) || rel.subjects.length === 0) {
                errors.push(`${loc}: "subjects" must be a non-empty array`);
                continue;
            }
            for (const ref of rel.subjects) {
                if (typeof ref !== 'object' || ref === null || typeof (ref as SubjectTypeRef).type !== 'string') {
                    errors.push(`${loc}: each subject must be {type} or {type, relation}`);
                    continue;
                }
                for (const key of Object.keys(ref)) {
                    if (key !== 'type' && key !== 'relation') errors.push(`${loc}: unknown subject key "${key}"`);
                }
                const target = subjectTypeDef(ref.type);
                if (!target) {
                    errors.push(`${loc}: unknown subject type "${ref.type}"`);
                    continue;
                }
                if (ref.relation !== undefined) {
                    if (typeof ref.relation !== 'string' || !NAME_RE.test(ref.relation)) {
                        errors.push(`${loc}: subject relation is invalid`);
                    } else if (!(target.relations ?? {})[ref.relation]) {
                        // v1: subject sets reference relations only, not permissions.
                        errors.push(`${loc}: "${ref.type}" has no relation "${ref.relation}"`);
                    }
                }
            }
        }

        for (const [permName, expr] of Object.entries(perms)) {
            const loc = `${typeName}.${permName}`;
            if (!NAME_RE.test(permName)) {
                errors.push(`${loc}: permission name is invalid`);
                continue;
            }
            validateExpr(expr, def, typeName, permName, doc, subjectTypeDef, errors);
        }

        // Same-type static cycles through {rel} edges between permissions.
        detectRelCycles(typeName, def, errors);
    }

    return errors.length ? { ok: false, errors } : { ok: true, doc };
}

function validateExpr(
    expr: unknown,
    def: TypeDefinition,
    typeName: string,
    permName: string,
    doc: SchemaDocument,
    subjectTypeDef: (t: string) => TypeDefinition | null,
    errors: string[]
): void {
    const loc = `${typeName}.${permName}`;
    let nodes = 0;

    const walk = (e: unknown): void => {
        if (++nodes > LIMITS.maxExprNodes) return;
        if (typeof e !== 'object' || e === null || Array.isArray(e)) {
            errors.push(`${loc}: expression must be an object`);
            return;
        }
        const keys = Object.keys(e);
        if (keys.length !== 1) {
            errors.push(`${loc}: expression must have exactly one of rel/arrow/union/intersection/exclusion`);
            return;
        }
        const node = e as Record<string, unknown>;
        switch (keys[0]) {
            case 'rel': {
                const target = node.rel;
                if (typeof target !== 'string') {
                    errors.push(`${loc}: "rel" must be a string`);
                } else if (!(def.relations ?? {})[target] && !(def.permissions ?? {})[target]) {
                    errors.push(`${loc}: unknown relation or permission "${target}"`);
                }
                break;
            }
            case 'arrow': {
                const arrow = node.arrow;
                if (typeof arrow !== 'object' || arrow === null) {
                    errors.push(`${loc}: "arrow" must be {via, permission}`);
                    break;
                }
                const { via, permission } = arrow as { via?: unknown; permission?: unknown };
                if (typeof via !== 'string' || typeof permission !== 'string') {
                    errors.push(`${loc}: "arrow" must be {via, permission} of strings`);
                    break;
                }
                const viaRel = (def.relations ?? {})[via];
                if (!viaRel) {
                    errors.push(`${loc}: arrow via "${via}" is not a relation on ${typeName}`);
                    break;
                }
                for (const ref of viaRel.subjects ?? []) {
                    if (typeof ref !== 'object' || ref === null) continue;
                    if (ref.relation) {
                        // Same restriction SpiceDB imposes: arrow-traversed
                        // relations must have direct-only subjects.
                        errors.push(`${loc}: arrow via "${via}" allows subject set "${ref.type}#${ref.relation}" — arrows require direct-only subjects`);
                        continue;
                    }
                    const target = subjectTypeDef(ref.type);
                    if (!target) continue; // unknown type already reported by relation validation
                    if (!(target.relations ?? {})[permission] && !(target.permissions ?? {})[permission]) {
                        errors.push(`${loc}: arrow target "${ref.type}" has no relation or permission "${permission}"`);
                    }
                }
                break;
            }
            case 'union':
            case 'intersection': {
                const children = node[keys[0]];
                if (!Array.isArray(children) || children.length === 0) {
                    errors.push(`${loc}: "${keys[0]}" must be a non-empty array`);
                    break;
                }
                children.forEach(walk);
                break;
            }
            case 'exclusion': {
                const ex = node.exclusion;
                if (typeof ex !== 'object' || ex === null) {
                    errors.push(`${loc}: "exclusion" must be {base, subtract}`);
                    break;
                }
                const { base, subtract } = ex as { base?: unknown; subtract?: unknown };
                if (base === undefined || subtract === undefined) {
                    errors.push(`${loc}: "exclusion" must be {base, subtract}`);
                    break;
                }
                walk(base);
                walk(subtract);
                break;
            }
            default:
                errors.push(`${loc}: unknown expression key "${keys[0]}"`);
        }
    };

    walk(expr);
    if (nodes > LIMITS.maxExprNodes) {
        errors.push(`${loc}: expression exceeds ${LIMITS.maxExprNodes} nodes`);
    }
}

/** Reject a -> b -> a reference cycles between permissions of the same type. */
function detectRelCycles(typeName: string, def: TypeDefinition, errors: string[]): void {
    const perms = def.permissions ?? {};

    const relEdges = (expr: PermissionExpr, out: string[]): string[] => {
        if ('rel' in expr) {
            if (perms[expr.rel]) out.push(expr.rel);
        } else if ('union' in expr) {
            expr.union.forEach((e) => relEdges(e, out));
        } else if ('intersection' in expr) {
            expr.intersection.forEach((e) => relEdges(e, out));
        } else if ('exclusion' in expr) {
            relEdges(expr.exclusion.base, out);
            relEdges(expr.exclusion.subtract, out);
        }
        // arrows recurse into a *different* object, never a static same-type cycle
        return out;
    };

    const visiting = new Set<string>();
    const done = new Set<string>();

    const visit = (name: string): boolean => {
        if (done.has(name)) return false;
        if (visiting.has(name)) return true;
        visiting.add(name);
        const expr = perms[name];
        let cyclic = false;
        if (expr && typeof expr === 'object') {
            for (const next of relEdges(expr, [])) {
                if (visit(next)) cyclic = true;
            }
        }
        visiting.delete(name);
        done.add(name);
        return cyclic;
    };

    for (const name of Object.keys(perms)) {
        if (visit(name)) {
            errors.push(`${typeName}.${name}: permission reference cycle`);
            return; // one report per type is enough
        }
    }
}

// --- persistence ---

export type StoredSchema = { doc: SchemaDocument; version: number; updatedAt: number };

export async function loadSchema(db: D1Database, tenant: string): Promise<StoredSchema | null> {
    const row = await db
        .prepare('SELECT document, version, updated_at FROM schemas WHERE tenant = ?')
        .bind(tenant)
        .first<{ document: string; version: number; updated_at: number }>();
    if (!row) return null;
    return { doc: JSON.parse(row.document) as SchemaDocument, version: row.version, updatedAt: row.updated_at };
}

export async function saveSchema(db: D1Database, tenant: string, doc: SchemaDocument): Promise<number> {
    const result = await db
        .prepare(
            `INSERT INTO schemas (tenant, document, version, updated_at) VALUES (?, ?, 1, ?)
             ON CONFLICT(tenant) DO UPDATE SET document = excluded.document,
                 version = schemas.version + 1, updated_at = excluded.updated_at
             RETURNING version`
        )
        .bind(tenant, JSON.stringify(doc), Date.now())
        .first<{ version: number }>();
    return result?.version ?? 1;
}
