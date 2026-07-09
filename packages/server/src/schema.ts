// A structural mirror of gratos-authz's SchemaDocument (packages/gratos-authz/
// src/schema.ts). Kept as a local copy so this package has no dependency on the
// worker; it must track the shape returned by GET /v1/authz/schema.

export interface SubjectTypeRef {
    type: string;
    relation?: string;
}

export interface RelationDef {
    subjects: SubjectTypeRef[];
}

export type PermissionExpr =
    | { rel: string }
    | { arrow: { via: string; permission: string } }
    | { union: PermissionExpr[] }
    | { intersection: PermissionExpr[] }
    | { exclusion: { base: PermissionExpr; subtract: PermissionExpr } };

export interface TypeDefinition {
    relations?: Record<string, RelationDef>;
    permissions?: Record<string, PermissionExpr>;
}

export interface SchemaDocument {
    definitions: Record<string, TypeDefinition>;
}

/** Shape of `GET /v1/authz/schema`. */
export interface SchemaResponse {
    schema: SchemaDocument;
    version: number;
    updated_at: number;
}
