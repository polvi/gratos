// @authgravity/server — server-side authorization client + tooling.
export {
    authgravity,
    AuthgravityServer,
    user,
    touch,
    create,
    del,
} from './client';
export type {
    Amr,
    AnySchema,
    AuthgravityConfig,
    CheckRef,
    CheckResult,
    CookieSource,
    RelUpdate,
    SchemaShape,
} from './client';

export { escapeObjectId, unescapeObjectId, objectRef, parseObjectRef, MAX_OBJECT_ID_LENGTH } from './ids';

export { schemaToTypes } from './codegen';
export type { CodegenOptions } from './codegen';
export type {
    SchemaDocument,
    SchemaResponse,
    TypeDefinition,
    RelationDef,
    SubjectTypeRef,
    PermissionExpr,
} from './schema';
