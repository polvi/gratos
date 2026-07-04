// Recursive userset-rewrite evaluation: does `subject` have `permission` on
// `object`? Resolves direct tuples, subject sets (group:eng#member), computed
// permissions, and arrows (parent->view), bounded by a query budget and depth
// limit, with memoization and cycle detection over the (object, name) space.

import { ApiError, ObjectRef, SubjectRef, fmtObject } from './model';
import { PermissionExpr, SchemaDocument, TypeDefinition, typeDef } from './schema';
import { Budget, TupleStore } from './tuples';

export const MAX_QUERIES = 100;
export const MAX_DEPTH = 25;

export type CheckResult = { allowed: boolean; queries: number };

type Ctx = {
    store: TupleStore;
    schema: SchemaDocument | null;
    subject: SubjectRef;
    budget: Budget;
    memo: Map<string, Promise<boolean>>;
    inProgress: Set<string>;
    parentsCache: Map<string, SubjectRef[]>;
};

export function newBudget(maxQueries = MAX_QUERIES): Budget {
    return { queries: 0, maxQueries };
}

export async function checkPermission(
    store: TupleStore,
    schema: SchemaDocument | null,
    budget: Budget,
    object: ObjectRef,
    permission: string,
    subject: SubjectRef
): Promise<CheckResult> {
    const ctx: Ctx = {
        store,
        schema,
        subject,
        budget,
        memo: new Map(),
        inProgress: new Set(),
        parentsCache: new Map(),
    };
    const allowed = await checkInternal(ctx, object, permission, 0);
    return { allowed, queries: ctx.budget.queries };
}

async function checkInternal(ctx: Ctx, obj: ObjectRef, name: string, depth: number): Promise<boolean> {
    if (depth > MAX_DEPTH) throw new ApiError(422, 'check depth exceeded');

    const key = `${fmtObject(obj)}#${name}`;
    // A subproblem that recursively depends on itself contributes nothing new
    // (least-fixpoint semantics) — this terminates cyclic *data* like nested
    // groups independent of the depth limit.
    if (ctx.inProgress.has(key)) return false;
    const memoized = ctx.memo.get(key);
    if (memoized) return memoized;

    const promise = (async () => {
        ctx.inProgress.add(key);
        try {
            const def = typeDef(ctx.schema, obj.type);
            if (!def) throw new ApiError(400, `unknown object type "${obj.type}"`);

            const relation = (def.relations ?? {})[name];
            if (relation) return await evalRelation(ctx, obj, name, depth);

            const expr = (def.permissions ?? {})[name];
            if (expr) return await evalExpr(ctx, obj, def, expr, depth);

            throw new ApiError(400, `unknown permission "${name}" on type "${obj.type}"`);
        } finally {
            ctx.inProgress.delete(key);
        }
    })();
    ctx.memo.set(key, promise);
    return promise;
}

async function evalRelation(ctx: Ctx, obj: ObjectRef, relation: string, depth: number): Promise<boolean> {
    const { direct, usersets } = await ctx.store.relationLookup(obj, relation, ctx.subject);
    if (direct) return true;
    // Sequential with short-circuit: bounded query spend.
    for (const us of usersets) {
        if (await checkInternal(ctx, { type: us.type, id: us.id }, us.relation!, depth + 1)) return true;
    }
    return false;
}

async function evalExpr(
    ctx: Ctx,
    obj: ObjectRef,
    def: TypeDefinition,
    expr: PermissionExpr,
    depth: number
): Promise<boolean> {
    if ('rel' in expr) {
        return checkInternal(ctx, obj, expr.rel, depth + 1);
    }
    if ('union' in expr) {
        for (const child of expr.union) {
            if (await evalExpr(ctx, obj, def, child, depth)) return true;
        }
        return false;
    }
    if ('intersection' in expr) {
        for (const child of expr.intersection) {
            if (!(await evalExpr(ctx, obj, def, child, depth))) return false;
        }
        return true;
    }
    if ('exclusion' in expr) {
        if (!(await evalExpr(ctx, obj, def, expr.exclusion.base, depth))) return false;
        return !(await evalExpr(ctx, obj, def, expr.exclusion.subtract, depth));
    }
    // arrow
    const { via, permission } = expr.arrow;
    const cacheKey = `${fmtObject(obj)}#${via}`;
    let parents = ctx.parentsCache.get(cacheKey);
    if (!parents) {
        parents = await ctx.store.listParents(obj, via);
        ctx.parentsCache.set(cacheKey, parents);
    }
    for (const parent of parents) {
        if (await checkInternal(ctx, { type: parent.type, id: parent.id }, permission, depth + 1)) return true;
    }
    return false;
}
