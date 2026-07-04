import { describe, expect, test } from 'bun:test';
import { checkPermission, newBudget } from '../src/check';
import { ApiError, ObjectRef, SubjectRef, parseObjectRef, parseSubjectRef } from '../src/model';
import { validateSchema, SchemaDocument } from '../src/schema';
import { Budget, TupleStore, MAX_USERSETS_PER_RELATION, RelationLookup } from '../src/tuples';
import { EXAMPLE_SCHEMA } from './schema.test';

type Tuple = { object: ObjectRef; relation: string; subject: SubjectRef };

/** In-memory TupleStore with the same budget/fan-out semantics as D1TupleStore. */
class MemTupleStore implements TupleStore {
    tuples: Tuple[] = [];

    constructor(
        private budget: Budget,
        tuples: string[] = []
    ) {
        // "document:readme#viewer@user:bob" / "...@group:eng#member"
        for (const t of tuples) {
            const [objRel, subject] = t.split('@');
            const hash = objRel.indexOf('#');
            this.tuples.push({
                object: parseObjectRef(objRel.slice(0, hash)),
                relation: objRel.slice(hash + 1),
                subject: parseSubjectRef(subject),
            });
        }
    }

    private spend() {
        if (++this.budget.queries > this.budget.maxQueries) {
            throw new ApiError(422, 'check budget exceeded');
        }
    }

    async relationLookup(obj: ObjectRef, relation: string, subject: SubjectRef): Promise<RelationLookup> {
        this.spend();
        const rows = this.tuples.filter(
            (t) => t.object.type === obj.type && t.object.id === obj.id && t.relation === relation
        );
        const direct = rows.some(
            (t) =>
                t.subject.type === subject.type &&
                t.subject.id === subject.id &&
                (t.subject.relation ?? '') === (subject.relation ?? '')
        );
        const usersets = rows.filter((t) => t.subject.relation).map((t) => t.subject);
        if (usersets.length > MAX_USERSETS_PER_RELATION) {
            throw new ApiError(422, 'relation fan-out exceeded');
        }
        return { direct, usersets };
    }

    async listParents(obj: ObjectRef, via: string): Promise<SubjectRef[]> {
        this.spend();
        return this.tuples
            .filter(
                (t) => t.object.type === obj.type && t.object.id === obj.id && t.relation === via && !t.subject.relation
            )
            .map((t) => ({ type: t.subject.type, id: t.subject.id }));
    }
}

const schemaOf = (input: unknown): SchemaDocument => {
    const result = validateSchema(input);
    if (!result.ok) throw new Error(`invalid test schema: ${result.errors.join('; ')}`);
    return result.doc;
};

const SCHEMA = schemaOf(EXAMPLE_SCHEMA);

const TUPLES = [
    'folder:root#owner@user:alice',
    'folder:specs#parent@folder:root',
    'folder:root#viewer@group:eng#member',
    'document:readme#parent@folder:specs',
    'document:readme#viewer@user:bob',
    'group:eng#member@user:carol',
    'group:eng#member@group:contractors#member',
    'group:contractors#member@user:dave',
];

async function check(object: string, permission: string, subject: string, tuples = TUPLES, schema = SCHEMA) {
    const budget = newBudget();
    const store = new MemTupleStore(budget, tuples);
    return checkPermission(store, schema, budget, parseObjectRef(object), permission, parseSubjectRef(subject));
}

describe('checkPermission', () => {
    test('direct viewer hit (1 query)', async () => {
        const r = await check('document:readme', 'view', 'user:bob');
        expect(r.allowed).toBe(true);
        expect(r.queries).toBe(1);
    });

    test('owner via computed userset + arrow inheritance (7 queries)', async () => {
        const r = await check('document:readme', 'view', 'user:alice');
        expect(r.allowed).toBe(true);
        expect(r.queries).toBe(7);
    });

    test('group member via folder viewer', async () => {
        const r = await check('document:readme', 'view', 'user:carol');
        expect(r.allowed).toBe(true);
    });

    test('nested group behind folder inheritance (memo + parentsCache, 12 queries)', async () => {
        const r = await check('document:readme', 'view', 'user:dave');
        expect(r.allowed).toBe(true);
        expect(r.queries).toBe(12);
    });

    test('denied for a stranger', async () => {
        const r = await check('document:readme', 'view', 'user:mallory');
        expect(r.allowed).toBe(false);
    });

    test('edit not granted to viewers', async () => {
        expect((await check('document:readme', 'edit', 'user:bob')).allowed).toBe(false);
        expect((await check('document:readme', 'edit', 'user:alice')).allowed).toBe(true);
    });

    test('built-in tenant ownership gate (1 query)', async () => {
        // The on-behalf owner gate runs exactly this check in the root space.
        const tuples = ['gratos_tenant:hippo.love#owner@user:alice'];
        const r = await check('gratos_tenant:hippo.love', 'manage', 'user:alice', tuples);
        expect(r.allowed).toBe(true);
        expect(r.queries).toBe(1);
        expect((await check('gratos_tenant:hippo.love', 'manage', 'user:bob', tuples)).allowed).toBe(false);
    });

    test('cyclic group data terminates (2 queries, denied)', async () => {
        const tuples = ['group:a#member@group:b#member', 'group:b#member@group:a#member'];
        const r = await check('group:a', 'member', 'user:x', tuples);
        expect(r.allowed).toBe(false);
        expect(r.queries).toBe(2);
    });

    test('cyclic folder parents terminate', async () => {
        const tuples = ['folder:a#parent@folder:b', 'folder:b#parent@folder:a'];
        const r = await check('folder:a', 'view', 'user:x', tuples);
        expect(r.allowed).toBe(false);
    });

    test('intersection requires all branches', async () => {
        const schema = schemaOf({
            definitions: {
                doc: {
                    relations: {
                        viewer: { subjects: [{ type: 'user' }] },
                        approved: { subjects: [{ type: 'user' }] },
                    },
                    permissions: {
                        read: { intersection: [{ rel: 'viewer' }, { rel: 'approved' }] },
                    },
                },
            },
        });
        const both = ['doc:x#viewer@user:a', 'doc:x#approved@user:a'];
        expect((await check('doc:x', 'read', 'user:a', both, schema)).allowed).toBe(true);
        expect((await check('doc:x', 'read', 'user:a', both.slice(0, 1), schema)).allowed).toBe(false);
    });

    test('exclusion subtracts', async () => {
        const schema = schemaOf({
            definitions: {
                doc: {
                    relations: {
                        viewer: { subjects: [{ type: 'user' }] },
                        banned: { subjects: [{ type: 'user' }] },
                    },
                    permissions: {
                        read: { exclusion: { base: { rel: 'viewer' }, subtract: { rel: 'banned' } } },
                    },
                },
            },
        });
        const tuples = ['doc:x#viewer@user:a', 'doc:x#viewer@user:b', 'doc:x#banned@user:b'];
        expect((await check('doc:x', 'read', 'user:a', tuples, schema)).allowed).toBe(true);
        expect((await check('doc:x', 'read', 'user:b', tuples, schema)).allowed).toBe(false);
    });

    test('budget exceeded throws 422', async () => {
        // Wide fan-out: 100 group usersets on one relation = 101 lookups > 100 budget.
        const tuples: string[] = [];
        for (let i = 0; i < 100; i++) {
            tuples.push(`document:x#viewer@group:g${i}#member`);
        }
        await expect(check('document:x', 'view', 'user:x', tuples)).rejects.toThrow('check budget exceeded');
    });

    test('depth exceeded throws 422', async () => {
        const tuples: string[] = [];
        for (let i = 0; i < 40; i++) tuples.push(`folder:f${i}#parent@folder:f${i + 1}`);
        await expect(check('folder:f0', 'view', 'user:x', tuples)).rejects.toThrow('check depth exceeded');
    });

    test('unknown type / permission throw 400', async () => {
        await expect(check('ghost:x', 'view', 'user:a')).rejects.toThrow('unknown object type');
        await expect(check('document:readme', 'ghost', 'user:a')).rejects.toThrow('unknown permission');
    });
});
