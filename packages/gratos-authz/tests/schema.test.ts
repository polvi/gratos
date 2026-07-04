import { describe, expect, test } from 'bun:test';
import { validateSchema, typeDef, BUILTIN_DEFS } from '../src/schema';
import { parseObjectRef, parseSubjectRef, ApiError } from '../src/model';

export const EXAMPLE_SCHEMA = {
    definitions: {
        group: {
            relations: {
                member: { subjects: [{ type: 'user' }, { type: 'group', relation: 'member' }] },
            },
        },
        folder: {
            relations: {
                owner: { subjects: [{ type: 'user' }] },
                viewer: { subjects: [{ type: 'user' }, { type: 'group', relation: 'member' }] },
                parent: { subjects: [{ type: 'folder' }] },
            },
            permissions: {
                edit: { union: [{ rel: 'owner' }, { arrow: { via: 'parent', permission: 'edit' } }] },
                view: { union: [{ rel: 'viewer' }, { rel: 'edit' }, { arrow: { via: 'parent', permission: 'view' } }] },
            },
        },
        document: {
            relations: {
                owner: { subjects: [{ type: 'user' }] },
                editor: { subjects: [{ type: 'user' }, { type: 'group', relation: 'member' }] },
                viewer: { subjects: [{ type: 'user' }, { type: 'group', relation: 'member' }] },
                parent: { subjects: [{ type: 'folder' }] },
            },
            permissions: {
                edit: { union: [{ rel: 'editor' }, { rel: 'owner' }, { arrow: { via: 'parent', permission: 'edit' } }] },
                view: { union: [{ rel: 'viewer' }, { rel: 'edit' }, { arrow: { via: 'parent', permission: 'view' } }] },
            },
        },
    },
};

const errorsOf = (input: unknown): string[] => {
    const result = validateSchema(input);
    return result.ok ? [] : result.errors;
};

describe('validateSchema', () => {
    test('accepts the example document/folder/group schema', () => {
        expect(validateSchema(EXAMPLE_SCHEMA).ok).toBe(true);
    });

    test('rejects non-objects and unknown top-level keys', () => {
        expect(errorsOf('nope')[0]).toContain('must be a JSON object');
        expect(errorsOf({ definitions: {}, extra: 1 })[0]).toContain('unknown key "extra"');
        expect(errorsOf({})[0]).toContain('"definitions" must be an object');
    });

    test('rejects reserved type names', () => {
        expect(errorsOf({ definitions: { user: {} } })[0]).toContain('reserved');
        expect(errorsOf({ definitions: { gratos_tenant: {} } })[0]).toContain('reserved');
        expect(errorsOf({ definitions: { gratos_anything: {} } })[0]).toContain('reserved');
    });

    test('rejects bad names', () => {
        expect(errorsOf({ definitions: { 'Bad-Name': {} } })[0]).toContain('invalid');
        expect(
            errorsOf({ definitions: { doc: { relations: { 'X': { subjects: [{ type: 'user' }] } } } } })[0]
        ).toContain('invalid');
    });

    test('rejects relation/permission name collisions', () => {
        const errors = errorsOf({
            definitions: {
                doc: {
                    relations: { viewer: { subjects: [{ type: 'user' }] } },
                    permissions: { viewer: { rel: 'viewer' } },
                },
            },
        });
        expect(errors[0]).toContain('both a relation and a permission');
    });

    test('rejects unknown subject types and gratos_tenant as a subject', () => {
        expect(
            errorsOf({ definitions: { doc: { relations: { viewer: { subjects: [{ type: 'ghost' }] } } } } })[0]
        ).toContain('unknown subject type "ghost"');
        expect(
            errorsOf({ definitions: { doc: { relations: { viewer: { subjects: [{ type: 'gratos_tenant' }] } } } } })[0]
        ).toContain('unknown subject type "gratos_tenant"');
    });

    test('rejects subject-set relation that does not exist on the target', () => {
        const errors = errorsOf({
            definitions: {
                group: { relations: { member: { subjects: [{ type: 'user' }] } } },
                doc: { relations: { viewer: { subjects: [{ type: 'group', relation: 'ghost' }] } } },
            },
        });
        expect(errors[0]).toContain('has no relation "ghost"');
    });

    test('rejects {rel} referencing nothing', () => {
        const errors = errorsOf({
            definitions: { doc: { permissions: { view: { rel: 'ghost' } } } },
        });
        expect(errors[0]).toContain('unknown relation or permission "ghost"');
    });

    test('rejects arrows via non-relations and via subject-set relations', () => {
        expect(
            errorsOf({
                definitions: { doc: { permissions: { view: { arrow: { via: 'ghost', permission: 'view' } } } } },
            })[0]
        ).toContain('not a relation');

        const viaSubjectSet = errorsOf({
            definitions: {
                group: { relations: { member: { subjects: [{ type: 'user' }] } } },
                doc: {
                    relations: { parent: { subjects: [{ type: 'group', relation: 'member' }] } },
                    permissions: { view: { arrow: { via: 'parent', permission: 'member' } } },
                },
            },
        });
        expect(viaSubjectSet[0]).toContain('direct-only');
    });

    test('rejects arrows whose target lacks the permission', () => {
        const errors = errorsOf({
            definitions: {
                folder: { relations: { owner: { subjects: [{ type: 'user' }] } } },
                doc: {
                    relations: { parent: { subjects: [{ type: 'folder' }] } },
                    permissions: { view: { arrow: { via: 'parent', permission: 'view' } } },
                },
            },
        });
        expect(errors[0]).toContain('has no relation or permission "view"');
    });

    test('rejects same-type permission cycles', () => {
        const errors = errorsOf({
            definitions: {
                doc: {
                    permissions: {
                        a: { rel: 'b' },
                        b: { rel: 'a' },
                    },
                },
            },
        });
        expect(errors[0]).toContain('cycle');

        const self = errorsOf({ definitions: { doc: { permissions: { a: { rel: 'a' } } } } });
        expect(self[0]).toContain('cycle');
    });

    test('rejects malformed expressions', () => {
        expect(
            errorsOf({ definitions: { doc: { permissions: { view: { rel: 'x', union: [] } } } } })[0]
        ).toContain('exactly one');
        expect(errorsOf({ definitions: { doc: { permissions: { view: { union: [] } } } } })[0]).toContain(
            'non-empty'
        );
        expect(errorsOf({ definitions: { doc: { permissions: { view: { what: 1 } } } } })[0]).toContain(
            'unknown expression key'
        );
    });

    test('collects multiple errors', () => {
        const errors = errorsOf({
            definitions: {
                doc: {
                    relations: { viewer: { subjects: [{ type: 'ghost' }] } },
                    permissions: { view: { rel: 'nope' } },
                },
            },
        });
        expect(errors.length).toBe(2);
    });
});

describe('typeDef', () => {
    test('merges built-ins over any tenant doc', () => {
        expect(typeDef(null, 'user')).toBe(BUILTIN_DEFS.user);
        expect(typeDef(null, 'gratos_tenant')).toBe(BUILTIN_DEFS.gratos_tenant);
        const result = validateSchema(EXAMPLE_SCHEMA);
        if (!result.ok) throw new Error('example schema invalid');
        expect(typeDef(result.doc, 'document')).toBe(result.doc.definitions.document);
        expect(typeDef(result.doc, 'ghost')).toBeNull();
    });
});

describe('ref parsing', () => {
    test('parses object and subject refs', () => {
        expect(parseObjectRef('document:readme')).toEqual({ type: 'document', id: 'readme' });
        expect(parseSubjectRef('user:abc-123')).toEqual({ type: 'user', id: 'abc-123' });
        expect(parseSubjectRef('group:eng#member')).toEqual({ type: 'group', id: 'eng', relation: 'member' });
    });

    test('rejects malformed refs', () => {
        expect(() => parseObjectRef('nocolon')).toThrow(ApiError);
        expect(() => parseObjectRef('Bad:id')).toThrow(ApiError);
        expect(() => parseObjectRef('doc:')).toThrow(ApiError);
        expect(() => parseObjectRef('doc:has:colon')).toThrow(ApiError);
        expect(() => parseSubjectRef('group:eng#Bad!')).toThrow(ApiError);
        // '*' reserved for future wildcards
        expect(() => parseObjectRef('doc:*')).toThrow(ApiError);
    });
});
