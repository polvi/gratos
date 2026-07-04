import { describe, expect, test } from 'bun:test';
import { validateUpdate, RelUpdate } from '../src/tuples';
import { parseObjectRef, parseSubjectRef } from '../src/model';
import { validateSchema, SchemaDocument } from '../src/schema';
import { EXAMPLE_SCHEMA } from './schema.test';

const schemaOf = (input: unknown): SchemaDocument => {
    const result = validateSchema(input);
    if (!result.ok) throw new Error(result.errors.join('; '));
    return result.doc;
};

const SCHEMA = schemaOf(EXAMPLE_SCHEMA);

const update = (op: RelUpdate['op'], object: string, relation: string, subject: string): RelUpdate => ({
    op,
    object: parseObjectRef(object),
    relation,
    subject: parseSubjectRef(subject),
});

describe('validateUpdate', () => {
    test('allows schema-valid writes', () => {
        expect(validateUpdate(SCHEMA, update('touch', 'document:readme', 'viewer', 'user:abc'))).toBeNull();
        expect(validateUpdate(SCHEMA, update('delete', 'folder:root', 'viewer', 'group:eng#member'))).toBeNull();
    });

    test('rejects gratos_tenant as object for all ops (control plane only)', () => {
        for (const op of ['touch', 'create', 'delete'] as const) {
            const err = validateUpdate(SCHEMA, update(op, 'gratos_tenant:hippo.love', 'owner', 'user:abc'));
            expect(err).toContain('control plane');
        }
        // with no tenant schema at all, still rejected
        expect(validateUpdate(null, update('touch', 'gratos_tenant:x', 'owner', 'user:abc'))).toContain(
            'control plane'
        );
    });

    test('rejects any gratos_* object or subject (no admin exception remains)', () => {
        expect(validateUpdate(SCHEMA, update('touch', 'gratos_authz:root', 'admin', 'user:abc'))).toContain(
            'reserved'
        );
        expect(validateUpdate(SCHEMA, update('touch', 'document:readme', 'viewer', 'gratos_tenant:x'))).toContain(
            'may not be a subject'
        );
        expect(validateUpdate(SCHEMA, update('touch', 'document:readme', 'viewer', 'gratos_authz:root'))).toContain(
            'may not be a subject'
        );
    });

    test('rejects unknown types, non-relations, and disallowed subjects', () => {
        expect(validateUpdate(SCHEMA, update('touch', 'ghost:x', 'viewer', 'user:abc'))).toContain(
            'unknown object type'
        );
        expect(validateUpdate(SCHEMA, update('touch', 'document:readme', 'view', 'user:abc'))).toContain(
            'not a relation'
        );
        expect(validateUpdate(SCHEMA, update('touch', 'folder:root', 'owner', 'folder:x'))).toContain(
            'not allowed'
        );
    });
});
