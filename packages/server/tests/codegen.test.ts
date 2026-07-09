import { describe, expect, test } from 'bun:test';
import { schemaToTypes } from '../src/codegen';
import type { SchemaDocument } from '../src/schema';

const DOC: SchemaDocument = {
    definitions: {
        document: {
            relations: {
                owner: { subjects: [{ type: 'user' }] },
                viewer: { subjects: [{ type: 'user' }, { type: 'group', relation: 'member' }] },
            },
            permissions: {
                view: { union: [{ rel: 'viewer' }, { rel: 'owner' }] },
                edit: { rel: 'owner' },
            },
        },
        folder: {
            relations: { parent: { subjects: [{ type: 'folder' }] } },
        },
    },
};

describe('schemaToTypes', () => {
    const out = schemaToTypes(DOC, { version: 7, tenant: 'hippo.love', updatedAt: 123 });

    test('stamps version + tenant', () => {
        expect(out).toContain('export const SCHEMA_VERSION = 7;');
        expect(out).toContain('tenant: hippo.love');
        expect(out).toContain('schema version: 7');
    });

    test('emits per-type permission and relation unions', () => {
        expect(out).toContain('document: { permissions: "view" | "edit"; relations: "owner" | "viewer" };');
    });

    test('type with no permissions gets never', () => {
        expect(out).toContain('folder: { permissions: never; relations: "parent" };');
    });

    test('synthesizes the built-in user type', () => {
        expect(out).toContain('user: { permissions: never; relations: never };');
    });

    test('emits helper types', () => {
        expect(out).toContain('export type ObjectType = keyof AuthzSchema;');
        expect(out).toContain("export type PermissionOf<T extends ObjectType> = AuthzSchema[T]['permissions'];");
    });

    test('is deterministic', () => {
        expect(schemaToTypes(DOC, { version: 7, tenant: 'hippo.love', updatedAt: 123 })).toBe(out);
    });
});
