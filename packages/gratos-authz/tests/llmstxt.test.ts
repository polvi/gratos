import { describe, expect, test } from 'bun:test';
import { buildTenantLlmsTxt, fmtExpr } from '../src/llmstxt';
import { validateSchema, SchemaDocument } from '../src/schema';
import { EXAMPLE_SCHEMA } from './schema.test';

const docOf = (input: unknown): SchemaDocument => {
    const result = validateSchema(input);
    if (!result.ok) throw new Error(result.errors.join('; '));
    return result.doc;
};

describe('fmtExpr', () => {
    test('renders all expression kinds compactly', () => {
        expect(fmtExpr({ rel: 'viewer' })).toBe('viewer');
        expect(fmtExpr({ arrow: { via: 'parent', permission: 'view' } })).toBe('parent->view');
        expect(fmtExpr({ union: [{ rel: 'viewer' }, { arrow: { via: 'parent', permission: 'view' } }] })).toBe(
            'viewer | parent->view'
        );
        expect(fmtExpr({ intersection: [{ rel: 'a' }, { rel: 'b' }] })).toBe('a & b');
        expect(fmtExpr({ exclusion: { base: { rel: 'viewer' }, subtract: { rel: 'banned' } } })).toBe(
            'viewer minus banned'
        );
        expect(
            fmtExpr({ exclusion: { base: { union: [{ rel: 'a' }, { rel: 'b' }] }, subtract: { rel: 'c' } } })
        ).toBe('(a | b) minus c');
    });
});

describe('buildTenantLlmsTxt', () => {
    const stored = { doc: docOf(EXAMPLE_SCHEMA), version: 3, updatedAt: 0 };

    test('renders the live schema for a managed tenant', () => {
        const txt = buildTenantLlmsTxt('hippo.love', stored, 'managed');
        expect(txt).toContain('# Authorization for hippo.love');
        expect(txt).toContain('Schema version 3');
        expect(txt).toContain('### document');
        expect(txt).toContain('allowed subjects: user, group#member');
        expect(txt).toContain('`view` = viewer | edit | parent->view');
        expect(txt).toContain('owner-managed');
        expect(txt).toContain('POST <this host>/v1/authz/check'.replace('POST <this host>', 'curl -X POST <this host>'));
        // examples use real names from the schema
        expect(txt).toMatch(/"object": "(group|folder|document):example-id"/);
        expect(txt).toContain('## Schema JSON (current)');
    });

    test('open sandbox mode says writes are open', () => {
        const txt = buildTenantLlmsTxt('sandbox.authgravity.org/abc', stored, 'open-sandbox');
        expect(txt).toContain('anonymous sandbox');
        expect(txt).not.toContain('owner-managed');
    });

    test('no schema yet', () => {
        const txt = buildTenantLlmsTxt('hippo.love', null, 'managed');
        expect(txt).toContain('No schema is defined yet');
        expect(txt).not.toContain('## Schema JSON');
    });
});
