import { describe, expect, test } from 'bun:test';
import { buildLlmsTxt, fmtExpr, LlmsContext } from '../src/llmstxt';
import { validateSchema, SchemaDocument } from '../src/schema';
import { EXAMPLE_SCHEMA } from './schema.test';

const docOf = (input: unknown): SchemaDocument => {
    const result = validateSchema(input);
    if (!result.ok) throw new Error(result.errors.join('; '));
    return result.doc;
};

const ctx = (over: Partial<LlmsContext>): LlmsContext => ({
    tenant: 'hippo.love',
    kind: 'domain',
    endpoint: 'https://authgravity.hippo.love',
    mode: 'managed',
    stored: null,
    ...over,
});

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

describe('buildLlmsTxt', () => {
    const stored = { doc: docOf(EXAMPLE_SCHEMA), version: 3, updatedAt: 0 };

    test('domain host: unified auth + live authz, endpoint pre-filled', () => {
        const txt = buildLlmsTxt(ctx({ stored }));
        // one doc now carries auth AND authz
        expect(txt).toContain('# AuthGravity — hippo.love');
        expect(txt).toContain('## Auth (passkeys)');
        expect(txt).toContain('PUBLIC_AUTH_ENDPOINT=https://authgravity.hippo.love');
        expect(txt).toContain('## Account keys');
        // live schema
        expect(txt).toContain('Schema version 3');
        expect(txt).toContain('#### document');
        expect(txt).toContain('allowed subjects: user, group#member');
        expect(txt).toContain('`view` = viewer | edit | parent->view');
        expect(txt).toContain('owner-managed');
        expect(txt).toMatch(/"object": "(group|folder|document):example-id"/);
        expect(txt).toContain('Schema JSON (current)');
        // a live domain doesn't need the "go to production" claim flow
        expect(txt).not.toContain('Go to production');
    });

    test('open sandbox: writes are open, reached via the listen proxy', () => {
        const txt = buildLlmsTxt(ctx({ tenant: 'sandbox.authgravity.org/abc', kind: 'sandbox', endpoint: 'https://sandbox.authgravity.org/abc', mode: 'open-sandbox', stored }));
        expect(txt).toContain('# AuthGravity — sandbox');
        expect(txt).toContain('anonymous sandbox');
        expect(txt).toContain('npx @authgravity/cli listen');
        expect(txt).not.toContain('owner-managed');
    });

    test('domain with no schema yet', () => {
        const txt = buildLlmsTxt(ctx({ stored: null }));
        expect(txt).toContain('No schema is defined yet');
        expect(txt).not.toContain('Schema JSON (current)');
    });

    test('schema document format is documented and its example passes the validator', () => {
        // Rendered with and without a live schema — the format section is always there.
        for (const txt of [buildLlmsTxt(ctx({ stored: null })), buildLlmsTxt(ctx({ stored }))]) {
            expect(txt).toContain('### Schema document format');
            const block = txt.match(/### Schema document format[\s\S]*?```json\n([\s\S]*?)\n```/);
            expect(block).not.toBeNull();
            const result = validateSchema(JSON.parse(block![1]));
            expect(result.ok).toBe(true);
            // every construct an agent might author appears in the example
            for (const construct of ['"union"', '"exclusion"', '"arrow"', '"relation": "member"']) {
                expect(block![1]).toContain(construct);
            }
        }
        // the root overview doc doesn't carry the tenant format section
        const root = buildLlmsTxt(ctx({ tenant: 'authgravity.org', kind: 'root', endpoint: null, stored: null }));
        expect(root).not.toContain('### Schema document format');
    });

    test('root: onboarding framing, no live schema dump', () => {
        const txt = buildLlmsTxt(ctx({ tenant: 'authgravity.org', kind: 'root', endpoint: null, stored: null }));
        expect(txt).toContain('# AuthGravity');
        expect(txt).toContain('Start in 60 seconds');
        expect(txt).toContain('Go to production');
    });
});
