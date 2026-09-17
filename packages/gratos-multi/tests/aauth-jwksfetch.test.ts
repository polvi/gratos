// Seam §8 JWKS document shapes: verifiers must accept top-level keys, nested
// jwks.keys (tokenpony's resource doc, incl. its self-referential jwks_uri),
// and jwks_uri-only docs (followed exactly once). Plus serve-stale-on-error.

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';

import { fetchIssuerJwks } from '../src/aauth/jwksfetch';

function memoryKV(): KVNamespace {
    const store = new Map<string, string>();
    return {
        get: async (k: string, type?: string) => {
            const v = store.get(k) ?? null;
            return v !== null && type === 'json' ? JSON.parse(v) : v;
        },
        put: async (k: string, v: string) => void store.set(k, v),
        delete: async (k: string) => void store.delete(k),
    } as unknown as KVNamespace;
}

const KEY = { kty: 'OKP', crv: 'Ed25519', x: 'xxxx', kid: 'k1' };
let docs: Record<string, unknown> = {};
let fetchCount = 0;
const realFetch = globalThis.fetch;

beforeAll(() => {
    globalThis.fetch = (async (input: any) => {
        const url = String(input instanceof Request ? input.url : input);
        fetchCount++;
        const doc = docs[url];
        if (!doc) return new Response('nope', { status: 404 });
        return new Response(JSON.stringify(doc), { headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;
});

afterAll(() => {
    globalThis.fetch = realFetch;
});

describe('jwksfetch document shapes', () => {
    test('top-level {"keys":[...]}', async () => {
        docs = { 'https://a.example/.well-known/aauth-agent.json': { keys: [KEY] } };
        const keys = await fetchIssuerJwks(memoryKV(), 'https://a.example', 'aauth-agent.json');
        expect(keys).toEqual([KEY]);
    });

    test('nested {"jwks":{"keys":[...]}} with self-referential jwks_uri (tokenpony shape)', async () => {
        const url = 'https://api.tokenpony.example/.well-known/aauth-resource.json';
        docs = {
            [url]: {
                resource: 'https://api.tokenpony.example',
                jwks: { keys: [KEY] },
                jwks_uri: url, // points back at itself — must not loop
                budget_endpoint: 'https://api.tokenpony.example/grant',
            },
        };
        fetchCount = 0;
        const keys = await fetchIssuerJwks(memoryKV(), 'https://api.tokenpony.example', 'aauth-resource.json');
        expect(keys).toEqual([KEY]);
        expect(fetchCount).toBe(1); // nested shape wins before any follow
    });

    test('jwks_uri-only doc is followed exactly once', async () => {
        docs = {
            'https://b.example/.well-known/aauth-resource.json': { jwks_uri: 'https://b.example/keys.json' },
            'https://b.example/keys.json': { keys: [KEY] },
        };
        const keys = await fetchIssuerJwks(memoryKV(), 'https://b.example', 'aauth-resource.json');
        expect(keys).toEqual([KEY]);
    });

    test('jwks_uri chains do not recurse', async () => {
        docs = {
            'https://c.example/.well-known/aauth-resource.json': { jwks_uri: 'https://c.example/hop1.json' },
            'https://c.example/hop1.json': { jwks_uri: 'https://c.example/hop2.json' },
            'https://c.example/hop2.json': { keys: [KEY] },
        };
        expect(fetchIssuerJwks(memoryKV(), 'https://c.example', 'aauth-resource.json')).rejects.toThrow(
            'could not fetch keys'
        );
    });

    test('serve-stale-on-error: cached keys survive a failing refresh', async () => {
        const kv = memoryKV();
        docs = { 'https://d.example/.well-known/aauth-agent.json': { keys: [KEY] } };
        await fetchIssuerJwks(kv, 'https://d.example', 'aauth-agent.json');
        // Age the cache past freshness, then break the origin.
        const raw = await (kv as any).get(await cacheKeyFor('https://d.example', 'aauth-agent.json'));
        const entry = JSON.parse(raw);
        entry.at = Date.now() - 10 * 60 * 1000;
        await (kv as any).put(await cacheKeyFor('https://d.example', 'aauth-agent.json'), JSON.stringify(entry));
        docs = {};
        const keys = await fetchIssuerJwks(kv, 'https://d.example', 'aauth-agent.json');
        expect(keys).toEqual([KEY]);
    });
});

async function cacheKeyFor(iss: string, dwk: string): Promise<string> {
    const bytes = new TextEncoder().encode(iss + '/' + dwk);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return `aauth_jwks:${Buffer.from(digest).toString('base64url')}`;
}
