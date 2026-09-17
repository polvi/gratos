import { afterEach, describe, expect, test } from 'bun:test';
import { lastUsed, parseLastUsed, rememberLastUsed } from '../src/last-used';
import { runCeremony } from '../src/ceremony';

const g = globalThis as any;

function memoryStorage() {
    const m = new Map<string, string>();
    return {
        getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
        setItem: (k: string, v: string) => void m.set(k, String(v)),
        removeItem: (k: string) => void m.delete(k),
    };
}

afterEach(() => {
    delete g.document;
    delete g.localStorage;
    delete g.__fetch;
});

describe('parseLastUsed', () => {
    test('accepts every action × method and nothing else', () => {
        expect(parseLastUsed('login.webauthn')).toEqual({ action: 'login', method: 'webauthn' });
        expect(parseLastUsed('register.key')).toEqual({ action: 'register', method: 'key' });
        expect(parseLastUsed('login.device')).toEqual({ action: 'login', method: 'device' });
        for (const bad of ['', 'login', 'login.password', 'signup.key', 'login.key.x', 42, null, undefined, {}]) {
            expect(parseLastUsed(bad)).toBeNull();
        }
    });
});

describe('lastUsed', () => {
    test('null when nothing is known (no DOM, no storage)', () => {
        expect(lastUsed()).toBeNull();
    });

    test('reads the server cookie, url-decoded, among other cookies', () => {
        g.document = { cookie: 'theme=dark; ag_last_used=login.webauthn; other=1' };
        expect(lastUsed()).toEqual({ action: 'login', method: 'webauthn' });
        g.document = { cookie: 'ag_last_used=register%2Ekey' };
        expect(lastUsed()).toEqual({ action: 'register', method: 'key' });
    });

    test('ignores a look-alike cookie name and a garbage value', () => {
        g.document = { cookie: 'xag_last_used=login.webauthn' };
        expect(lastUsed()).toBeNull();
        g.document = { cookie: 'ag_last_used=login.password' };
        expect(lastUsed()).toBeNull();
    });

    test('falls back to the localStorage mirror; the cookie wins when both exist', () => {
        g.localStorage = memoryStorage();
        expect(rememberLastUsed('register.webauthn')).toEqual({ action: 'register', method: 'webauthn' });
        expect(lastUsed()).toEqual({ action: 'register', method: 'webauthn' });
        g.document = { cookie: 'ag_last_used=login.device' };
        expect(lastUsed()).toEqual({ action: 'login', method: 'device' });
    });

    test('rememberLastUsed takes a verify response object too and drops garbage', () => {
        g.localStorage = memoryStorage();
        expect(rememberLastUsed({ verified: true, last_used: 'login.key' })).toEqual({ action: 'login', method: 'key' });
        expect(rememberLastUsed('nope')).toBeNull();
        expect(lastUsed()).toEqual({ action: 'login', method: 'key' });
    });

    test('survives a throwing storage', () => {
        g.localStorage = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } };
        expect(rememberLastUsed('login.key')).toEqual({ action: 'login', method: 'key' });
        expect(lastUsed()).toBeNull();
    });
});

describe('runCeremony', () => {
    test('mirrors last_used from a successful verify into storage', async () => {
        g.localStorage = memoryStorage();
        const realFetch = globalThis.fetch;
        globalThis.fetch = (async (url: any, init?: RequestInit) => {
            if (String(url).endsWith('/options')) {
                return new Response(JSON.stringify({ challenge: 'c', context: 'ctx', tenant: 't' }), { status: 200 });
            }
            return new Response(JSON.stringify({ verified: true, user: { id: 'u' }, last_used: 'login.key' }), { status: 200 });
        }) as any;
        try {
            const r = await runCeremony('https://x', 'login', async () => ({ publicKey: new Uint8Array(1), signature: new Uint8Array(1) }));
            expect(r.ok).toBe(true);
            expect(lastUsed()).toEqual({ action: 'login', method: 'key' });
        } finally {
            globalThis.fetch = realFetch;
        }
    });
});
