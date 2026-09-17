import { afterEach, describe, expect, test } from 'bun:test';
import { listCredentials, removeCredential } from '../src/credentials';

const realFetch = globalThis.fetch;
afterEach(() => {
    globalThis.fetch = realFetch;
});

function mock(handler: (url: string, init?: RequestInit) => Response) {
    globalThis.fetch = (async (input: any, init?: RequestInit) => handler(String(input), init)) as any;
}

describe('listCredentials', () => {
    test('returns the list with credentials included', async () => {
        let seen: RequestInit | undefined;
        mock((url, init) => {
            seen = init;
            expect(url).toBe('https://auth.example/v1/credentials');
            return Response.json({ amr: 'webauthn', credentials: [{ id: 'r1', kind: 'webauthn', display: 'iCloud Keychain', current: true }] });
        });
        const out = await listCredentials('https://auth.example');
        expect(seen?.credentials).toBe('include');
        expect(out?.amr).toBe('webauthn');
        expect(out?.credentials[0].current).toBe(true);
    });

    test('401 → null, other failures throw', async () => {
        mock(() => new Response('', { status: 401 }));
        expect(await listCredentials('https://auth.example')).toBeNull();
        mock(() => new Response('', { status: 500 }));
        await expect(listCredentials('https://auth.example')).rejects.toThrow('500');
    });
});

describe('removeCredential', () => {
    test('DELETEs by row id and surfaces server refusals without throwing', async () => {
        mock((url, init) => {
            expect(init?.method).toBe('DELETE');
            expect(url).toBe('https://auth.example/v1/credentials/r%2F1');
            return Response.json({ deleted: true });
        });
        expect(await removeCredential('https://auth.example', 'r/1')).toEqual({ ok: true, status: 200 });

        mock(() => Response.json({ error: 'Cannot remove the last credential' }, { status: 409 }));
        expect(await removeCredential('https://auth.example', 'r1')).toEqual({
            ok: false,
            status: 409,
            error: 'Cannot remove the last credential',
        });
    });
});
