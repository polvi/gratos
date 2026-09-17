import { describe, expect, test } from 'bun:test';
import { parseSessionValue, mintSession } from '../src/sessions';

describe('parseSessionValue', () => {
    test('JSON sessions carry amr and the minting credential', () => {
        expect(parseSessionValue('{"u":"u1","amr":"webauthn","c":"row1"}')).toEqual({
            userId: 'u1',
            amr: 'webauthn',
            credentialId: 'row1',
        });
        expect(parseSessionValue('{"u":"u1","amr":"key"}')).toEqual({ userId: 'u1', amr: 'key' });
        expect(parseSessionValue('{"u":"u1","amr":"device","c":""}')).toEqual({ userId: 'u1', amr: 'device' });
    });

    test('legacy bare userId parses as a webauthn session with no credential', () => {
        expect(parseSessionValue('u1')).toEqual({ userId: 'u1', amr: 'webauthn' });
        expect(parseSessionValue(null)).toBeNull();
        expect(parseSessionValue('{"amr":"key"}')).toBeNull();
    });

    test('mintSession writes the credential only when given', async () => {
        const store = new Map<string, string>();
        const kv = { put: async (k: string, v: string) => void store.set(k, v) } as unknown as KVNamespace;
        const a = await mintSession(kv, 't', 'u1', 'webauthn', 'row1');
        const b = await mintSession(kv, 't', 'u1', 'key');
        expect(JSON.parse(store.get(`session:t:${a}`)!)).toEqual({ u: 'u1', amr: 'webauthn', c: 'row1' });
        expect(JSON.parse(store.get(`session:t:${b}`)!)).toEqual({ u: 'u1', amr: 'key' });
    });
});
