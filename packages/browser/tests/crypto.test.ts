import { describe, expect, test } from 'bun:test';
import {
    encodeCompact,
    decodeCompact,
    encodeWords,
    decodeWords,
    derivePrivateKey,
    publicKeyFor,
    signPayload,
    hex,
    fromHex,
} from '../src/crypto';

// Same golden vectors the server enforces (gratos-multi/tests/keyspec.test.ts).
// Any drift in the port fails here.
const ENTROPY = fromHex('000102030405060708090a0b0c0d0e0f');
const VECTORS = {
    compact: 'agak1_aaaqeayeaudaocajbifqydiob4xzc4',
    words: 'abandon amount liar amount expire adjust cage candy arch gather drum buyer',
    pubHippo:
        '0453623a50eecf820924c92a624edc72659d9ac33d38a86c9a09bfe3c8161b42f8dce16ae80d56886eb41bf263fcb86c3cc184eca1b43e0c5d60eeb9e8b2754d0b',
    pubOther:
        '0413e7c1f181565c7350dd000773bc02a5c1bc775364793a52fb171494fdff04b6c638aaee0808227fec8771ca934d5ead9f61608affa1373da1afd04824e9d8b1',
};

describe('account-key spec vectors (browser port)', () => {
    test('compact rendering round-trips and matches the vector', () => {
        expect(encodeCompact(ENTROPY)).toBe(VECTORS.compact);
        expect(hex(decodeCompact(VECTORS.compact))).toBe(hex(ENTROPY));
        expect(hex(decodeCompact('  ' + VECTORS.compact.toUpperCase() + ' '))).toBe(hex(ENTROPY));
    });

    test('compact checksum catches typos', () => {
        const corrupted = VECTORS.compact.slice(0, 10) + 'x' + VECTORS.compact.slice(11);
        expect(() => decodeCompact(corrupted)).toThrow();
    });

    test('words rendering round-trips and matches the BIP39 vector', () => {
        expect(encodeWords(ENTROPY).join(' ')).toBe(VECTORS.words);
        expect(hex(decodeWords(VECTORS.words.split(' ')))).toBe(hex(ENTROPY));
    });

    test('words checksum catches a swapped word', () => {
        const words = VECTORS.words.split(' ');
        [words[0], words[1]] = [words[1], words[0]];
        expect(() => decodeWords(words)).toThrow();
    });

    test('derivation is tenant-salted and matches vectors', () => {
        expect(hex(publicKeyFor(derivePrivateKey(ENTROPY, 'hippo.love')))).toBe(VECTORS.pubHippo);
        expect(hex(publicKeyFor(derivePrivateKey(ENTROPY, 'other.com')))).toBe(VECTORS.pubOther);
    });

    test('signatures are 64-byte r||s and verify under WebCrypto', async () => {
        const priv = derivePrivateKey(ENTROPY, 'hippo.love');
        const payload = 'authgravity-key-login-v1\ntest-challenge_123456\nhippo.love';
        const sig = signPayload(priv, payload);
        expect(sig.length).toBe(64);
        const pub = publicKeyFor(priv);
        expect(pub.length).toBe(65);
        expect(pub[0]).toBe(0x04);
        const key = await crypto.subtle.importKey(
            'raw',
            pub,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['verify']
        );
        const ok = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            sig,
            new TextEncoder().encode(payload)
        );
        expect(ok).toBe(true);
    });
});
