import { describe, expect, test } from 'bun:test';
import { generateTokenSecret, hashToken, isServiceToken, TOKEN_PREFIX } from '../src/tokens';

describe('service tokens', () => {
    test('secrets have the agk_ prefix, are url-safe, and are unique', () => {
        const a = generateTokenSecret();
        const b = generateTokenSecret();
        expect(a).toMatch(/^agk_[A-Za-z0-9_-]{43}$/);
        expect(a).not.toBe(b);
        expect(isServiceToken(a)).toBe(true);
    });

    test('session ids are not mistaken for tokens', () => {
        expect(isServiceToken(crypto.randomUUID())).toBe(false);
        expect(isServiceToken('')).toBe(false);
    });

    test('hashing is deterministic and one-way shaped', async () => {
        const secret = TOKEN_PREFIX + 'x'.repeat(43);
        const h1 = await hashToken(secret);
        const h2 = await hashToken(secret);
        expect(h1).toBe(h2);
        expect(h1).toMatch(/^[0-9a-f]{64}$/);
        expect(h1).not.toContain('x'.repeat(10));
        expect(await hashToken(secret + 'y')).not.toBe(h1);
    });
});
