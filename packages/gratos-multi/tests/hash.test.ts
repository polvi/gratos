import { describe, expect, test } from 'bun:test';
import { sha256Hex } from '../src/hash';

describe('sha256Hex', () => {
    test('matches the known SHA-256 vector for the empty string', async () => {
        expect(await sha256Hex('')).toBe(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        );
    });

    test('is stable and 64 lowercase hex chars', async () => {
        const a = await sha256Hex('203.0.113.7');
        const b = await sha256Hex('203.0.113.7');
        expect(a).toBe(b);
        expect(a).toMatch(/^[0-9a-f]{64}$/);
    });

    test('different IPs hash differently, and the raw IP never appears', async () => {
        const ip = '198.51.100.42';
        const h = await sha256Hex(ip);
        expect(h).not.toContain(ip);
        expect(h).not.toBe(await sha256Hex('198.51.100.43'));
    });
});
