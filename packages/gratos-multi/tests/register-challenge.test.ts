import { describe, expect, test } from 'bun:test';
import { parseRegChallenge, sanitizeLabel, inBackground } from '../src/auth';

describe('sanitizeLabel', () => {
    test('trims, caps at 64, and drops empties / non-strings', () => {
        expect(sanitizeLabel('  MacBook  ')).toBe('MacBook');
        expect(sanitizeLabel('x'.repeat(100))).toHaveLength(64);
        expect(sanitizeLabel('   ')).toBeNull();
        expect(sanitizeLabel(undefined)).toBeNull();
        expect(sanitizeLabel(42)).toBeNull();
    });
});

describe('parseRegChallenge', () => {
    test('new JSON shape carries userId and optional label', () => {
        expect(parseRegChallenge('{"u":"u1","l":"Phone"}')).toEqual({ userId: 'u1', label: 'Phone' });
        expect(parseRegChallenge('{"u":"u1"}')).toEqual({ userId: 'u1', label: null });
        expect(parseRegChallenge('{"l":"Phone"}')).toBeNull();
        expect(parseRegChallenge('{bad')).toBeNull();
    });

    test('pre-label bare userId values still parse (in-flight ceremonies across a deploy)', () => {
        expect(parseRegChallenge('u1')).toEqual({ userId: 'u1', label: null });
        expect(parseRegChallenge(null)).toBeNull();
        expect(parseRegChallenge('')).toBeNull();
    });
});

describe('inBackground', () => {
    test('a context whose executionCtx getter throws still runs the work inline', async () => {
        const c = {
            get executionCtx() {
                throw new Error('This context has no ExecutionContext');
            },
        };
        let ran = false;
        await inBackground(c, async () => {
            ran = true;
        });
        expect(ran).toBe(true);
    });

    test('uses waitUntil when present and swallows failures either way', async () => {
        const waited: Promise<unknown>[] = [];
        const c = { executionCtx: { waitUntil: (p: Promise<unknown>) => waited.push(p) } };
        await inBackground(c, async () => {
            throw new Error('db down');
        });
        expect(waited).toHaveLength(1);
        await expect(waited[0]).resolves.toBeUndefined();
        await expect(
            inBackground({}, async () => {
                throw new Error('db down');
            })
        ).resolves.toBeUndefined();
    });
});

describe('parseRegChallenge amr', () => {
    test('carries the adding session amr so verify can cap the new session', () => {
        expect(parseRegChallenge('{"u":"u1","a":"otp"}')).toEqual({ userId: 'u1', label: null, amr: 'otp' });
        expect(parseRegChallenge('{"u":"u1","a":"bogus"}')).toEqual({ userId: 'u1', label: null });
    });
});
