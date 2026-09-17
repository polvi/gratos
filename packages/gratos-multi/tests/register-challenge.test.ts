import { describe, expect, test } from 'bun:test';
import { parseRegChallenge, sanitizeLabel } from '../src/auth';

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
