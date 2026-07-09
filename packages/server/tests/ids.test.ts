import { describe, expect, test } from 'bun:test';
import {
    escapeObjectId,
    unescapeObjectId,
    objectRef,
    parseObjectRef,
    MAX_OBJECT_ID_LENGTH,
} from '../src/ids';

// The server's ID_RE (packages/gratos-authz/src/model.ts). Escaped output MUST
// be a subset of this alphabet so the server needs no change.
const ID_RE = /^[a-zA-Z0-9_@.\/=+-]{1,128}$/;

describe('escapeObjectId', () => {
    const samples = [
        'plain',
        'oats-42',
        '2026-07-08T12:00:00Z', // ISO timestamp — contains ':'
        'urn:isbn:0451450523', // URN — multiple ':'
        'a#b', // '#'
        'a=b', // the sentinel itself
        'path/like/id',
        'with space',
        'emoji 🦛 and é', // multi-byte UTF-8
        'user@example.com',
    ];

    test('escaped form stays within ID_RE', () => {
        for (const s of samples) {
            expect(escapeObjectId(s)).toMatch(ID_RE);
        }
    });

    test('round-trips losslessly', () => {
        for (const s of samples) {
            expect(unescapeObjectId(escapeObjectId(s))).toBe(s);
        }
    });

    test('never emits the forbidden delimiters', () => {
        for (const s of samples) {
            const e = escapeObjectId(s);
            expect(e.includes(':')).toBe(false);
            expect(e.includes('#')).toBe(false);
        }
    });

    test('escapes : # = to =HH', () => {
        expect(escapeObjectId('a:b')).toBe('a=3Ab');
        expect(escapeObjectId('a#b')).toBe('a=23b');
        expect(escapeObjectId('a=b')).toBe('a=3Db');
    });

    test('throws (does not truncate) when escaped form exceeds the cap', () => {
        const longSafe = 'a'.repeat(MAX_OBJECT_ID_LENGTH);
        expect(escapeObjectId(longSafe).length).toBe(MAX_OBJECT_ID_LENGTH);
        const overflowByEscaping = ':'.repeat(50); // each ':' → 3 chars = 150
        expect(() => escapeObjectId(overflowByEscaping)).toThrow(/too long/);
    });

    test('unescape rejects malformed sequences', () => {
        expect(() => unescapeObjectId('a=ZZ')).toThrow();
        expect(() => unescapeObjectId('a=3')).toThrow();
    });
});

describe('objectRef / parseObjectRef', () => {
    test('builds and parses escaping only the id segment', () => {
        const ref = objectRef('recipe', '2026-07-08T12:00:00Z');
        expect(ref.startsWith('recipe:')).toBe(true);
        expect(ref.includes('T12=3A00')).toBe(true); // ':' escaped inside id
        const parsed = parseObjectRef(ref);
        expect(parsed.type).toBe('recipe');
        expect(parsed.id).toBe('2026-07-08T12:00:00Z');
    });
});
