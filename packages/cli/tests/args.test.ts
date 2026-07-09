import { describe, expect, test } from 'bun:test';
import { parseArgs, flagStr, flagBool } from '../src/args';
import { normalizeUpdates, chunk, planSummary } from '../src/tuples';

describe('parseArgs', () => {
    test('positionals + valued flags + boolean flags', () => {
        const { positionals, flags } = parseArgs(['import', 'file.json', '--endpoint', 'https://x', '--dry-run']);
        expect(positionals).toEqual(['import', 'file.json']);
        expect(flags.endpoint).toBe('https://x');
        expect(flags['dry-run']).toBe(true);
    });

    test('a flag followed by another flag is boolean', () => {
        const { flags } = parseArgs(['--dry-run', '--token', 'agk_1']);
        expect(flags['dry-run']).toBe(true);
        expect(flags.token).toBe('agk_1');
    });

    test('flagStr / flagBool helpers', () => {
        const { flags } = parseArgs(['-h', '--out', 'types.ts']);
        expect(flagBool(flags, 'help', 'h')).toBe(true);
        expect(flagStr(flags, 'out')).toBe('types.ts');
        expect(flagStr(flags, 'missing')).toBeUndefined();
    });
});

describe('normalizeUpdates', () => {
    const valid = [{ op: 'touch', object: 'doc:1', relation: 'owner', subject: 'user:u1' }];

    test('accepts a bare array', () => {
        expect(normalizeUpdates(valid)).toHaveLength(1);
    });

    test('accepts { updates: [...] }', () => {
        expect(normalizeUpdates({ updates: valid })).toHaveLength(1);
    });

    test('rejects bad op / missing fields / non-array', () => {
        expect(() => normalizeUpdates({})).toThrow();
        expect(() => normalizeUpdates([{ op: 'nope', object: 'd:1', relation: 'r', subject: 's:1' }])).toThrow();
        expect(() => normalizeUpdates([{ op: 'touch', object: '', relation: 'r', subject: 's:1' }])).toThrow();
    });
});

describe('chunk / planSummary', () => {
    test('chunks at the boundary', () => {
        const items = Array.from({ length: 250 }, (_, i) => i);
        expect(chunk(items, 100).map((c) => c.length)).toEqual([100, 100, 50]);
    });

    test('summarizes per-op counts and chunk count', () => {
        const updates = [
            { op: 'touch' as const, object: 'd:1', relation: 'r', subject: 'u:1' },
            { op: 'touch' as const, object: 'd:2', relation: 'r', subject: 'u:1' },
            { op: 'delete' as const, object: 'd:3', relation: 'r', subject: 'u:1' },
        ];
        const p = planSummary(updates);
        expect(p.total).toBe(3);
        expect(p.chunks).toBe(1);
        expect(p.byOp).toEqual({ touch: 2, delete: 1 });
    });
});
