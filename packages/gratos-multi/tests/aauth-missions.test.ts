// Mission proposal validation and the budget attenuation matrix (narrowing
// only), plus scope-subset logic for grants. Pure functions — no D1.

import { describe, test, expect } from 'bun:test';

import { validateProposal, validateBudgets, applyAttenuation } from '../src/aauth/missions';
import { normalizeScope, scopeCovered } from '../src/aauth/grants';
import type { BudgetEntry } from '../src/aauth/jwt';

const PROPOSED: BudgetEntry[] = [
    { resource: 'https://api.tokenpony.dev', amount: '2.00', currency: 'USD', models: ['pony-8b', 'pony-70b'] },
    { resource: 'https://api.search.example', amount: '0.50', currency: 'USD' },
];

describe('proposal validation', () => {
    test('minimal valid proposal', () => {
        const p = validateProposal({ mission: { description: 'Implement RFC v2' } });
        expect(p.description).toBe('Implement RFC v2');
    });

    test('description required', () => {
        expect(() => validateProposal({ mission: {} })).toThrow('description');
        expect(() => validateProposal(null)).toThrow('description');
    });

    test('budgets validated: bad amount / currency / duplicate resource / bad models', () => {
        const mk = (b: object) => () => validateBudgets([b]);
        expect(mk({ resource: 'https://r.example', amount: '-1', currency: 'USD' })).toThrow('amount');
        expect(mk({ resource: 'https://r.example', amount: '0', currency: 'USD' })).toThrow('amount');
        expect(mk({ resource: 'https://r.example', amount: '1.0', currency: 'usd' })).toThrow('currency');
        expect(mk({ resource: 'https://r.example', amount: '1.0', currency: 'XTS' })).toThrow('currency');
        expect(mk({ resource: 'not-a-url', amount: '1.0', currency: 'USD' })).toThrow('https URL');
        expect(mk({ resource: 'https://r.example', amount: '1.0', currency: 'USD', models: [] })).toThrow('models');
        expect(mk({ resource: 'https://r.example', amount: '1.0', currency: 'USD', models: ['a', 'a'] })).toThrow('models');
        expect(() =>
            validateBudgets([
                { resource: 'https://r.example', amount: '1.0', currency: 'USD' },
                { resource: 'https://r.example', amount: '2.0', currency: 'USD' },
            ])
        ).toThrow('one budget entry per resource');
    });

    test('expires_in capped at 30 days', () => {
        expect(() =>
            validateProposal({ mission: { description: 'd', expires_in: 31 * 24 * 3600 } })
        ).toThrow('30 days');
    });
});

describe('budget attenuation (narrowing only)', () => {
    test('unchanged approval grants entries as proposed', () => {
        const granted = applyAttenuation(PROPOSED, undefined, undefined);
        expect(granted).toEqual(PROPOSED);
    });

    test('reduce amount ✓', () => {
        const granted = applyAttenuation(PROPOSED, [{ resource: 'https://api.tokenpony.dev', amount: '1.00' }], undefined);
        expect(granted[0].amount).toBe('1.00');
        expect(granted[1].amount).toBe('0.50');
    });

    test('omit an entry ✓', () => {
        const granted = applyAttenuation(PROPOSED, undefined, ['https://api.search.example']);
        expect(granted).toHaveLength(1);
        expect(granted[0].resource).toBe('https://api.tokenpony.dev');
    });

    test('increase amount ✗', () => {
        expect(() =>
            applyAttenuation(PROPOSED, [{ resource: 'https://api.tokenpony.dev', amount: '3.00' }], undefined)
        ).toThrow('may not exceed');
    });

    test('add an entry ✗', () => {
        expect(() =>
            applyAttenuation(PROPOSED, [{ resource: 'https://new.example', amount: '1.00' }], undefined)
        ).toThrow('may not add');
    });

    test('models narrow ✓, widen ✗', () => {
        const granted = applyAttenuation(PROPOSED, [{ resource: 'https://api.tokenpony.dev', models: ['pony-8b'] }], undefined);
        expect(granted[0].models).toEqual(['pony-8b']);
        expect(() =>
            applyAttenuation(PROPOSED, [{ resource: 'https://api.tokenpony.dev', models: ['pony-8b', 'gpt-x'] }], undefined)
        ).toThrow('subset');
    });

    test('models may be ADDED when the proposal had none (TPX-A)', () => {
        const granted = applyAttenuation(PROPOSED, [{ resource: 'https://api.search.example', models: ['fast-1'] }], undefined);
        expect(granted[1].models).toEqual(['fast-1']);
    });
});

describe('grant scope logic', () => {
    test('normalizeScope dedupes and sorts', () => {
        expect(normalizeScope('b a  b c')).toBe('a b c');
        expect(normalizeScope(undefined)).toBe('');
    });

    test('scopeCovered is subset semantics', () => {
        expect(scopeCovered('a b', 'a b c')).toBe(true);
        expect(scopeCovered('a d', 'a b c')).toBe(false);
        expect(scopeCovered(undefined, 'a')).toBe(true);
        expect(scopeCovered('a', '')).toBe(false);
    });
});
