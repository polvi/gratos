import { describe, expect, test } from 'bun:test';
import { createAccountKeySetup } from '../src/setup';
import type { AccountKey, VerifyResult } from '../src/account-key';

const fakeKey: AccountKey = {
    entropy: new Uint8Array(16),
    compact: 'agak1_test',
    words: 'a b c d e f g h i j k l'.split(' '),
};

function make(overrides = {}) {
    const registered: AccountKey[] = [];
    const setup = createAccountKeySetup({
        endpoint: 'https://x',
        method: 'account-key',
        mint: () => fakeKey,
        pickConfirmIndex: () => 2, // deterministic: word "c"
        register: async (_e, key): Promise<VerifyResult> => {
            registered.push(key);
            return { verified: true, user: { id: 'u1' } };
        },
        ...overrides,
    });
    return { setup, registered };
}

describe('account-key setup state machine', () => {
    test('forced account-key path: intro → show (mints) → confirm → register → done', async () => {
        const { setup, registered } = make();
        await setup.start();
        expect(setup.state).toBe('words_intro');

        setup.acknowledgePaper();
        expect(setup.state).toBe('words_show');
        expect(setup.context.key).toBe(fakeKey);

        setup.toConfirm();
        expect(setup.state).toBe('words_confirm');
        expect(setup.context.confirmIndex).toBe(2);

        const ok = await setup.confirmWord('  C '); // case/space tolerant, matches word[2]='c'
        expect(ok).toBe(true);
        expect(setup.state).toBe('done');
        expect(setup.context.result?.user?.id).toBe('u1');
        expect(registered).toHaveLength(1);
    });

    test('wrong confirmation word does not register and stays put', async () => {
        const { setup, registered } = make();
        await setup.start();
        setup.acknowledgePaper();
        setup.toConfirm();
        const ok = await setup.confirmWord('wrong');
        expect(ok).toBe(false);
        expect(setup.state).toBe('words_confirm');
        expect(registered).toHaveLength(0);
    });

    test('registration failure surfaces as error state', async () => {
        const { setup } = make({
            register: async (): Promise<VerifyResult> => ({ verified: false, error: 'boom' }),
        });
        await setup.start();
        setup.acknowledgePaper();
        setup.toConfirm();
        await setup.confirmWord('c');
        expect(setup.state).toBe('error');
        expect(setup.context.error).toBe('boom');
    });

    test('passkey path nudges a recovery key, which reuses the words flow', async () => {
        const { setup } = make({ method: 'passkey' });
        await setup.start();
        expect(setup.state).toBe('passkey');
        setup.onPasskeyRegistered({ verified: true, user: { id: 'u1' } });
        expect(setup.state).toBe('recovery_nudge');
        setup.createRecoveryKey();
        expect(setup.state).toBe('words_intro');
        expect(setup.context.isRecovery).toBe(true);
    });

    test('subscribe fires on transitions', async () => {
        const { setup } = make();
        const states: string[] = [];
        setup.subscribe((s) => states.push(s));
        await setup.start();
        setup.acknowledgePaper();
        expect(states).toContain('words_intro');
        expect(states).toContain('words_show');
    });
});
