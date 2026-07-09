// Headless account-key setup — a framework-agnostic state machine for the flow
// that makes or breaks an elderly-user deployment. It owns the STATES and
// TRANSITIONS (capability detect → method choice → pen-and-paper priming →
// word grid → confirm-one-word → register, plus the recovery-key nudge for
// passkey users); the app supplies all markup by reading `state`/`context` and
// calling the transition methods. No hosted page, no UI opinions.

import { mintKey, registerAccountKey, type AccountKey, type VerifyResult } from './account-key';
import { suggestedMethod, type AuthMethod } from './capabilities';

export type SetupState =
    | 'detecting' // running capability detection
    | 'choose' // pick passkey vs account key
    | 'passkey' // app performs the passkey ceremony
    | 'recovery_nudge' // passkey done — offer a recovery key
    | 'words_intro' // "grab a pen and paper" priming
    | 'words_show' // show the 12-word grid + compact + print sheet
    | 'words_confirm' // confirm one word to prove the paper is right
    | 'registering' // submitting the account key
    | 'done'
    | 'error';

export interface SetupContext {
    suggested?: AuthMethod;
    /** Minted when entering words_show; render context.key.words / .compact. */
    key?: AccountKey;
    /** Index (0–11) of the word to confirm in words_confirm. */
    confirmIndex?: number;
    /** True when the words flow is creating a recovery key for a passkey user. */
    isRecovery: boolean;
    result?: VerifyResult;
    error?: string;
}

export interface SetupOptions {
    endpoint: string;
    label?: string;
    /** Skip capability detection and start from a chosen method. */
    method?: AuthMethod;
    /** Injectable for tests. */
    register?: (endpoint: string, key: AccountKey, label?: string) => Promise<VerifyResult>;
    pickConfirmIndex?: () => number;
    mint?: () => AccountKey;
}

export interface AccountKeySetup {
    readonly state: SetupState;
    readonly context: SetupContext;
    subscribe(fn: (state: SetupState, context: SetupContext) => void): () => void;
    /** Kick off detection (or jump straight in if `method` was given). */
    start(): Promise<void>;
    chooseAccountKey(): void;
    choosePasskey(): void;
    /** Call after the app completes the passkey ceremony. */
    onPasskeyRegistered(result?: VerifyResult): void;
    /** From recovery_nudge: enroll a recovery account key, or finish. */
    createRecoveryKey(): void;
    skipRecovery(): void;
    /** From words_intro: user has pen and paper. Mints the key. */
    acknowledgePaper(): void;
    /** From words_show: proceed to the confirmation check. */
    toConfirm(): void;
    /** Returns true (and advances to register) if the word matches. */
    confirmWord(input: string): Promise<boolean>;
    /** Back from words_confirm to re-view the words. */
    review(): void;
    reset(): void;
}

export function createAccountKeySetup(opts: SetupOptions): AccountKeySetup {
    const register = opts.register ?? registerAccountKey;
    const mint = opts.mint ?? mintKey;
    const pickIndex = opts.pickConfirmIndex ?? (() => Math.floor(Math.random() * 12));

    let state: SetupState = 'detecting';
    let context: SetupContext = { isRecovery: false };
    const subs = new Set<(s: SetupState, c: SetupContext) => void>();

    const emit = () => {
        for (const fn of subs) fn(state, context);
    };
    const set = (next: SetupState, patch: Partial<SetupContext> = {}) => {
        state = next;
        context = { ...context, ...patch };
        emit();
    };

    const doRegister = async () => {
        if (!context.key) return;
        set('registering');
        try {
            const result = await register(opts.endpoint, context.key, opts.label);
            if (result.verified) set('done', { result });
            else set('error', { error: result.error || 'registration failed' });
        } catch (e) {
            set('error', { error: (e as Error).message });
        }
    };

    return {
        get state() {
            return state;
        },
        get context() {
            return context;
        },
        subscribe(fn) {
            subs.add(fn);
            return () => subs.delete(fn);
        },
        async start() {
            if (opts.method) {
                set('choose', { suggested: opts.method });
                if (opts.method === 'account-key') this.chooseAccountKey();
                else this.choosePasskey();
                return;
            }
            set('detecting');
            const suggested = await suggestedMethod();
            set('choose', { suggested });
        },
        chooseAccountKey() {
            set('words_intro', { isRecovery: false });
        },
        choosePasskey() {
            set('passkey');
        },
        onPasskeyRegistered(result) {
            set('recovery_nudge', { result });
        },
        createRecoveryKey() {
            set('words_intro', { isRecovery: true });
        },
        skipRecovery() {
            set('done');
        },
        acknowledgePaper() {
            set('words_show', { key: mint() });
        },
        toConfirm() {
            set('words_confirm', { confirmIndex: pickIndex() });
        },
        async confirmWord(input) {
            const i = context.confirmIndex ?? 0;
            const expected = context.key?.words[i];
            if (!expected || input.trim().toLowerCase() !== expected) return false;
            await doRegister();
            return true;
        },
        review() {
            set('words_show');
        },
        reset() {
            state = 'detecting';
            context = { isRecovery: false };
            emit();
        },
    };
}
