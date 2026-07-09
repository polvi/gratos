// Account keys — the no-passkey fallback and universal recovery path. Mint or
// decode a 128-bit secret, then register/login/claim-or-recover against a
// tenant endpoint.

import {
    COMPACT_PREFIX,
    decodeCompact,
    decodeWords,
    derivePrivateKey,
    encodeCompact,
    encodeWords,
    publicKeyFor,
    signPayload,
} from './crypto';
import { runCeremony, type Signer } from './ceremony';

export interface AccountKey {
    entropy: Uint8Array;
    /** Compact rendering: "agak1_…". */
    compact: string;
    /** 12-word BIP39 rendering. */
    words: string[];
}

export interface VerifyResult {
    verified: boolean;
    user?: { id: string };
    credential_id?: string;
    /** Present on sandbox endpoints (Bearer-usable). */
    session_id?: string;
    error?: string;
}

export function keyFromEntropy(entropy: Uint8Array): AccountKey {
    if (entropy.length !== 16) throw new Error('entropy must be 16 bytes');
    return { entropy, compact: encodeCompact(entropy), words: encodeWords(entropy) };
}

/** Mint a fresh account key (16 bytes of CSPRNG entropy). */
export function mintKey(): AccountKey {
    const entropy = new Uint8Array(16);
    crypto.getRandomValues(entropy);
    return keyFromEntropy(entropy);
}

/** Decode a user-entered key: an "agak1_…" string or 12 space-separated words. */
export function decodeKey(input: string): AccountKey {
    const trimmed = input.trim();
    const entropy = trimmed.toLowerCase().startsWith(COMPACT_PREFIX)
        ? decodeCompact(trimmed)
        : decodeWords(trimmed.split(/\s+/));
    return keyFromEntropy(entropy);
}

function accountKeySigner(entropy: Uint8Array): Signer {
    return async (payload, tenant) => {
        const priv = derivePrivateKey(entropy, tenant);
        return { publicKey: publicKeyFor(priv), signature: signPayload(priv, payload) };
    };
}

/** Register an account key, creating a new account (or, with a session, adding a recovery key). */
export async function registerAccountKey(
    endpoint: string,
    key: AccountKey,
    label = 'account key'
): Promise<VerifyResult> {
    const r = await runCeremony(endpoint, 'register', accountKeySigner(key.entropy), { kind: 'softkey', label });
    if (!r.ok) return { verified: false, error: r.data?.error || `register failed (${r.status})` };
    return r.data as VerifyResult;
}

/** Log in with an existing account key. */
export async function loginWithAccountKey(endpoint: string, key: AccountKey): Promise<VerifyResult> {
    const r = await runCeremony(endpoint, 'login', accountKeySigner(key.entropy), {});
    if (!r.ok) return { verified: false, error: r.data?.error || `login failed (${r.status})` };
    return r.data as VerifyResult;
}

/**
 * Bring-your-own phrase: claim the account if the key is new, or recover
 * (log in) if it already exists. Registration returns 409 for an existing
 * credential; on any non-verified register we fall back to login with the same
 * key. `recovered` says which path succeeded.
 */
export async function claimOrRecover(
    endpoint: string,
    key: AccountKey,
    label = 'account key'
): Promise<VerifyResult & { recovered: boolean }> {
    const reg = await registerAccountKey(endpoint, key, label);
    if (reg.verified) return { ...reg, recovered: false };
    const login = await loginWithAccountKey(endpoint, key);
    return { ...login, recovered: true };
}
