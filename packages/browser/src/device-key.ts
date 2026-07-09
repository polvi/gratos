// Device keys — the silent daily-login half. A non-extractable WebCrypto P-256
// pair, enrolled as an extra credential after first login and tried silently on
// return. The account-key words are then only for a new computer or recovery.
//
// Sharp edges decided once, here: the key is non-extractable; storage failures
// FAIL OPEN (registration still succeeds; only silent login is unavailable); a
// revoked/absent key never strands the user (trySilentLogin returns null).

import { runCeremony, type Signer } from './ceremony';
import type { VerifyResult } from './account-key';

const DB_NAME = 'authgravity-keys';
const STORE = 'keys';
const DEVICE_KEY = 'device';

function idb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(STORE);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
    const db = await idb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
        tx.onsuccess = () => resolve(tx.result as T | undefined);
        tx.onerror = () => reject(tx.error);
    });
}

async function idbSet(key: string, value: unknown): Promise<void> {
    const db = await idb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function idbDelete(key: string): Promise<void> {
    const db = await idb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).delete(key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

function deviceKeySigner(pair: CryptoKeyPair): Signer {
    return async (payload) => {
        const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
        const signature = new Uint8Array(
            await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-256' },
                pair.privateKey,
                new TextEncoder().encode(payload)
            )
        );
        return { publicKey, signature };
    };
}

export interface EnableDeviceKeyResult extends VerifyResult {
    /** False if the key registered but couldn't be persisted (silent login unavailable). */
    stored: boolean;
}

/**
 * Enroll a silent device key. Call after a first successful login (the session
 * cookie is what attaches this credential to the user). Non-extractable, so it
 * can never leave this device; storage failure fails open.
 */
export async function enableDeviceKey(endpoint: string, label = 'this device'): Promise<EnableDeviceKeyResult> {
    const pair = (await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, // non-extractable
        ['sign']
    )) as CryptoKeyPair;

    const r = await runCeremony(endpoint, 'register', deviceKeySigner(pair), { kind: 'devicekey', label });
    if (!r.ok) {
        return { verified: false, stored: false, error: r.data?.error || `device register failed (${r.status})` };
    }

    let stored = false;
    try {
        await idbSet(DEVICE_KEY, pair);
        stored = true;
    } catch {
        stored = false; // fail open — credential is registered, just not silently reusable
    }
    return { ...(r.data as VerifyResult), stored };
}

/**
 * Try a silent login with the stored device key. Returns null when there is no
 * device key, storage is unavailable, or the login is rejected (e.g. revoked) —
 * the caller falls back to passkey / account-key.
 */
export async function trySilentLogin(endpoint: string): Promise<VerifyResult | null> {
    let pair: CryptoKeyPair | undefined;
    try {
        pair = await idbGet<CryptoKeyPair>(DEVICE_KEY);
    } catch {
        return null;
    }
    if (!pair) return null;
    try {
        const r = await runCeremony(endpoint, 'login', deviceKeySigner(pair), {});
        if (r.ok) return r.data as VerifyResult;
        // Revoked/unknown device key: stop offering it silently.
        if (r.status === 400 || r.status === 401) await forgetDeviceKey();
        return null;
    } catch {
        return null;
    }
}

export async function hasDeviceKey(): Promise<boolean> {
    try {
        return !!(await idbGet(DEVICE_KEY));
    } catch {
        return false;
    }
}

export async function forgetDeviceKey(): Promise<void> {
    try {
        await idbDelete(DEVICE_KEY);
    } catch {
        // best-effort
    }
}
