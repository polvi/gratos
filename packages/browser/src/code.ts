// Sign in with an app-delivered code — for people who can't use a passkey
// (no phone, no platform authenticator). This browser starts a ticket and
// keeps its verifier; the app's own backend resolves the person's phone/email
// to a Gratos user id, mints a code for the ticket with its service token, and
// delivers it (voice call, email, …). The code only works in THIS browser.
//
//   const ticket = await startCodeLogin(API);
//   await fetch('/api/send-code', { method: 'POST', body: JSON.stringify({ ticket, phone }) });
//   const r = await verifyCode(API, typedCode);
//   if (r.verified) await enableDeviceKey(API); // next time: silent sign-in

import type { VerifyResult } from './account-key';
import { rememberLastUsed } from './last-used';

const STORAGE_PREFIX = 'ag_code_ticket:';
const memory = new Map<string, string>(); // when sessionStorage is unavailable

function store(endpoint: string, value: string | null) {
    const key = STORAGE_PREFIX + endpoint;
    try {
        const s = (globalThis as any).sessionStorage as Storage | undefined;
        if (s) {
            if (value === null) s.removeItem(key);
            else s.setItem(key, value);
            return;
        }
    } catch {
        // fall through to memory
    }
    if (value === null) memory.delete(key);
    else memory.set(key, value);
}

function load(endpoint: string): { ticket: string; verifier: string } | null {
    const key = STORAGE_PREFIX + endpoint;
    let raw: string | null | undefined;
    try {
        raw = ((globalThis as any).sessionStorage as Storage | undefined)?.getItem(key);
    } catch {
        raw = undefined;
    }
    raw ??= memory.get(key) ?? null;
    if (!raw) return null;
    try {
        const v = JSON.parse(raw);
        return typeof v?.ticket === 'string' && typeof v?.verifier === 'string' ? v : null;
    } catch {
        return null;
    }
}

/**
 * Start a code sign-in. Returns the ticket to hand to your backend (which
 * mints the code for it); the matching verifier stays in this tab.
 */
export async function startCodeLogin(endpoint: string): Promise<string> {
    const res = await fetch(`${endpoint}/v1/code/start`, { method: 'POST', credentials: 'include' });
    if (!res.ok) throw new Error(`code start failed (${res.status})`);
    const { ticket, verifier } = (await res.json()) as { ticket: string; verifier: string };
    store(endpoint, JSON.stringify({ ticket, verifier }));
    return ticket;
}

/** Verify the code the person typed. Mints a session (amr "otp") on success. */
export async function verifyCode(endpoint: string, code: string): Promise<VerifyResult> {
    const pending = load(endpoint);
    if (!pending) return { verified: false, error: 'No code sign-in in progress' };
    const res = await fetch(`${endpoint}/v1/code/verify`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...pending, code }),
    });
    let data: any = {};
    try {
        data = await res.json();
    } catch {
        // non-JSON body
    }
    if (!res.ok) return { verified: false, error: data?.error || `code verify failed (${res.status})` };
    store(endpoint, null);
    if (data?.last_used) rememberLastUsed(data.last_used);
    return data as VerifyResult;
}
