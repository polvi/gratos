// "Last used": which door this browser walked through last — sign in or
// create account — and with which credential kind. The server sets a
// JS-readable `ag_last_used` cookie on the tenant domain after every ceremony
// that mints a session, so the app can mark the matching button ("Last used")
// on the next visit. No identity is carried: value is `<action>.<method>`.
//
// Sources, in order: the cookie (authoritative, shared across the domain's
// apps), then a localStorage mirror filled by `rememberLastUsed` for origins
// the cookie cannot reach (a sandbox used directly, without `authgravity listen`).

export const LAST_USED_COOKIE = 'ag_last_used';
const STORAGE_KEY = 'ag_last_used';

export type LastUsedAction = 'login' | 'register';
export type LastUsedMethod = 'webauthn' | 'device' | 'key';
export type LastUsed = { action: LastUsedAction; method: LastUsedMethod };

const ACTIONS: ReadonlySet<string> = new Set(['login', 'register']);
const METHODS: ReadonlySet<string> = new Set(['webauthn', 'device', 'key']);

/** Parse the wire form (`login.webauthn`, `register.key`, …); null otherwise. */
export function parseLastUsed(value: unknown): LastUsed | null {
    if (typeof value !== 'string') return null;
    const [action, method, extra] = value.split('.');
    if (extra !== undefined || !ACTIONS.has(action) || !METHODS.has(method)) return null;
    return { action: action as LastUsedAction, method: method as LastUsedMethod };
}

function fromCookie(): LastUsed | null {
    try {
        const cookie = (globalThis as any).document?.cookie;
        if (typeof cookie !== 'string') return null;
        const m = cookie.match(/(?:^|; )ag_last_used=([^;]*)/);
        return m ? parseLastUsed(decodeURIComponent(m[1])) : null;
    } catch {
        return null;
    }
}

function fromStorage(): LastUsed | null {
    try {
        return parseLastUsed((globalThis as any).localStorage?.getItem(STORAGE_KEY));
    } catch {
        return null;
    }
}

/**
 * Which button to mark "Last used" — `{ action: 'login' | 'register', method }`
 * — or null for a browser that has never completed a ceremony here.
 */
export function lastUsed(): LastUsed | null {
    return fromCookie() ?? fromStorage();
}

/**
 * Mirror a verify response's `last_used` field into localStorage, for origins
 * the server cookie cannot reach. The SDK's own ceremonies call this; apps
 * driving the passkey endpoints directly can call it with the verify JSON.
 * Ignores anything that does not parse. Returns what was recorded.
 */
export function rememberLastUsed(value: unknown): LastUsed | null {
    const parsed = parseLastUsed(typeof value === 'object' && value !== null ? (value as any).last_used : value);
    if (!parsed) return null;
    try {
        (globalThis as any).localStorage?.setItem(STORAGE_KEY, `${parsed.action}.${parsed.method}`);
    } catch {
        // storage unavailable (private mode, blocked) — the cookie still works
    }
    return parsed;
}
