// "Last used" signal: which door this browser walked through last, sign-in or
// create-account, and with which credential kind. Every ceremony that mints a
// session sets a long-lived, JS-readable cookie on the tenant domain so the
// app can put a "Last used" hint on the matching button next time — the way
// consumer sign-in screens mark the provider you picked before. Logout keeps
// it on purpose: that is exactly when the hint matters.
//
// Server-side it is never read; it carries no identity (no user id, no
// credential id), only `<action>.<amr>`.

import { setCookie } from 'hono/cookie';

import type { TenantInfo } from './tenant';
import type { Amr } from './sessions';

export const LAST_USED_COOKIE = 'ag_last_used';
export const LAST_USED_TTL = 365 * 86400; // a year; refreshed on every ceremony

export type LastUsedAction = 'login' | 'register';
export type LastUsed = { action: LastUsedAction; method: Amr };

const ACTIONS = new Set<string>(['login', 'register']);
const METHODS = new Set<string>(['webauthn', 'device', 'key', 'otp']);

/** Wire form of the cookie / response field: `login.webauthn`, `register.key`, … */
export function formatLastUsed(action: LastUsedAction, method: Amr): string {
    return `${action}.${method}`;
}

/** Parse the wire form; null for anything malformed or from the future. */
export function parseLastUsed(value: string | null | undefined): LastUsed | null {
    if (typeof value !== 'string') return null;
    const [action, method, extra] = value.split('.');
    if (extra !== undefined || !ACTIONS.has(action) || !METHODS.has(method)) return null;
    return { action: action as LastUsedAction, method: method as Amr };
}

/**
 * Record the signal on the response and return the wire value so the verify
 * JSON can carry it too (sandbox tenants are cross-site and never see the
 * cookie; the CLI proxy mirrors the field onto localhost).
 */
export function setLastUsed(c: any, tenantInfo: TenantInfo, action: LastUsedAction, method: Amr): string {
    const value = formatLastUsed(action, method);
    setCookie(c, LAST_USED_COOKIE, value, {
        // Deliberately NOT httpOnly: the whole point is that the app's own
        // sign-in UI reads it. Same site scoping as the session cookie.
        secure: true,
        sameSite: 'None',
        path: '/',
        maxAge: LAST_USED_TTL,
        domain: tenantInfo.cookieDomain,
    });
    return value;
}
