// Session-strength ranking for `min_amr` enforcement on /v1/authz/check.
//
// The source of truth for these ranks is `packages/gratos-multi/src/sessions.ts`
// (AMR_RANK). It is duplicated here on purpose: gratos-authz is a separately
// deployed Worker with no dependency on gratos-multi, and this is a four-entry
// constant. The authz worker only ever sees `amr` as the trusted `X-Gratos-Amr`
// header (see middleware.ts), which is one of these strings or undefined.

import { ApiError } from './model';

export type Amr = 'webauthn' | 'device' | 'key' | 'otp';

export const AMR_RANK: Record<Amr, number> = { webauthn: 3, device: 2, key: 1, otp: 0 };

export function isAmr(v: unknown): v is Amr {
    return v === 'webauthn' || v === 'device' || v === 'key' || v === 'otp';
}

/**
 * Parse an optional `min_amr` field. Returns null when absent; throws
 * ApiError(400) on a present-but-invalid value (matches parseObjectRef's style).
 */
export function parseMinAmr(v: unknown, label = ''): Amr | null {
    if (v === undefined || v === null) return null;
    if (isAmr(v)) return v;
    throw new ApiError(400, `${label}min_amr must be one of "webauthn", "device", "key", "otp"`);
}

/**
 * A session authenticated with `have` satisfies a requirement of `need` iff it
 * is at least as strong. A missing/unknown amr (undefined) NEVER satisfies a
 * requirement — fail closed rather than assume a strong session.
 */
export function meetsMinAmr(have: string | undefined, need: Amr): boolean {
    return isAmr(have) && AMR_RANK[have] >= AMR_RANK[need];
}
