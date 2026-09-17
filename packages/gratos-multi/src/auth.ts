// @ts-ignore
import { Buffer } from 'node:buffer';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
    GenerateRegistrationOptionsOpts,
    GenerateAuthenticationOptionsOpts,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';

import type { Env, Variables } from './index';
import { hostMatchesRpId, type TenantInfo } from './tenant';
import {
    getUser,
    createUser,
    saveCredential,
    getCredentialById,
    getUserCredentials,
    countCredentials,
    updateCredentialUse,
    parseTransports,
    MAX_CREDENTIALS_PER_USER,
} from './db';
import { mintSession, resolveSession, SESSION_TTL } from './sessions';
import { getSessionId } from './session';
import { ceremonyRateLimited } from './keys';
import { setLastUsed } from './last-used';

const CHALLENGE_TTL = 300; // 5 minutes

// The challenge becomes part of a KV key, so require base64url charset.
const CHALLENGE_RE = /^[A-Za-z0-9_-]{16,256}$/;

/** Optional passkey label from `?label=`: trimmed, capped, else null. */
export function sanitizeLabel(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const t = raw.trim();
    return t ? t.slice(0, 64) : null;
}

/**
 * Pending-registration state stored under the challenge. Newer values are
 * JSON `{u, l}` (userId + optional label); values written before labels
 * existed are the bare userId, so a deploy never breaks an in-flight ceremony.
 */
export function parseRegChallenge(value: string | null): { userId: string; label: string | null } | null {
    if (!value) return null;
    if (value.startsWith('{')) {
        try {
            const parsed = JSON.parse(value) as { u?: unknown; l?: unknown };
            if (typeof parsed.u !== 'string' || !parsed.u) return null;
            return { userId: parsed.u, label: sanitizeLabel(parsed.l) };
        } catch {
            return null;
        }
    }
    return { userId: value, label: null };
}

/**
 * Get the allowed origin for WebAuthn verification.
 * The browser's WebAuthn response contains the *page's* origin (e.g. the dash),
 * not the API server's origin. We use the request's Origin header and validate
 * it belongs to the tenant's domain.
 */
function getExpectedOrigin(c: any, tenantInfo: TenantInfo): string {
    const requestOrigin = c.req.header('Origin');
    if (requestOrigin) {
        try {
            const host = new URL(requestOrigin).hostname;
            // Sandbox tenants run the ceremony on the developer's local app
            // (rpId=localhost) or, with a custom rp_id, on that hostname.
            if (tenantInfo.sandbox) {
                if (host === 'localhost' || host === '127.0.0.1' || hostMatchesRpId(host, tenantInfo.rpId)) {
                    return requestOrigin;
                }
            } else if (
                tenantInfo.tenant === 'localhost' ||
                host === tenantInfo.tenant ||
                host.endsWith('.' + tenantInfo.tenant)
            ) {
                return requestOrigin;
            }
        } catch {
            // invalid origin header
        }
    }
    // Fallback to worker's own origin
    return tenantInfo.origin;
}

/**
 * Recover the challenge from a WebAuthn credential response. The browser
 * echoes the challenge (signed) inside clientDataJSON, so pending-ceremony
 * state is keyed by the challenge itself — no separate correlation id.
 */
function challengeFromResponse(response: any): string | null {
    try {
        const clientData = JSON.parse(
            Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8')
        );
        const challenge = clientData.challenge;
        return typeof challenge === 'string' && CHALLENGE_RE.test(challenge)
            ? challenge
            : null;
    } catch {
        return null;
    }
}

async function createRegistrationOptions(c: any, tenantInfo: TenantInfo) {
    // With a valid session, registration ADDS a credential to the session's
    // user (multi-passkey / post-recovery re-enrollment). Otherwise a fresh
    // userId is minted; it travels only through the KV value — the client
    // never needs to see or echo it.
    let userId = crypto.randomUUID();
    // Existing passkeys of the signed-in user: the authenticator refuses to
    // enroll a second credential for one it already holds (InvalidStateError),
    // so "add a passkey" can never silently overwrite the one on this device.
    let excludeCredentials: { id: string; transports?: any[] }[] = [];
    const sessionId = getSessionId(c);
    if (sessionId) {
        const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
        if (session && (await getUser(c.env.DB, tenantInfo.tenant, session.userId))) {
            userId = session.userId;
            const existing = await getUserCredentials(c.env.DB, tenantInfo.tenant, userId);
            if (existing.length >= MAX_CREDENTIALS_PER_USER) {
                return { error: 'Too many credentials on this account' };
            }
            excludeCredentials = existing
                .filter((r: any) => (r.kind ?? 'webauthn') === 'webauthn')
                .map((r: any) => {
                    const transports = parseTransports(r.transports);
                    return transports.length ? { id: r.credential_id, transports } : { id: r.credential_id };
                });
        }
    }
    const label = sanitizeLabel(c.req.query('label'));

    const opts: GenerateRegistrationOptionsOpts = {
        rpName: tenantInfo.rpName,
        rpID: tenantInfo.rpId,
        userID: isoUint8Array.fromUTF8String(userId),
        userName: 'Me',
        userDisplayName: 'Me',
        excludeCredentials,
        // Any authenticator: platform (Touch ID, Windows Hello, phone) or
        // roaming (security keys) — a backup passkey is the point of allowing
        // several, so no attachment restriction.
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
        },
    };

    const options = await generateRegistrationOptions(opts);

    // Keyed by challenge; the value carries the minted userId (+ label) for verify.
    await c.env.KV.put(
        `reg_challenge:${tenantInfo.tenant}:${options.challenge}`,
        JSON.stringify({ u: userId, ...(label ? { l: label } : {}) }),
        { expirationTtl: CHALLENGE_TTL }
    );

    return options;
}

async function verifyRegistration(c: any, tenantInfo: TenantInfo, response: any) {
    const challenge = response && challengeFromResponse(response);
    if (!challenge) {
        return c.json({ verified: false, error: 'Malformed credential response' }, 400);
    }

    const key = `reg_challenge:${tenantInfo.tenant}:${challenge}`;
    const pending = parseRegChallenge(await c.env.KV.get(key));
    if (!pending) {
        return c.json({ error: 'Challenge not found or expired' }, 400);
    }
    const { userId, label } = pending;
    // Single-use: consume before verification. KV is eventually consistent,
    // so this is per-colo — same trust level as the previous design.
    await c.env.KV.delete(key);

    const expectedOrigin = getExpectedOrigin(c, tenantInfo);
    const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin,
        expectedRPID: tenantInfo.rpId,
    });

    if (verification.verified && verification.registrationInfo) {
        // Same authenticator, same account (or any account in this pool):
        // mirror the key path's 409 rather than surfacing a UNIQUE failure.
        if (typeof response.id !== 'string' || (await getCredentialById(c.env.DB, tenantInfo.tenant, response.id))) {
            return c.json({ error: 'Credential already registered' }, 409);
        }

        let user = await getUser(c.env.DB, tenantInfo.tenant, userId);
        const created = !user;
        if (!user) {
            await createUser(c.env.DB, tenantInfo.tenant, userId);
            user = { id: userId };
        } else if ((await countCredentials(c.env.DB, tenantInfo.tenant, userId)) >= MAX_CREDENTIALS_PER_USER) {
            return c.json({ error: 'Too many credentials on this account' }, 400);
        }

        const info = verification.registrationInfo as any;
        let rowId: string;
        try {
            rowId = await saveCredential(c.env.DB, tenantInfo.tenant, userId, verification, response.id, {
                label,
                aaguid: typeof info.aaguid === 'string' ? info.aaguid : null,
                transports: Array.isArray(info.credential?.transports) ? info.credential.transports : [],
                counter: typeof info.credential?.counter === 'number' ? info.credential.counter : 0,
            });
        } catch (e: any) {
            if (String(e?.message ?? e).includes('UNIQUE')) {
                return c.json({ error: 'Credential already registered' }, 409);
            }
            throw e;
        }

        const sessionId = await mintSession(c.env.KV, tenantInfo.tenant, userId, 'webauthn', rowId);

        setCookie(c, 'session_id', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            path: '/',
            maxAge: SESSION_TTL,
            domain: tenantInfo.cookieDomain,
        });
        // Only a brand-new account counts as "create account"; adding a
        // passkey to a signed-in user leaves the last-used signal alone.
        const lastUsed = created ? setLastUsed(c, tenantInfo, 'register', 'webauthn') : undefined;

        // Sandbox tenants are cross-site (local app ↔ sandbox host), so the
        // httpOnly cookie can't be relied on — return the session id so the
        // app can send it as `Authorization: Bearer <session_id>`.
        return c.json({
            verified: true,
            user: { id: userId },
            credential: { id: rowId },
            ...(lastUsed ? { last_used: lastUsed } : {}),
            ...(tenantInfo.sandbox ? { session_id: sessionId } : {}),
        });
    }

    return c.json({ verified: false, error: 'Verification failed' }, 400);
}

async function createAuthenticationOptions(c: any, tenantInfo: TenantInfo) {
    const opts: GenerateAuthenticationOptionsOpts = {
        rpID: tenantInfo.rpId,
        userVerification: 'preferred',
    };

    const options = await generateAuthenticationOptions(opts);

    await c.env.KV.put(
        `auth_challenge:${tenantInfo.tenant}:${options.challenge}`,
        '1',
        { expirationTtl: CHALLENGE_TTL }
    );

    return options;
}

async function verifyAuthentication(c: any, tenantInfo: TenantInfo, response: any) {
    const challenge = response && challengeFromResponse(response);
    if (!challenge) {
        return c.json({ verified: false, error: 'Malformed credential response' }, 400);
    }

    const key = `auth_challenge:${tenantInfo.tenant}:${challenge}`;
    const pending = await c.env.KV.get(key);
    if (!pending) {
        return c.json({ error: 'Challenge expired or invalid' }, 400);
    }
    // Single-use: consume before verification (see note in verifyRegistration).
    await c.env.KV.delete(key);

    const credentialId = response.id;
    const credential = await getCredentialById(c.env.DB, tenantInfo.tenant, credentialId) as any;

    if (!credential) {
        return c.json({ error: 'Credential not found' }, 400);
    }

    const storedTransports = parseTransports(credential.transports);
    const credentialObj = {
        id: credentialId,
        publicKey: new Uint8Array(Buffer.from(credential.public_key, 'base64')),
        counter: typeof credential.counter === 'number' ? credential.counter : 0,
        ...(storedTransports.length ? { transports: storedTransports as any } : {}),
    };

    const expectedOrigin = getExpectedOrigin(c, tenantInfo);
    const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin,
        expectedRPID: tenantInfo.rpId,
        credential: credentialObj,
    });

    if (verification.verified) {
        const user = await getUser(c.env.DB, tenantInfo.tenant, credential.user_id);
        if (!user) {
            return c.json({ error: 'User not found' }, 400);
        }

        const sessionId = await mintSession(c.env.KV, tenantInfo.tenant, (user as any).id, 'webauthn', credential.id);

        setCookie(c, 'session_id', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            path: '/',
            maxAge: SESSION_TTL,
            domain: tenantInfo.cookieDomain,
        });
        const lastUsed = setLastUsed(c, tenantInfo, 'login', 'webauthn');
        const newCounter = verification.authenticationInfo?.newCounter ?? credentialObj.counter;
        const bookkeeping = updateCredentialUse(c.env.DB, credential.id, newCounter);
        if (c.executionCtx?.waitUntil) c.executionCtx.waitUntil(bookkeeping);
        else await bookkeeping;

        return c.json({
            verified: true,
            user,
            last_used: lastUsed,
            ...(tenantInfo.sandbox ? { session_id: sessionId } : {}),
        });
    }

    return c.json({ verified: false }, 400);
}

export function authRoutes(tenantInfo: TenantInfo) {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();

    // Standard WebAuthn JSON: options endpoints return @simplewebauthn/server
    // output verbatim (PublicKeyCredentialCreationOptionsJSON /
    // RequestOptionsJSON); verify endpoints accept a bare
    // RegistrationResponseJSON / AuthenticationResponseJSON as the whole
    // POST body.

    app.get('/v1/register/options', async (c) => {
        // Same per-IP meter as the key ceremonies: attestation "none" means a
        // software authenticator can script this pipeline, so challenge
        // minting must be as bounded here as it is there.
        if (await ceremonyRateLimited(c)) return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
        const options = await createRegistrationOptions(c, tenantInfo);
        if ('error' in options) return c.json(options, 400);
        return c.json(options);
    });

    app.post('/v1/register/verify', async (c) => {
        return verifyRegistration(c, tenantInfo, await c.req.json());
    });

    app.get('/v1/login/options', async (c) => {
        if (await ceremonyRateLimited(c)) return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
        return c.json(await createAuthenticationOptions(c, tenantInfo));
    });

    app.post('/v1/login/verify', async (c) => {
        return verifyAuthentication(c, tenantInfo, await c.req.json());
    });

    return app;
}
