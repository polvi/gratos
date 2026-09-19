// Software-key credentials: account keys (seed-derived, user-held recovery
// root) and device keys (non-extractable WebCrypto keys for silent daily
// login). Server-side this is deliberately minimal — the client derives a
// P-256 key pair (HKDF of the 128-bit account secret, salted by tenant, or a
// generated non-extractable device key) and proves possession by signing a
// single-use challenge. We store only the public key, mirroring WebAuthn.
//
// Signature payload (utf8): `${context}\n${challenge}\n${tenant}` — context
// domain-separates registration from login.

// @ts-ignore
import { Buffer } from 'node:buffer';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';

import type { Env, Variables } from './index';
import type { TenantInfo } from './tenant';
import {
    getUser,
    createUser,
    getCredentialById,
    getUserCredentials,
    saveKeyCredential,
    countCredentials,
    touchCredential,
    parseTransports,
    MAX_CREDENTIALS_PER_USER,
} from './db';
import { providerName } from './aaguid';
import { mintSession, resolveSession, weakerAmr, AMR_RANK, Amr, SESSION_TTL } from './sessions';
import { setLastUsed } from './last-used';
import { getSessionId } from './session';
import { WORDLIST } from './wordlist';

const CHALLENGE_TTL = 300; // 5 minutes, matches WebAuthn ceremonies
const CHALLENGE_RE = /^[A-Za-z0-9_-]{16,256}$/;

export const KEY_REGISTER_CONTEXT = 'authgravity-key-register-v1';
export const KEY_LOGIN_CONTEXT = 'authgravity-key-login-v1';

export function keySignaturePayload(context: string, challenge: string, tenant: string): string {
    return `${context}\n${challenge}\n${tenant}`;
}

const KIND_RANK: Record<string, number> = { webauthn: 3, devicekey: 2, softkey: 1 };
const KIND_TO_AMR: Record<string, Amr> = { devicekey: 'device', softkey: 'key' };

function b64u(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

function fromB64u(s: string): Uint8Array | null {
    try {
        return new Uint8Array(Buffer.from(s, 'base64url'));
    } catch {
        return null;
    }
}

async function credentialIdFor(publicKey: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', publicKey as any);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Verify a raw P-256 signature (64-byte r||s) over the payload. */
async function verifyKeySignature(publicKey: Uint8Array, signature: Uint8Array, payload: string): Promise<boolean> {
    if (publicKey.length !== 65 || publicKey[0] !== 0x04 || signature.length !== 64) return false;
    try {
        const key = await crypto.subtle.importKey(
            'raw',
            publicKey as any,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['verify']
        );
        return await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            signature as any,
            new TextEncoder().encode(payload) as any
        );
    } catch {
        return false;
    }
}

function newChallenge(): string {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return b64u(bytes);
}

/**
 * Light per-IP rate limit on ceremony challenge minting — ONE shared bucket
 * for WebAuthn and key ceremonies (so an attacker can't sum the allowances).
 * WebAuthn is scriptable too (attestation "none" verifies for software
 * authenticators), so both pipelines need the same meter.
 */
export async function ceremonyRateLimited(c: any): Promise<boolean> {
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const key = `auth_rl:${ip}`;
    const count = parseInt((await c.env.KV.get(key)) || '0', 10);
    if (count >= 120) return true;
    await c.env.KV.put(key, String(count + 1), { expirationTtl: 3600 });
    return false;
}

export function setSessionCookie(c: any, tenantInfo: TenantInfo, sessionId: string) {
    setCookie(c, 'session_id', sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        path: '/',
        maxAge: SESSION_TTL,
        domain: tenantInfo.cookieDomain,
    });
}

export function keyRoutes(tenantInfo: TenantInfo) {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();

    // Static BIP39 English wordlist, for clients rendering the 12-word form.
    app.get('/v1/key/wordlist.json', (c) =>
        c.json(WORDLIST, 200, { 'Cache-Control': 'public, max-age=86400, immutable' })
    );

    app.get('/v1/key/register/options', async (c) => {
        if (await ceremonyRateLimited(c)) return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
        const challenge = newChallenge();
        await c.env.KV.put(`key_reg_challenge:${tenantInfo.tenant}:${challenge}`, '1', {
            expirationTtl: CHALLENGE_TTL,
        });
        return c.json({ challenge, context: KEY_REGISTER_CONTEXT, tenant: tenantInfo.tenant });
    });

    app.post('/v1/key/register/verify', async (c) => {
        const body = await c.req.json().catch(() => null);
        const { challenge, public_key, signature, kind, label } = body ?? {};
        if (
            typeof challenge !== 'string' ||
            !CHALLENGE_RE.test(challenge) ||
            typeof public_key !== 'string' ||
            typeof signature !== 'string' ||
            (kind !== 'softkey' && kind !== 'devicekey')
        ) {
            return c.json({ verified: false, error: 'Malformed request' }, 400);
        }

        // Single-use challenge: consume before verification.
        const kvKey = `key_reg_challenge:${tenantInfo.tenant}:${challenge}`;
        if (!(await c.env.KV.get(kvKey))) {
            return c.json({ error: 'Challenge not found or expired' }, 400);
        }
        await c.env.KV.delete(kvKey);

        const pub = fromB64u(public_key);
        const sig = fromB64u(signature);
        if (!pub || !sig) return c.json({ verified: false, error: 'Malformed key material' }, 400);

        const payload = keySignaturePayload(KEY_REGISTER_CONTEXT, challenge, tenantInfo.tenant);
        if (!(await verifyKeySignature(pub, sig, payload))) {
            return c.json({ verified: false, error: 'Verification failed' }, 400);
        }

        const credentialId = await credentialIdFor(pub);
        if (await getCredentialById(c.env.DB, tenantInfo.tenant, credentialId)) {
            return c.json({ error: 'Credential already registered' }, 409);
        }

        // With a valid session, ATTACH the credential to the session's user
        // (recovery-key enrollment, device provisioning). Otherwise create a
        // fresh user — this is sign-up for the no-passkey path.
        let userId = crypto.randomUUID();
        let amr: Amr = KIND_TO_AMR[kind];
        const sessionId = getSessionId(c);
        if (sessionId) {
            const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
            if (session && (await getUser(c.env.DB, tenantInfo.tenant, session.userId))) {
                userId = session.userId;
                // Attaching never upgrades the session: a code or account-key
                // session that enrolls a device key stays at its own rank.
                amr = weakerAmr(session.amr, amr);
                if ((await countCredentials(c.env.DB, tenantInfo.tenant, userId)) >= MAX_CREDENTIALS_PER_USER) {
                    return c.json({ error: 'Too many credentials on this account' }, 400);
                }
            }
        }
        const created = !(await getUser(c.env.DB, tenantInfo.tenant, userId));
        if (created) {
            await createUser(c.env.DB, tenantInfo.tenant, userId);
        }

        const safeLabel = typeof label === 'string' && label.trim() ? label.trim().slice(0, 64) : null;
        const rowId = await saveKeyCredential(c.env.DB, tenantInfo.tenant, userId, credentialId, public_key, kind, safeLabel);

        const newSessionId = await mintSession(c.env.KV, tenantInfo.tenant, userId, amr, rowId);
        setSessionCookie(c, tenantInfo, newSessionId);
        // Sign-up only when this ceremony created the account; attaching a
        // recovery or device key to a signed-in user is not a "create account".
        const lastUsed = created ? setLastUsed(c, tenantInfo, 'register', KIND_TO_AMR[kind]) : undefined;

        return c.json({
            verified: true,
            user: { id: userId },
            credential_id: credentialId,
            credential: { id: rowId },
            ...(lastUsed ? { last_used: lastUsed } : {}),
            ...(tenantInfo.sandbox ? { session_id: newSessionId } : {}),
        });
    });

    app.get('/v1/key/login/options', async (c) => {
        if (await ceremonyRateLimited(c)) return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
        const challenge = newChallenge();
        await c.env.KV.put(`key_auth_challenge:${tenantInfo.tenant}:${challenge}`, '1', {
            expirationTtl: CHALLENGE_TTL,
        });
        return c.json({ challenge, context: KEY_LOGIN_CONTEXT, tenant: tenantInfo.tenant });
    });

    app.post('/v1/key/login/verify', async (c) => {
        const body = await c.req.json().catch(() => null);
        const { challenge, public_key, signature } = body ?? {};
        if (
            typeof challenge !== 'string' ||
            !CHALLENGE_RE.test(challenge) ||
            typeof public_key !== 'string' ||
            typeof signature !== 'string'
        ) {
            return c.json({ verified: false, error: 'Malformed request' }, 400);
        }

        const kvKey = `key_auth_challenge:${tenantInfo.tenant}:${challenge}`;
        if (!(await c.env.KV.get(kvKey))) {
            return c.json({ error: 'Challenge expired or invalid' }, 400);
        }
        await c.env.KV.delete(kvKey);

        const pub = fromB64u(public_key);
        const sig = fromB64u(signature);
        if (!pub || !sig) return c.json({ verified: false, error: 'Malformed key material' }, 400);

        const credentialId = await credentialIdFor(pub);
        const credential = (await getCredentialById(c.env.DB, tenantInfo.tenant, credentialId)) as any;
        if (!credential || credential.kind === 'webauthn') {
            return c.json({ error: 'Credential not found' }, 400);
        }
        // Defense in depth: verify against the STORED key, not the presented one.
        const storedPub = fromB64u(credential.public_key);
        if (!storedPub) return c.json({ error: 'Credential not found' }, 400);

        const payload = keySignaturePayload(KEY_LOGIN_CONTEXT, challenge, tenantInfo.tenant);
        if (!(await verifyKeySignature(storedPub, sig, payload))) {
            return c.json({ verified: false, error: 'Verification failed' }, 400);
        }

        const user = await getUser(c.env.DB, tenantInfo.tenant, credential.user_id);
        if (!user) return c.json({ error: 'User not found' }, 400);

        const amr: Amr = KIND_TO_AMR[credential.kind] ?? 'key';
        const newSessionId = await mintSession(c.env.KV, tenantInfo.tenant, (user as any).id, amr, credential.id);
        setSessionCookie(c, tenantInfo, newSessionId);
        const lastUsed = setLastUsed(c, tenantInfo, 'login', amr);
        c.executionCtx?.waitUntil?.(touchCredential(c.env.DB, credential.id));

        return c.json({
            verified: true,
            user: { id: (user as any).id },
            last_used: lastUsed,
            ...(tenantInfo.sandbox ? { session_id: newSessionId } : {}),
        });
    });

    // --- credential management (session required) ---

    // Wire shape of one credential. `display` is what a UI shows: the owner's
    // label, else the passkey provider (from the AAGUID), else a kind default.
    // `current` marks the credential that minted this very session.
    const publicCredential = (r: any, sessionCredentialId?: string) => {
        const kind: string = r.kind ?? 'webauthn';
        const label: string | null = r.label ?? null;
        const provider = kind === 'webauthn' ? providerName(r.aaguid) : null;
        const fallback = kind === 'webauthn' ? 'Passkey' : kind === 'devicekey' ? 'This device' : 'Account key';
        return {
            id: r.id,
            kind,
            label,
            provider,
            display: label ?? provider ?? fallback,
            backed_up: kind === 'webauthn' ? !!r.user_backed_up : null,
            transports: parseTransports(r.transports),
            created_at: r.created_at ?? null,
            last_used_at: r.last_used_at ?? null,
            current: !!sessionCredentialId && r.id === sessionCredentialId,
        };
    };

    const requireSession = async (c: any) => {
        const sessionId = getSessionId(c);
        if (!sessionId) return null;
        const session = await resolveSession(c.env.KV, tenantInfo.tenant, sessionId);
        if (!session) return null;
        if (!(await getUser(c.env.DB, tenantInfo.tenant, session.userId))) return null;
        return session;
    };

    app.get('/v1/credentials', async (c) => {
        const session = await requireSession(c);
        if (!session) return c.json({ error: 'Not authenticated' }, 401);
        const rows = await getUserCredentials(c.env.DB, tenantInfo.tenant, session.userId);
        return c.json({
            amr: session.amr,
            credentials: rows.map((r: any) => publicCredential(r, session.credentialId)),
        });
    });

    app.delete('/v1/credentials/:id', async (c) => {
        const session = await requireSession(c);
        if (!session) return c.json({ error: 'Not authenticated' }, 401);
        const rowId = c.req.param('id');

        const rows = await getUserCredentials(c.env.DB, tenantInfo.tenant, session.userId);
        const target = rows.find((r: any) => r.id === rowId);
        if (!target) return c.json({ error: 'Credential not found' }, 404);

        // Never orphan an account.
        if (rows.length <= 1) {
            return c.json({ error: 'Cannot remove the last credential' }, 409);
        }
        // A session may not remove a credential stronger than how it was
        // authenticated — a phished account key cannot evict a passkey.
        const targetRank = KIND_RANK[(target as any).kind ?? 'webauthn'] ?? 3;
        if (AMR_RANK[session.amr] < targetRank) {
            return c.json({ error: 'This session cannot remove a stronger credential — sign in with it first' }, 403);
        }

        await c.env.DB.prepare('DELETE FROM public_keys WHERE id = ? AND tenant = ? AND user_id = ?')
            .bind(rowId, tenantInfo.tenant, session.userId)
            .run();
        return c.json({ deleted: true });
    });

    return app;
}
