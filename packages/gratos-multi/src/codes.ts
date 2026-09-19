// App-delivered sign-in codes, for users who can't hold a passkey (no phone,
// no platform authenticator, not comfortable with one). The tenant's backend
// owns the delivery channel — a voice call to a landline, an email — and the
// mapping from that address to a Gratos user; Gratos never sees either. It
// only provisions users and mints/verifies short codes. NIST SP 800-63B calls
// this an out-of-band authenticator; it is NOT phishing-resistant, so sessions
// it mints carry the lowest amr ("otp") and the expected next step is to
// enroll a device key so the code is needed once per computer.
//
// Flow (admin-provisioned accounts only — codes are never minted for a user
// that doesn't exist, so there is no self-serve sign-up and no toll-fraud
// surface here):
//   1. backend  POST /v1/users            (service token) → {user_id}
//   2. browser  POST /v1/code/start                        → {ticket, verifier}
//   3. browser → app backend: {ticket, phone}; the app resolves phone → user_id
//   4. backend  POST /v1/code/mint {ticket, user_id} (service token) → {code}
//   5. app delivers the code; browser POST /v1/code/verify {ticket, verifier, code}
//
// The verifier never leaves the browser that started the ticket, so a code
// overheard or left on voicemail is useless in any other browser. Ticket
// state lives in D1 (migration 0009) so attempts and the claim are atomic.

import { Hono } from 'hono';

import type { Env, Variables } from './index';
import type { TenantInfo } from './tenant';
import { getUser, createUser } from './db';
import { mintSession } from './sessions';
import { ceremonyRateLimited, setSessionCookie } from './keys';
import { setLastUsed } from './last-used';
import { b64u, sha256B64u } from './aauth/encoding';

export const TICKET_TTL_S = 600; // a code is typed within 10 minutes (NIST OOB guidance)
export const MAX_MINTS = 3; // first code + two resends per ticket
export const MAX_TRIES = 5; // attempts per code before the ticket is burned
export const USER_MINTS_PER_HOUR = 5;
const TICKET_RE = /^[A-Za-z0-9_-]{22}$/;
const CODE_RE = /^\d{6}$/;

export type CodeResult<T> = T | { error: string; status: 400 | 404 | 409 | 429 };

type TicketRow = { vh: string; exp: number; mints: number; tries: number; user_id: string | null; ch: string | null };

function randomB64u(n: number): string {
    return b64u(crypto.getRandomValues(new Uint8Array(n)));
}

/** Uniform 6-digit code: rejection-sample a uint32 so no residue is favoured. */
export function generateCode(): string {
    const limit = Math.floor(0x100000000 / 1_000_000) * 1_000_000;
    const buf = new Uint32Array(1);
    for (;;) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) return String(buf[0] % 1_000_000).padStart(6, '0');
    }
}

function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

async function readTicket(db: D1Database, tenant: string, ticket: string, now: number): Promise<TicketRow | null> {
    if (!TICKET_RE.test(ticket)) return null;
    const row = await db
        .prepare('SELECT vh, exp, mints, tries, user_id, ch FROM code_tickets WHERE tenant = ? AND ticket = ?')
        .bind(tenant, ticket)
        .first<TicketRow>();
    return row && row.exp > now ? row : null;
}

export async function startTicket(db: D1Database, tenant: string, now = Date.now()) {
    const ticket = randomB64u(16);
    const verifier = randomB64u(32);
    const exp = now + TICKET_TTL_S * 1000;
    // Expired tickets of this pool go as new ones arrive (plus the sandbox sweeps).
    await db.batch([
        db.prepare('DELETE FROM code_tickets WHERE tenant = ? AND exp <= ?').bind(tenant, now),
        db
            .prepare('INSERT INTO code_tickets (tenant, ticket, vh, exp) VALUES (?, ?, ?, ?)')
            .bind(tenant, ticket, await sha256B64u(verifier), exp),
    ]);
    return { ticket, verifier, expires_at: exp };
}

/**
 * Mint (or re-mint, for "call me again") the code for a ticket. The caller —
 * the tenant backend — has already checked that `userId` exists. A re-mint
 * replaces the code, resets the tries, and restarts the 10-minute window.
 */
export async function mintCode(
    db: D1Database,
    kv: Pick<KVNamespace, 'get' | 'put'>,
    tenant: string,
    ticket: string,
    userId: string,
    now = Date.now()
): Promise<CodeResult<{ code: string; expires_at: number }>> {
    const rec = await readTicket(db, tenant, ticket, now);
    if (!rec) return { error: 'Ticket not found or expired', status: 404 };
    if (rec.mints >= MAX_MINTS) return { error: 'Too many codes for this ticket', status: 429 };
    if (rec.user_id && rec.user_id !== userId) return { error: 'Ticket belongs to another user', status: 400 };

    // Soft cap (KV is not atomic); the hard limits are per ticket, in D1.
    const rlKey = `code_rl_user:${tenant}:${userId}`;
    const sent = parseInt((await kv.get(rlKey)) || '0', 10);
    if (sent >= USER_MINTS_PER_HOUR) return { error: 'Too many codes for this user, try again later', status: 429 };
    await kv.put(rlKey, String(sent + 1), { expirationTtl: 3600 });

    const code = generateCode();
    const exp = now + TICKET_TTL_S * 1000;
    const updated = await db
        .prepare(
            `UPDATE code_tickets SET user_id = ?1, ch = ?2, mints = mints + 1, tries = 0, exp = ?3
             WHERE tenant = ?4 AND ticket = ?5 AND exp > ?6 AND mints < ?7 AND (user_id IS NULL OR user_id = ?1)
             RETURNING exp`
        )
        .bind(userId, await sha256B64u(`${ticket}:${code}`), exp, tenant, ticket, now, MAX_MINTS)
        .first<{ exp: number }>();
    if (!updated) return { error: 'Ticket changed concurrently, try again', status: 409 };
    return { code, expires_at: exp };
}

/**
 * Check a typed code. A wrong verifier (another browser) is refused without
 * spending a try. Otherwise one attempt is reserved atomically BEFORE the
 * comparison, so parallel guesses can never exceed MAX_TRIES per code, and a
 * match must win the conditional DELETE, so a code yields one session at most.
 */
export async function verifyCode(
    db: D1Database,
    tenant: string,
    ticket: string,
    verifier: string,
    code: string,
    now = Date.now()
): Promise<CodeResult<{ userId: string }>> {
    const invalid = { error: 'Invalid or expired code', status: 400 as const };
    const rec = await readTicket(db, tenant, ticket, now);
    if (!rec || !rec.ch) return invalid;
    if (!timingSafeEqual(await sha256B64u(verifier), rec.vh)) return invalid;

    const attempt = await db
        .prepare(
            `UPDATE code_tickets SET tries = tries + 1
             WHERE tenant = ? AND ticket = ? AND exp > ? AND ch IS NOT NULL AND tries < ?
             RETURNING user_id, ch, tries`
        )
        .bind(tenant, ticket, now, MAX_TRIES)
        .first<{ user_id: string; ch: string; tries: number }>();
    if (!attempt) return invalid;

    const presented = CODE_RE.test(code) ? await sha256B64u(`${ticket}:${code}`) : '';
    if (!timingSafeEqual(presented, attempt.ch)) {
        if (attempt.tries >= MAX_TRIES) {
            await db.prepare('DELETE FROM code_tickets WHERE tenant = ? AND ticket = ?').bind(tenant, ticket).run();
        }
        return invalid;
    }
    const claimed = await db
        .prepare('DELETE FROM code_tickets WHERE tenant = ? AND ticket = ? AND ch = ? RETURNING user_id')
        .bind(tenant, ticket, attempt.ch)
        .first<{ user_id: string }>();
    return claimed ? { userId: claimed.user_id } : invalid;
}

/**
 * The tenant backend's credential: `Authorization: Bearer agk_…`, verified by
 * gratos-authz (which owns service tokens). Anonymous sandboxes are open pools
 * — same rule as authz writes — so agents can exercise the flow with no setup.
 */
async function isTenantBackend(c: any, tenantInfo: TenantInfo): Promise<boolean> {
    if (tenantInfo.sandbox) {
        const row = (await c.env.DB.prepare('SELECT user_id FROM sandboxes WHERE id = ?')
            .bind(tenantInfo.tenant)
            .first()) as { user_id: string | null } | null;
        if (row && !row.user_id) return true;
    }
    const auth: string | undefined = c.req.header('Authorization');
    if (!auth?.startsWith('Bearer agk_')) return false;
    return c.env.AUTHZ.verifyServiceToken(tenantInfo.tenant, auth.slice(7));
}

export function codeRoutes(tenantInfo: TenantInfo) {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();
    const tenant = tenantInfo.tenant;
    const fail = (c: any, r: { error: string; status: number }) => c.json({ error: r.error }, r.status);

    // Provision a user with no credentials yet (the app stores the mapping
    // from its own contact address to this id).
    app.post('/v1/users', async (c) => {
        if (!(await isTenantBackend(c, tenantInfo))) return c.json({ error: 'Service token required' }, 401);
        const userId = crypto.randomUUID();
        await createUser(c.env.DB, tenant, userId);
        return c.json({ user_id: userId }, 201);
    });

    app.post('/v1/code/start', async (c) => {
        if (await ceremonyRateLimited(c)) return c.json({ error: 'Rate limit exceeded, try again later' }, 429);
        return c.json(await startTicket(c.env.DB, tenant));
    });

    app.post('/v1/code/mint', async (c) => {
        if (!(await isTenantBackend(c, tenantInfo))) return c.json({ error: 'Service token required' }, 401);
        const body = await c.req.json().catch(() => null);
        const { ticket, user_id } = body ?? {};
        if (typeof ticket !== 'string' || typeof user_id !== 'string') {
            return c.json({ error: 'Malformed request' }, 400);
        }
        if (!(await getUser(c.env.DB, tenant, user_id))) return c.json({ error: 'Unknown user' }, 404);
        const r = await mintCode(c.env.DB, c.env.KV, tenant, ticket, user_id);
        return 'error' in r ? fail(c, r) : c.json(r);
    });

    app.post('/v1/code/verify', async (c) => {
        const body = await c.req.json().catch(() => null);
        const { ticket, verifier, code } = body ?? {};
        if (typeof ticket !== 'string' || typeof verifier !== 'string' || typeof code !== 'string') {
            return c.json({ verified: false, error: 'Malformed request' }, 400);
        }
        const r = await verifyCode(c.env.DB, tenant, ticket, verifier, code.replace(/\D/g, ''));
        if ('error' in r) return c.json({ verified: false, error: r.error }, r.status);
        if (!(await getUser(c.env.DB, tenant, r.userId))) {
            return c.json({ verified: false, error: 'Invalid or expired code' }, 400);
        }

        const sessionId = await mintSession(c.env.KV, tenant, r.userId, 'otp');
        setSessionCookie(c, tenantInfo, sessionId);
        const lastUsed = setLastUsed(c, tenantInfo, 'login', 'otp');
        return c.json({
            verified: true,
            user: { id: r.userId },
            last_used: lastUsed,
            ...(tenantInfo.sandbox ? { session_id: sessionId } : {}),
        });
    });

    return app;
}
