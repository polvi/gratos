// Server-side AuthGravity client. Talks to the tenant host HTTP API
// (https://authgravity.<domain>) — the authz worker has no public route, so a
// backend reaches it through this host with the end-user's session cookie (for
// checks) or a service token (for writes).

import { objectRef } from './ids';

export type Amr = 'webauthn' | 'device' | 'key' | 'otp';

/** Structural schema shape; the generated `AuthzSchema` satisfies it. */
export interface SchemaShape {
    [type: string]: { permissions: string; relations: string };
}

/** Default when the caller doesn't parameterize with a generated schema. */
export interface AnySchema extends SchemaShape {
    [type: string]: { permissions: string; relations: string };
}

/** Anything carrying a cookie header: a Request, Headers, or the raw string. */
export type CookieSource = string | { headers: { get(name: string): string | null } };

export interface CheckRef<S extends SchemaShape, T extends keyof S & string> {
    type: T;
    id: string;
    permission: S[T]['permissions'];
    /** Explicit subject (e.g. user(uuid)); omit to check the session user ("self"). */
    subject?: string;
    /** Require the session to be at least this strong; else reason: "insufficient_amr". */
    min_amr?: Amr;
}

export interface CheckResult {
    allowed: boolean;
    reason?: string;
    error?: string;
    userId?: string;
}

export interface RelUpdate {
    op: 'touch' | 'create' | 'delete';
    object: string;
    relation: string;
    subject: string;
}

export interface AuthgravityConfig {
    /** e.g. https://authgravity.myapp.com */
    endpoint: string;
    /** Service token (agk_…) for relationship writes, service-token checks, and sign-in codes. */
    serviceToken?: string;
}

const CHECK_CHUNK = 50; // server MAX_CHECK_ITEMS
const WRITE_CHUNK = 100; // server MAX_UPDATES

function cookieHeaderFrom(src: CookieSource | null | undefined): string | undefined {
    if (!src) return undefined;
    if (typeof src === 'string') return src || undefined;
    return src.headers.get('cookie') ?? src.headers.get('Cookie') ?? undefined;
}

function refToItem<S extends SchemaShape, T extends keyof S & string>(ref: CheckRef<S, T>) {
    return {
        object: objectRef(ref.type, ref.id),
        permission: ref.permission,
        ...(ref.subject ? { subject: ref.subject } : {}),
        ...(ref.min_amr ? { min_amr: ref.min_amr } : {}),
    };
}

export class AuthgravityServer<S extends SchemaShape = AnySchema> {
    constructor(private readonly config: AuthgravityConfig) {}

    private async post(path: string, body: unknown, cookie?: string, requireService = false): Promise<Response> {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (cookie) {
            headers.cookie = cookie;
        } else {
            if (!this.config.serviceToken) {
                throw new Error(
                    requireService
                        ? 'a serviceToken is required for this call'
                        : 'no session cookie and no serviceToken: cannot authenticate the check'
                );
            }
            headers.Authorization = `Bearer ${this.config.serviceToken}`;
        }
        return fetch(`${this.config.endpoint}${path}`, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
        });
    }

    /**
     * Check one permission. Fails CLOSED: any transport error or non-2xx
     * response resolves to { allowed: false }, never throws.
     */
    async check<T extends keyof S & string>(source: CookieSource | null, ref: CheckRef<S, T>): Promise<CheckResult> {
        const cookie = cookieHeaderFrom(source);
        try {
            const res = await this.post('/v1/authz/check', refToItem(ref), cookie);
            if (!res.ok) return { allowed: false };
            const data = (await res.json()) as any;
            return { allowed: !!data.allowed, reason: data.reason, userId: data.user_id };
        } catch {
            return { allowed: false };
        }
    }

    /**
     * Batch check (e.g. a list page). Order-preserving; chunked at the server's
     * 50-item cap. A failed chunk fails closed (all its items → allowed:false).
     */
    async checkMany<T extends keyof S & string>(
        source: CookieSource | null,
        refs: CheckRef<S, T>[]
    ): Promise<CheckResult[]> {
        const cookie = cookieHeaderFrom(source);
        const out: CheckResult[] = [];
        for (let i = 0; i < refs.length; i += CHECK_CHUNK) {
            const chunk = refs.slice(i, i + CHECK_CHUNK);
            try {
                const res = await this.post('/v1/authz/check', { items: chunk.map(refToItem) }, cookie);
                if (!res.ok) {
                    out.push(...chunk.map(() => ({ allowed: false }) as CheckResult));
                    continue;
                }
                const data = (await res.json()) as any;
                const results = Array.isArray(data.results) ? data.results : [];
                out.push(
                    ...chunk.map((_, j) => {
                        const r = results[j];
                        return r
                            ? { allowed: !!r.allowed, reason: r.reason, error: r.error }
                            : { allowed: false };
                    })
                );
            } catch {
                out.push(...chunk.map(() => ({ allowed: false }) as CheckResult));
            }
        }
        return out;
    }

    /**
     * Write relationships with the service token. Chunked at the server's
     * 100-update atomic cap (each chunk is its own transaction — no
     * cross-chunk atomicity). Throws on failure so the caller notices.
     */
    async write(updates: RelUpdate[]): Promise<{ written: number; deleted: number }> {
        let written = 0;
        let deleted = 0;
        for (let i = 0; i < updates.length; i += WRITE_CHUNK) {
            const chunk = updates.slice(i, i + WRITE_CHUNK);
            const res = await this.post('/v1/authz/relationships', { updates: chunk }, undefined, true);
            if (!res.ok) {
                throw new Error(`authz write failed (${res.status}): ${await res.text()}`);
            }
            const data = (await res.json()) as any;
            written += data.written ?? 0;
            deleted += data.deleted ?? 0;
        }
        return { written, deleted };
    }

    /**
     * Provision a user with no credentials yet (e.g. a relative you set up
     * for code sign-in). Store the returned id against their phone/email —
     * AuthGravity never sees either.
     */
    async createUser(): Promise<{ userId: string }> {
        const res = await this.post('/v1/users', {}, undefined, true);
        if (!res.ok) throw new Error(`create user failed (${res.status}): ${await res.text()}`);
        const data = (await res.json()) as { user_id: string };
        return { userId: data.user_id };
    }

    /**
     * Mint a 6-digit sign-in code for a ticket the person's browser started
     * (`startCodeLogin` in @authgravity/browser). Deliver the code yourself
     * (voice call, email); it only works in that browser, for 10 minutes.
     * Calling again for the same ticket is a resend (replaces the code).
     */
    async mintCode(args: { ticket: string; userId: string }): Promise<{ code: string; expiresAt: number }> {
        const res = await this.post('/v1/code/mint', { ticket: args.ticket, user_id: args.userId }, undefined, true);
        if (!res.ok) throw new Error(`mint code failed (${res.status}): ${await res.text()}`);
        const data = (await res.json()) as { code: string; expires_at: number };
        return { code: data.code, expiresAt: data.expires_at };
    }
}

export function authgravity<S extends SchemaShape = AnySchema>(config: AuthgravityConfig): AuthgravityServer<S> {
    return new AuthgravityServer<S>(config);
}

// --- Tuple builders ---

/** A user subject from an AuthGravity UUID (uuids need no escaping). */
export function user(id: string): string {
    return `user:${id}`;
}

export function touch(object: string, relation: string, subject: string): RelUpdate {
    return { op: 'touch', object, relation, subject };
}
export function create(object: string, relation: string, subject: string): RelUpdate {
    return { op: 'create', object, relation, subject };
}
export function del(object: string, relation: string, subject: string): RelUpdate {
    return { op: 'delete', object, relation, subject };
}
