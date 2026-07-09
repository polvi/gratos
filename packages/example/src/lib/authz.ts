// Thin glue over @authgravity/server. The app writes NO auth UI — users sign in
// on the hosted surfaces (see middleware.ts) — and uses AuthGravity only for the
// session check and per-resource authorization.

import { authgravity, objectRef, touch, user } from '@authgravity/server';

export interface RuntimeEnv {
    PUBLIC_AUTH_ENDPOINT: string;
    /** Set in prod (owner-managed tenant). Optional in an open sandbox. */
    AUTHZ_SERVICE_TOKEN?: string;
    NOTES: KVNamespace;
}

export { objectRef, touch, user };

/** Resolve the signed-in user id by forwarding the session cookie to /v1/whoami. */
export async function whoami(request: Request, env: RuntimeEnv): Promise<string | null> {
    const cookie = request.headers.get('cookie');
    const res = await fetch(`${env.PUBLIC_AUTH_ENDPOINT}/v1/whoami`, {
        headers: cookie ? { cookie } : {},
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { user_id?: string };
    return data.user_id ?? null;
}

export function authzClient(env: RuntimeEnv) {
    return authgravity({ endpoint: env.PUBLIC_AUTH_ENDPOINT, serviceToken: env.AUTHZ_SERVICE_TOKEN });
}

/**
 * Write relationship tuples. In production (owner-managed tenant) this uses the
 * app's service token; in an open sandbox there's no token, so we fall back to
 * the caller's session (any pool user may write) — keeping the example runnable
 * against `authgravity listen` with zero setup.
 */
export async function writeTuples(
    request: Request,
    env: RuntimeEnv,
    updates: Array<{ op: string; object: string; relation: string; subject: string }>
): Promise<void> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (env.AUTHZ_SERVICE_TOKEN) {
        headers.Authorization = `Bearer ${env.AUTHZ_SERVICE_TOKEN}`;
    } else {
        const cookie = request.headers.get('cookie');
        if (cookie) headers.cookie = cookie;
    }
    const res = await fetch(`${env.PUBLIC_AUTH_ENDPOINT}/v1/authz/relationships`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ updates }),
    });
    if (!res.ok) throw new Error(`authz write failed (${res.status}): ${await res.text()}`);
}
