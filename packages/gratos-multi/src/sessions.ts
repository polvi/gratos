// Session storage. Values are JSON `{"u": userId, "amr": method}` so callers
// can distinguish how the session was established (webauthn passkey, account
// key, or silent device key). Legacy sessions stored the bare userId string —
// parse both shapes; legacy implies webauthn.

export const SESSION_TTL = 604800; // 7 days

/** How the session was authenticated, strongest first. */
export type Amr = 'webauthn' | 'device' | 'key';

export const AMR_RANK: Record<Amr, number> = { webauthn: 3, device: 2, key: 1 };

export type SessionInfo = { userId: string; amr: Amr };

export async function mintSession(
    kv: KVNamespace,
    tenant: string,
    userId: string,
    amr: Amr
): Promise<string> {
    const sessionId = crypto.randomUUID();
    await kv.put(`session:${tenant}:${sessionId}`, JSON.stringify({ u: userId, amr }), {
        expirationTtl: SESSION_TTL,
    });
    return sessionId;
}

export function parseSessionValue(value: string | null): SessionInfo | null {
    if (!value) return null;
    if (value.startsWith('{')) {
        try {
            const parsed = JSON.parse(value) as { u?: string; amr?: string };
            if (typeof parsed.u !== 'string') return null;
            const amr: Amr = parsed.amr === 'device' || parsed.amr === 'key' ? parsed.amr : 'webauthn';
            return { userId: parsed.u, amr };
        } catch {
            return null;
        }
    }
    // Legacy shape: the bare userId. All legacy sessions were passkey-minted.
    return { userId: value, amr: 'webauthn' };
}

export async function resolveSession(
    kv: KVNamespace,
    tenant: string,
    sessionId: string
): Promise<SessionInfo | null> {
    return parseSessionValue(await kv.get(`session:${tenant}:${sessionId}`));
}
