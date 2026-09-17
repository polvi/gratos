// Session storage. Values are JSON `{"u": userId, "amr": method, "c": credId}`
// so callers can distinguish how the session was established (webauthn
// passkey, account key, or silent device key) and WHICH credential row minted
// it (so a credential list can mark "signed in with this"). Legacy sessions
// stored the bare userId string — parse both shapes; legacy implies webauthn.

export const SESSION_TTL = 604800; // 7 days

/** How the session was authenticated, strongest first. */
export type Amr = 'webauthn' | 'device' | 'key';

export const AMR_RANK: Record<Amr, number> = { webauthn: 3, device: 2, key: 1 };

export type SessionInfo = { userId: string; amr: Amr; credentialId?: string };

export async function mintSession(
    kv: KVNamespace,
    tenant: string,
    userId: string,
    amr: Amr,
    credentialId?: string
): Promise<string> {
    const sessionId = crypto.randomUUID();
    const value: Record<string, string> = { u: userId, amr };
    if (credentialId) value.c = credentialId;
    await kv.put(`session:${tenant}:${sessionId}`, JSON.stringify(value), {
        expirationTtl: SESSION_TTL,
    });
    return sessionId;
}

export function parseSessionValue(value: string | null): SessionInfo | null {
    if (!value) return null;
    if (value.startsWith('{')) {
        try {
            const parsed = JSON.parse(value) as { u?: string; amr?: string; c?: string };
            if (typeof parsed.u !== 'string') return null;
            const amr: Amr = parsed.amr === 'device' || parsed.amr === 'key' ? parsed.amr : 'webauthn';
            const info: SessionInfo = { userId: parsed.u, amr };
            if (typeof parsed.c === 'string' && parsed.c) info.credentialId = parsed.c;
            return info;
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
