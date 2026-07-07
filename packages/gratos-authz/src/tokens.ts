// Per-tenant service tokens. The tenant's application backend holds one as a
// secret and sends it as `Authorization: Bearer agk_...` to the tenant-host
// authz API, which grants relationship writes, reads, and checks for that
// tenant only (schema changes stay owner-only). Minted and revoked by the
// tenant owner through the on-behalf API; only SHA-256 hashes are stored.

export const TOKEN_PREFIX = 'agk_';

// Throttle last_used_at writes to at most one per hour per token.
const LAST_USED_THROTTLE_MS = 60 * 60 * 1000;

export function isServiceToken(bearer: string): boolean {
    return bearer.startsWith(TOKEN_PREFIX);
}

export function generateTokenSecret(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    // base64url, no padding
    return TOKEN_PREFIX + btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function hashToken(secret: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export type TokenRow = { id: string; name: string; created_at: number; last_used_at: number | null };

export async function mintToken(
    db: D1Database,
    tenant: string,
    name: string
): Promise<{ id: string; name: string; token: string; created_at: number }> {
    const secret = generateTokenSecret();
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    await db
        .prepare('INSERT INTO service_tokens (id, tenant, name, token_hash, created_at) VALUES (?, ?, ?, ?, ?)')
        .bind(id, tenant, name, await hashToken(secret), createdAt)
        .run();
    return { id, name, token: secret, created_at: createdAt };
}

export async function listTokens(db: D1Database, tenant: string): Promise<TokenRow[]> {
    const { results } = await db
        .prepare('SELECT id, name, created_at, last_used_at FROM service_tokens WHERE tenant = ? ORDER BY created_at')
        .bind(tenant)
        .all<TokenRow>();
    return results ?? [];
}

export async function revokeToken(db: D1Database, tenant: string, id: string): Promise<boolean> {
    const result = await db
        .prepare('DELETE FROM service_tokens WHERE tenant = ? AND id = ?')
        .bind(tenant, id)
        .run();
    return (result.meta?.changes ?? 0) > 0;
}

/**
 * Verify a bearer secret against the tenant's tokens. The tenant scoping is
 * the security boundary: a token minted for tenant A never authorizes tenant B.
 * Returns a best-effort last_used_at updater for the caller to waitUntil.
 */
export async function verifyToken(
    db: D1Database,
    tenant: string,
    secret: string
): Promise<{ id: string; touch: () => Promise<void> } | null> {
    const row = await db
        .prepare('SELECT id, last_used_at FROM service_tokens WHERE tenant = ? AND token_hash = ?')
        .bind(tenant, await hashToken(secret))
        .first<{ id: string; last_used_at: number | null }>();
    if (!row) return null;
    const now = Date.now();
    const touch = async () => {
        if (row.last_used_at && now - row.last_used_at < LAST_USED_THROTTLE_MS) return;
        try {
            await db
                .prepare('UPDATE service_tokens SET last_used_at = ? WHERE id = ?')
                .bind(now, row.id)
                .run();
        } catch {
            // telemetry only
        }
    };
    return { id: row.id, touch };
}
