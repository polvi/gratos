// Durable "remember this approval" consent grants: (agent identity, resource)
// → user + scope set. A matching unexpired grant lets the token endpoint
// auto-issue without a fresh consent round-trip.

const GRANT_TTL_MS = 90 * 24 * 60 * 60 * 1000;

export type GrantRow = {
    id: string;
    tenant: string;
    user_id: string;
    agent_iss: string;
    agent_sub: string;
    resource: string;
    scope: string;
    created_at: number;
    last_used_at: number | null;
    expires_at: number | null;
    revoked_at: number | null;
};

/** Space-separated scope → deduped, sorted canonical form. */
export function normalizeScope(scope: string | undefined): string {
    if (!scope) return '';
    return [...new Set(scope.split(/\s+/).filter(Boolean))].sort().join(' ');
}

/** True when every requested scope value is in the granted set. */
export function scopeCovered(requested: string | undefined, granted: string): boolean {
    const grantedSet = new Set(granted.split(' ').filter(Boolean));
    return normalizeScope(requested)
        .split(' ')
        .filter(Boolean)
        .every((s) => grantedSet.has(s));
}

export async function findGrant(
    db: D1Database,
    tenant: string,
    agentIss: string,
    agentSub: string,
    resource: string
): Promise<GrantRow | null> {
    const row = (await db
        .prepare(
            'SELECT * FROM aauth_grants WHERE tenant = ? AND agent_iss = ? AND agent_sub = ? AND resource = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)'
        )
        .bind(tenant, agentIss, agentSub, resource, Date.now())
        .first()) as GrantRow | null;
    return row;
}

export async function touchGrant(db: D1Database, id: string): Promise<void> {
    await db.prepare('UPDATE aauth_grants SET last_used_at = ? WHERE id = ?').bind(Date.now(), id).run();
}

export async function upsertGrant(
    db: D1Database,
    tenant: string,
    userId: string,
    agentIss: string,
    agentSub: string,
    resource: string,
    scope: string
): Promise<void> {
    const now = Date.now();
    await db
        .prepare(
            `INSERT INTO aauth_grants (id, tenant, user_id, agent_iss, agent_sub, resource, scope, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(tenant, agent_iss, agent_sub, resource) DO UPDATE SET
               user_id = excluded.user_id, scope = excluded.scope,
               expires_at = excluded.expires_at, revoked_at = NULL`
        )
        .bind(crypto.randomUUID(), tenant, userId, agentIss, agentSub, resource, normalizeScope(scope), now, now + GRANT_TTL_MS)
        .run();
}

export async function listGrants(db: D1Database, tenant: string, userId: string): Promise<GrantRow[]> {
    const { results } = await db
        .prepare(
            'SELECT * FROM aauth_grants WHERE tenant = ? AND user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC'
        )
        .bind(tenant, userId)
        .all();
    return (results || []) as GrantRow[];
}

export async function revokeGrant(db: D1Database, tenant: string, userId: string, id: string): Promise<boolean> {
    const res = await db
        .prepare('UPDATE aauth_grants SET revoked_at = ? WHERE tenant = ? AND user_id = ? AND id = ? AND revoked_at IS NULL')
        .bind(Date.now(), tenant, userId, id)
        .run();
    return (res.meta?.changes ?? 0) > 0;
}
