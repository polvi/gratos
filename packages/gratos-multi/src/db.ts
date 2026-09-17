// @ts-ignore
import { Buffer } from 'node:buffer';

/** Hard cap on credentials (passkeys + keys) per account, every kind combined. */
export const MAX_CREDENTIALS_PER_USER = 10;

export async function getUser(db: D1Database, tenant: string, id: string) {
    return await db
        .prepare('SELECT * FROM users WHERE id = ? AND tenant = ?')
        .bind(id, tenant)
        .first();
}

export async function createUser(db: D1Database, tenant: string, id: string) {
    await db
        .prepare('INSERT INTO users (id, tenant) VALUES (?, ?)')
        .bind(id, tenant)
        .run();
}

export async function getUserCredentials(db: D1Database, tenant: string, userId: string): Promise<any[]> {
    const { results } = await db
        .prepare('SELECT * FROM public_keys WHERE user_id = ? AND tenant = ? ORDER BY created_at, id')
        .bind(userId, tenant)
        .all();
    return results || [];
}

export async function getCredentialById(db: D1Database, tenant: string, credentialId: string) {
    return await db
        .prepare('SELECT * FROM public_keys WHERE tenant = ? AND credential_id = ?')
        .bind(tenant, credentialId)
        .first();
}

export type PasskeyMeta = {
    label: string | null;
    aaguid: string | null;
    transports: string[];
    counter: number;
};

/** Store a WebAuthn credential; returns the new row id. */
export async function saveCredential(
    db: D1Database,
    tenant: string,
    userId: string,
    verification: any,
    clientCredentialID: string,
    meta: PasskeyMeta
): Promise<string> {
    const { registrationInfo } = verification;
    const { credentialBackedUp, credential } = registrationInfo;
    const credentialPublicKey = credential.publicKey;

    const id = crypto.randomUUID();

    await db
        .prepare(
            `INSERT INTO public_keys (id, user_id, tenant, credential_id, public_key, user_backed_up, transports, kind, label, aaguid, counter, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'webauthn', ?, ?, ?, ?)`
        )
        .bind(
            id,
            userId,
            tenant,
            clientCredentialID,
            Buffer.from(credentialPublicKey).toString('base64'),
            credentialBackedUp ? 1 : 0,
            meta.transports.join(','),
            meta.label,
            meta.aaguid,
            meta.counter,
            Date.now()
        )
        .run();
    return id;
}

/** Store a software-key credential (account key or device key); returns the row id. */
export async function saveKeyCredential(
    db: D1Database,
    tenant: string,
    userId: string,
    credentialId: string,
    publicKeyB64u: string,
    kind: 'softkey' | 'devicekey',
    label: string | null
): Promise<string> {
    const id = crypto.randomUUID();
    await db
        .prepare(
            `INSERT INTO public_keys (id, user_id, tenant, credential_id, public_key, user_backed_up, transports, kind, label, created_at)
             VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?)`
        )
        .bind(id, userId, tenant, credentialId, publicKeyB64u, kind, label, Date.now())
        .run();
    return id;
}

export async function countCredentials(db: D1Database, tenant: string, userId: string): Promise<number> {
    const row = await db
        .prepare('SELECT COUNT(*) AS n FROM public_keys WHERE tenant = ? AND user_id = ?')
        .bind(tenant, userId)
        .first<{ n: number }>();
    return row?.n ?? 0;
}

export async function touchCredential(db: D1Database, rowId: string) {
    try {
        await db.prepare('UPDATE public_keys SET last_used_at = ? WHERE id = ?').bind(Date.now(), rowId).run();
    } catch {
        // telemetry only
    }
}

/** Passkey login bookkeeping: bump the signature counter and last_used_at together. */
export async function updateCredentialUse(db: D1Database, rowId: string, counter: number) {
    try {
        await db
            .prepare('UPDATE public_keys SET last_used_at = ?, counter = ? WHERE id = ?')
            .bind(Date.now(), counter, rowId)
            .run();
    } catch {
        // older deployments without the counter column: keep last_used_at at least
        await touchCredential(db, rowId);
    }
}

/** Parse the stored comma-separated transports list. */
export function parseTransports(value: unknown): string[] {
    if (typeof value !== 'string' || !value) return [];
    return value.split(',').filter(Boolean);
}
