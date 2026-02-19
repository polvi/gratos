// @ts-ignore
import { Buffer } from 'node:buffer';

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
        .prepare('SELECT * FROM public_keys WHERE user_id = ? AND tenant = ?')
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

export async function saveCredential(
    db: D1Database,
    tenant: string,
    userId: string,
    verification: any,
    clientCredentialID: string
) {
    const { registrationInfo } = verification;
    const { credentialBackedUp, credential } = registrationInfo;
    const credentialPublicKey = credential.publicKey;

    const id = crypto.randomUUID();

    await db
        .prepare(
            `INSERT INTO public_keys (id, user_id, tenant, credential_id, public_key, user_backed_up, transports)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
            id,
            userId,
            tenant,
            clientCredentialID,
            Buffer.from(credentialPublicKey).toString('base64'),
            credentialBackedUp ? 1 : 0,
            ''
        )
        .run();
}
