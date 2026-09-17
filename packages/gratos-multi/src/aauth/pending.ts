// Short-lived pending consent state in KV: token / permission / interaction
// kinds live 600s (an interactive round-trip). Mission proposals do NOT live
// here — they are D1-backed on the aauth_missions row so consent can wait days
// (asynchronous, possibly third-party approval).

import { sha256B64u } from './encoding';

export const PENDING_TTL_S = 600;

/** Crockford base32 without 0/O/1/I — 8 chars, ~40 bits. */
const CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateCode(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    let code = '';
    for (const b of bytes) code += CODE_ALPHABET[b % CODE_ALPHABET.length];
    return code;
}

export type PendingKind = 'token' | 'permission' | 'interaction';

export type ChatEntry = { from: 'user' | 'agent'; text: string; at: number };

export type PendingRecord = {
    kind: PendingKind;
    st: 'pending' | 'approved' | 'denied';
    agent: { iss: string; sub: string; jwk: { kty: string; crv: string; x: string } };
    /** Kind-specific payload (token: resource/scope/justification; permission: action/...; interaction: type/...). */
    payload: Record<string, unknown>;
    chat: ChatEntry[];
    /** Set when resolved: the response body the agent's poll should receive. */
    result?: Record<string, unknown>;
    createdAt: number;
};

const pendingKey = (tenant: string, id: string) => `aauth_pending:${tenant}:${id}`;
const codeKey = async (tenant: string, code: string) =>
    `aauth_code:${tenant}:${await sha256B64u(code.toUpperCase())}`;

export async function createPending(
    kv: KVNamespace,
    tenant: string,
    record: Omit<PendingRecord, 'chat' | 'createdAt' | 'st'>
): Promise<{ id: string; code: string }> {
    const id = crypto.randomUUID();
    const code = generateCode();
    const full: PendingRecord = { ...record, st: 'pending', chat: [], createdAt: Date.now() };
    await kv.put(pendingKey(tenant, id), JSON.stringify(full), { expirationTtl: PENDING_TTL_S });
    await kv.put(await codeKey(tenant, code), id, { expirationTtl: PENDING_TTL_S });
    return { id, code };
}

export async function getPending(kv: KVNamespace, tenant: string, id: string): Promise<PendingRecord | null> {
    return (await kv.get(pendingKey(tenant, id), 'json')) as PendingRecord | null;
}

/** Overwrite a pending record (keeps a fresh TTL — the flow is near its end). */
export async function putPending(kv: KVNamespace, tenant: string, id: string, record: PendingRecord): Promise<void> {
    await kv.put(pendingKey(tenant, id), JSON.stringify(record), { expirationTtl: PENDING_TTL_S });
}

export async function deletePending(kv: KVNamespace, tenant: string, id: string): Promise<void> {
    await kv.delete(pendingKey(tenant, id));
}

export async function getPendingIdByCode(kv: KVNamespace, tenant: string, code: string): Promise<string | null> {
    return kv.get(await codeKey(tenant, code));
}

/** Single-use: remove the code → pending mapping. */
export async function consumeCode(kv: KVNamespace, tenant: string, code: string): Promise<void> {
    await kv.delete(await codeKey(tenant, code));
}
