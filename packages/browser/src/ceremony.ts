// The shared key-ceremony transport. GET options → sign the
// `${context}\n${challenge}\n${tenant}` payload → POST verify. `credentials:
// 'include'` so the server can set the first-party session cookie; sandbox
// endpoints additionally return session_id in the body.

import { b64u } from './crypto';

export interface CeremonyResult {
    ok: boolean;
    status: number;
    data: any;
}

/** Produces the public key + signature for a payload; tenant comes from options. */
export type Signer = (
    payload: string,
    tenant: string
) => Promise<{ publicKey: Uint8Array; signature: Uint8Array }>;

export async function runCeremony(
    endpoint: string,
    phase: 'register' | 'login',
    sign: Signer,
    extra: Record<string, unknown> = {}
): Promise<CeremonyResult> {
    const optRes = await fetch(`${endpoint}/v1/key/${phase}/options`, { credentials: 'include' });
    if (!optRes.ok) throw new Error(`key ${phase} options failed (${optRes.status})`);
    const opts = (await optRes.json()) as { challenge: string; context: string; tenant: string };

    const payload = `${opts.context}\n${opts.challenge}\n${opts.tenant}`;
    const { publicKey, signature } = await sign(payload, opts.tenant);

    const verRes = await fetch(`${endpoint}/v1/key/${phase}/verify`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            challenge: opts.challenge,
            public_key: b64u(publicKey),
            signature: b64u(signature),
            ...extra,
        }),
    });

    let data: any = {};
    try {
        data = await verRes.json();
    } catch {
        // non-JSON body
    }
    return { ok: verRes.ok, status: verRes.status, data };
}
