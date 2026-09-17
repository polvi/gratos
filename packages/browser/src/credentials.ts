// Credential management for a signed-in user: list every credential on the
// account (passkeys, device keys, recovery keys) and remove one. Adding a
// passkey is the ordinary registration ceremony run while signed in — see the
// llms.txt recipe — so there is nothing extra to wrap here.

export type CredentialKind = 'webauthn' | 'devicekey' | 'softkey';

export interface Credential {
    /** Row id — the value DELETE /v1/credentials/:id takes. */
    id: string;
    kind: CredentialKind;
    /** Owner-supplied name (`?label=` on register options, or the key label). */
    label: string | null;
    /** Passkey provider derived from the authenticator AAGUID (e.g. "iCloud Keychain"). */
    provider: string | null;
    /** What to show: label, else provider, else a kind default. */
    display: string;
    /** Multi-device (synced) passkey; null for keys. */
    backed_up: boolean | null;
    transports: string[];
    created_at: number | null;
    last_used_at: number | null;
    /** True for the credential that established the current session. */
    current: boolean;
}

export interface CredentialList {
    /** How the current session authenticated. */
    amr: 'webauthn' | 'device' | 'key';
    credentials: Credential[];
}

/** List the signed-in user's credentials; null when there is no session (401). */
export async function listCredentials(endpoint: string): Promise<CredentialList | null> {
    const res = await fetch(`${endpoint}/v1/credentials`, { credentials: 'include' });
    if (res.status === 401) return null;
    if (!res.ok) throw new Error(`list credentials failed (${res.status})`);
    return (await res.json()) as CredentialList;
}

export interface RemoveResult {
    ok: boolean;
    status: number;
    /** Server message on failure: 403 (session outranked), 409 (last credential), 404. */
    error?: string;
}

/** Remove one credential by row id. Never throws on a server refusal. */
export async function removeCredential(endpoint: string, id: string): Promise<RemoveResult> {
    const res = await fetch(`${endpoint}/v1/credentials/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'include',
    });
    if (res.ok) return { ok: true, status: res.status };
    let error: string | undefined;
    try {
        error = ((await res.json()) as { error?: string }).error;
    } catch {
        // non-JSON body
    }
    return { ok: false, status: res.status, error };
}
