// Per-tenant Ed25519 signing keys for the Person Server. Lazily generated on
// first use; private halves are AES-256-GCM-wrapped with a KEK derived from
// the PS_KEK wrangler secret so a D1 export alone yields nothing usable. When
// PS_KEK is unset (local dev, CI) a fixed well-known dev KEK keeps
// clone-and-dev zero-setup; kek_id records which KEK wrapped each row so a
// rotated/newly-set secret retires old rows instead of failing to unwrap.

import { b64u, b64uDecode, sha256, sha256B64u } from './encoding';

/** How long retired public keys stay in the JWKS (must exceed max token life). */
const RETIRED_JWKS_WINDOW_MS = 60 * 60 * 1000;

// Well-known dev KEK material. NOT a secret — it only exists so local dev
// works without provisioning; production sets PS_KEK.
const DEV_KEK_INPUT = 'authgravity-dev-kek-not-a-secret';

export type PublicJwk = { kty: 'OKP'; crv: 'Ed25519'; x: string; kid?: string; alg?: string; use?: string };

export type SigningKey = {
    kid: string;
    privateKey: CryptoKey;
    publicJwk: PublicJwk;
};

type PsKeyRow = {
    kid: string;
    public_jwk: string;
    private_wrapped: string;
    kek_id: string;
    created_at: number;
    retired_at: number | null;
};

async function kekFor(secret: string | undefined): Promise<{ kekId: string; key: CryptoKey }> {
    const input = secret || DEV_KEK_INPUT;
    const bytes = await sha256(new TextEncoder().encode(input));
    const kekId = secret ? b64u(bytes).slice(0, 8) : 'dev';
    const key = await crypto.subtle.importKey('raw', bytes as BufferSource, { name: 'AES-GCM' }, false, [
        'encrypt',
        'decrypt',
    ]);
    return { kekId, key };
}

/** RFC 7638 JWK thumbprint (OKP): sha256 over the canonical member subset. */
export async function jwkThumbprint(jwk: { crv: string; kty: string; x: string }): Promise<string> {
    const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
    return sha256B64u(canonical);
}

async function wrapPrivate(kek: CryptoKey, pkcs8: Uint8Array): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, kek, pkcs8 as BufferSource)
    );
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv, 0);
    out.set(ct, iv.length);
    return b64u(out);
}

async function unwrapPrivate(kek: CryptoKey, wrapped: string): Promise<CryptoKey> {
    const bytes = b64uDecode(wrapped);
    const iv = bytes.slice(0, 12);
    const ct = bytes.slice(12);
    const pkcs8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, kek, ct as BufferSource);
    return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
}

async function generateKey(
    db: D1Database,
    tenant: string,
    kekId: string,
    kek: CryptoKey
): Promise<{ kid: string; publicJwk: PublicJwk; privateKey: CryptoKey }> {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as PublicJwk;
    const jwk: PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x };
    const kid = await jwkThumbprint(jwk);
    const pkcs8 = new Uint8Array((await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as ArrayBuffer);
    const wrapped = await wrapPrivate(kek, pkcs8);
    // INSERT OR IGNORE: the one-active-key-per-tenant partial unique index
    // turns a concurrent same-tenant generate into a no-op; the caller
    // re-selects and converges on whichever row won.
    await db
        .prepare(
            'INSERT OR IGNORE INTO ps_keys (kid, tenant, public_jwk, private_wrapped, kek_id, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        )
        .bind(kid, tenant, JSON.stringify(jwk), wrapped, kekId, Date.now())
        .run();
    return { kid, publicJwk: jwk, privateKey: pair.privateKey };
}

/**
 * The tenant's current signing key, generating one on first use. Concurrent
 * first-use races are serialized by the one-active-key-per-tenant unique
 * index (the losing INSERT is ignored); every caller also deterministically
 * resolves to the OLDEST active row, so all instances converge on the same
 * signer even for pre-index rows. Rows wrapped under a different KEK (secret
 * was set/rotated) are retired and a fresh key is generated.
 */
export async function getSigningKey(db: D1Database, env: { PS_KEK?: string }, tenant: string): Promise<SigningKey> {
    const { kekId, key: kek } = await kekFor(env.PS_KEK);

    const { results } = await db
        .prepare('SELECT * FROM ps_keys WHERE tenant = ? AND retired_at IS NULL ORDER BY created_at ASC, kid ASC')
        .bind(tenant)
        .all();

    for (const row of (results || []) as PsKeyRow[]) {
        if (row.kek_id !== kekId) {
            await db.prepare('UPDATE ps_keys SET retired_at = ? WHERE kid = ?').bind(Date.now(), row.kid).run();
            continue;
        }
        const privateKey = await unwrapPrivate(kek, row.private_wrapped);
        return { kid: row.kid, privateKey, publicJwk: JSON.parse(row.public_jwk) as PublicJwk };
    }

    const fresh = await generateKey(db, tenant, kekId, kek);
    // Re-select in case a concurrent request won the insert race.
    const row = (await db
        .prepare('SELECT * FROM ps_keys WHERE tenant = ? AND retired_at IS NULL ORDER BY created_at ASC, kid ASC')
        .bind(tenant)
        .first()) as PsKeyRow | null;
    if (row && row.kid !== fresh.kid && row.kek_id === kekId) {
        const privateKey = await unwrapPrivate(kek, row.private_wrapped);
        return { kid: row.kid, privateKey, publicJwk: JSON.parse(row.public_jwk) as PublicJwk };
    }
    return fresh;
}

/**
 * JWKS for discovery reads: when the tenant has no key yet and the caller
 * allows it, provision one so backfilled/idle tenants never advertise an
 * empty key set. `allowMint` is the caller's tenant-existence guard —
 * sandbox ids are attacker-chosen path segments, so an unauthenticated GET
 * must not insert rows for sandboxes that don't exist (domain hosts only
 * route when a custom hostname is provisioned, so they always allow).
 */
export async function ensureTenantJwks(
    db: D1Database,
    env: { PS_KEK?: string },
    tenant: string,
    allowMint: boolean
): Promise<{ keys: PublicJwk[] }> {
    const jwks = await getTenantJwks(db, tenant);
    if (jwks.keys.length > 0 || !allowMint) return jwks;
    await getSigningKey(db, env, tenant);
    return getTenantJwks(db, tenant);
}

/**
 * Public JWKS for a tenant: active keys plus recently-retired ones (so
 * rotation never invalidates live tokens). Public halves only — no KEK needed.
 */
export async function getTenantJwks(db: D1Database, tenant: string): Promise<{ keys: PublicJwk[] }> {
    const cutoff = Date.now() - RETIRED_JWKS_WINDOW_MS;
    const { results } = await db
        .prepare(
            'SELECT kid, public_jwk FROM ps_keys WHERE tenant = ? AND (retired_at IS NULL OR retired_at > ?) ORDER BY created_at ASC'
        )
        .bind(tenant, cutoff)
        .all();
    const keys = ((results || []) as Array<{ kid: string; public_jwk: string }>).map((r) => ({
        ...(JSON.parse(r.public_jwk) as PublicJwk),
        kid: r.kid,
        alg: 'EdDSA',
        use: 'sig',
    }));
    return { keys };
}
