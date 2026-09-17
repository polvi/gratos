// Outbound JWKS discovery for agent / resource issuers, per the httpsig-keys
// pattern: keys live at `{iss}/.well-known/{dwk}`. Trust is OPEN (no issuer
// allowlist — seam §5: an attestation/agent identity only sets caps and proves
// consent; no money moves without a funded claim), but fetches are guarded:
// https-only (http for localhost dev), no literal IPs or internal-looking
// hostnames, 5s timeout, 64KB cap. Cached in KV ~5m with serve-stale-on-error.

import { AAuthError, sha256B64u } from './encoding';

const FRESH_MS = 5 * 60 * 1000;
const MAX_BYTES = 64 * 1024;
const KV_TTL_S = 24 * 60 * 60; // stale copies stay available for serve-on-error

export type RemoteJwk = { kty: string; crv?: string; x?: string; kid?: string; alg?: string };

type CacheEntry = { at: number; keys: RemoteJwk[] };

/**
 * Seam §8: every verifier MUST accept all three JWKS document shapes —
 * top-level `{"keys":[...]}`, nested `{"jwks":{"keys":[...]}}` (tokenpony's
 * resource doc), or a doc carrying only `jwks_uri` (followed once, no loops —
 * tokenpony's `jwks_uri` points back at the same document).
 */
function extractKeys(doc: unknown): RemoteJwk[] | null {
    const d = doc as { keys?: unknown; jwks?: { keys?: unknown } } | null;
    if (Array.isArray(d?.keys)) return d.keys as RemoteJwk[];
    if (Array.isArray(d?.jwks?.keys)) return d.jwks.keys as RemoteJwk[];
    return null;
}

function isDevHost(hostname: string): boolean {
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.localhost');
}

/** Validate an issuer URL for outbound fetching. Throws AAuthError. */
export function checkOutboundUrl(raw: string): URL {
    let u: URL;
    try {
        u = new URL(raw);
    } catch {
        throw new AAuthError('invalid_token', `not a valid URL: ${raw}`, 401);
    }
    const dev = isDevHost(u.hostname);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && dev)) {
        throw new AAuthError('invalid_token', 'issuer must be https', 401);
    }
    const host = u.hostname;
    // Literal IPs and internal-looking names are refused (SSRF guard); dev
    // localhost is the one exception.
    const isV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const isV6 = host.includes(':') || host.startsWith('[');
    if (!dev && (isV4 || isV6 || host.endsWith('.internal') || host.endsWith('.local'))) {
        throw new AAuthError('invalid_token', 'issuer host not allowed', 401);
    }
    return u;
}

/**
 * Fetch `{iss}/.well-known/{dwk}` with caching. Fresh within ~5m; on refresh
 * failure the last-good copy is served (seam §8 serve-stale-on-error).
 */
export async function fetchIssuerJwks(kv: KVNamespace, iss: string, dwk: string): Promise<RemoteJwk[]> {
    const base = checkOutboundUrl(iss);
    const url = new URL(base.toString().replace(/\/$/, '') + '/.well-known/' + dwk);

    const cacheKey = `aauth_jwks:${await sha256B64u(iss + '/' + dwk)}`;
    const cached = (await kv.get(cacheKey, 'json')) as CacheEntry | null;
    if (cached && Date.now() - cached.at < FRESH_MS) return cached.keys;

    try {
        const fetchDoc = async (u: string): Promise<unknown> => {
            const res = await fetch(u, {
                signal: AbortSignal.timeout(5000),
                headers: { Accept: 'application/json' },
            });
            if (!res.ok) throw new Error(`jwks fetch ${res.status}`);
            const text = await res.text();
            if (text.length > MAX_BYTES) throw new Error('jwks too large');
            return JSON.parse(text);
        };

        const doc = await fetchDoc(url.toString());
        let keys = extractKeys(doc);
        if (!keys) {
            // jwks_uri-only doc: follow it exactly once (never recursively).
            const jwksUri = (doc as { jwks_uri?: unknown } | null)?.jwks_uri;
            if (typeof jwksUri === 'string' && jwksUri !== url.toString()) {
                checkOutboundUrl(jwksUri);
                keys = extractKeys(await fetchDoc(jwksUri));
            }
        }
        if (!keys) throw new Error('jwks missing keys');
        const entry: CacheEntry = { at: Date.now(), keys };
        await kv.put(cacheKey, JSON.stringify(entry), { expirationTtl: KV_TTL_S });
        return entry.keys;
    } catch (e) {
        if (e instanceof AAuthError && !cached) throw e;
        if (cached) return cached.keys; // serve stale
        throw new AAuthError('invalid_token', `could not fetch keys for ${iss}`, 401);
    }
}
