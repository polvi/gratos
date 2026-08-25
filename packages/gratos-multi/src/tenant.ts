export type TenantInfo = {
    tenant: string;
    rpId: string;
    /** Human-readable name shown in the passkey dialog (WebAuthn rp.name). */
    rpName: string;
    cookieDomain: string;
    origin: string;
    /** True for ephemeral sandbox tenants (rpId=localhost, Bearer sessions). */
    sandbox?: boolean;
    /** The sandbox id (first path segment) for path-based sandbox tenants. */
    sandboxId?: string;
    /** The path prefix to strip before dispatching sandbox routes, e.g. "/abc123". */
    sandboxPrefix?: string;
};

/**
 * Hosts that serve instant sandbox tenants. A single Workers custom domain
 * (auto-certified, no ACM/wildcard) hosts every sandbox; the sandbox id lives in
 * the FIRST PATH SEGMENT: e.g. https://sandbox.authgravity.org/<id>/v1/register/options.
 * Each id is its own isolated user pool (tenant = "<host>/<id>"), with rpId pinned
 * to "localhost" so the passkey ceremony runs inline in a developer's local app.
 * "sandbox.localhost" is the dev-mode equivalent (*.localhost resolves to 127.0.0.1).
 */
export const SANDBOX_HOSTS = ['sandbox.authgravity.org', 'sandbox.localhost'];

// Registrable-hostname shape for a custom sandbox RP ID (lowercase labels, no
// port, no path). Effective-TLD checks are the browser's job; ours is only to
// keep out junk and AuthGravity's own domains.
const RP_ID_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RESERVED_RP_SUFFIXES = ['authgravity.org'];

/**
 * Validate a caller-supplied sandbox RP ID. Sandboxes default to rpId=localhost;
 * a custom one lets the ceremony run on a real hostname (e.g. a tailnet HTTPS
 * proxy). AuthGravity's own domains are refused so a throwaway sandbox can
 * never mint passkeys scoped to the real product RP.
 */
export function validateSandboxRpId(input: unknown): string | null {
    if (typeof input !== 'string') return null;
    const rpId = input.trim().toLowerCase();
    if (!RP_ID_RE.test(rpId)) return null;
    if (RESERVED_RP_SUFFIXES.some((d) => rpId === d || rpId.endsWith('.' + d))) return null;
    return rpId;
}

/** Is `host` the sandbox's RP ID or one of its subdomains? */
export function hostMatchesRpId(host: string, rpId: string): boolean {
    return host === rpId || host.endsWith('.' + rpId);
}

/** Apply a stored custom RP ID to a resolved sandbox tenant. */
export function withSandboxRpId(info: TenantInfo, rpId: string | null | undefined): TenantInfo {
    if (!info.sandbox || !rpId) return info;
    return { ...info, rpId };
}

/**
 * Passkey display name (WebAuthn rp.name). AuthGravity-owned surfaces (the
 * product's own pool, sandboxes, local dev) show "AuthGravity"; customer
 * domains show their own domain — the product is white-label first-party auth.
 */
function rpNameFor(tenant: string): string {
    if (tenant === 'authgravity.org' || tenant === 'localhost') return 'AuthGravity';
    return tenant;
}

/**
 * Derive tenant info from the request hostname.
 * e.g. "authgravity.example.com" → tenant="example.com", rpId="example.com",
 *      cookieDomain="example.com", origin="https://authgravity.example.com"
 *
 * For localhost development, tenant is "localhost".
 */
export function resolveTenant(url: URL): TenantInfo {
    const hostname = url.hostname;

    // Instant sandbox: "<host>/<id>" is the tenant (isolated pool per id), and
    // the WebAuthn RP is "localhost" so the ceremony works from a local app.
    if (SANDBOX_HOSTS.includes(hostname)) {
        const id = url.pathname.split('/').filter(Boolean)[0] || '';
        return {
            tenant: `${hostname}/${id}`,
            rpId: 'localhost',
            rpName: 'AuthGravity',
            cookieDomain: hostname, // unused in Bearer mode
            origin: url.origin,
            sandbox: true,
            sandboxId: id,
            sandboxPrefix: `/${id}`,
        };
    }

    // Localhost dev mode
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return {
            tenant: 'localhost',
            rpId: 'localhost',
            rpName: rpNameFor('localhost'),
            cookieDomain: 'localhost',
            origin: url.origin,
        };
    }

    // Extract parent domain: strip the first subdomain label
    const parts = hostname.split('.');
    if (parts.length <= 2) {
        // Already a root domain (e.g. "example.com") — use as-is
        return {
            tenant: hostname,
            rpId: hostname,
            rpName: rpNameFor(hostname),
            cookieDomain: hostname,
            origin: url.origin,
        };
    }

    // e.g. "authgravity.example.com" → "example.com"
    const tenant = parts.slice(1).join('.');
    return {
        tenant,
        rpId: tenant,
        rpName: rpNameFor(tenant),
        cookieDomain: tenant,
        origin: url.origin,
    };
}
