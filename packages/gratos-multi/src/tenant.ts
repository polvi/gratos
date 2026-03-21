export type TenantInfo = {
    tenant: string;
    rpId: string;
    cookieDomain: string;
    origin: string;
};

/**
 * Derive tenant info from the request hostname.
 * e.g. "authgravity.example.com" → tenant="example.com", rpId="example.com",
 *      cookieDomain="example.com", origin="https://authgravity.example.com"
 *
 * For localhost development, tenant is "localhost".
 */
export function resolveTenant(url: URL): TenantInfo {
    const hostname = url.hostname;

    // Localhost dev mode
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return {
            tenant: 'localhost',
            rpId: 'localhost',
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
            cookieDomain: hostname,
            origin: url.origin,
        };
    }

    // e.g. "authgravity.example.com" → "example.com"
    const tenant = parts.slice(1).join('.');
    return {
        tenant,
        rpId: tenant,
        cookieDomain: tenant,
        origin: url.origin,
    };
}
