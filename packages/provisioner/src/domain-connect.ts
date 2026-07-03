/**
 * Domain Connect discovery and URL construction.
 * https://www.domainconnect.org/specification/
 */

type DomainConnectSettings = {
    providerName: string;
    urlSyncUX: string;
    urlAPI?: string;
    width?: number;
    height?: number;
};

/** Query a TXT record via Cloudflare DNS-over-HTTPS. */
export async function lookupTXT(hostname: string): Promise<string[]> {
    try {
        const res = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`,
            { headers: { Accept: 'application/dns-json' } }
        );
        if (!res.ok) return [];
        const data = (await res.json()) as {
            Answer?: { type: number; data: string }[];
        };
        if (!data.Answer) return [];
        return data.Answer.filter((r) => r.type === 16).map((r) =>
            r.data.replace(/^"|"$/g, ''),
        );
    } catch {
        return [];
    }
}

/**
 * Validate a provider host discovered from an attacker-controlled TXT record
 * (`_domainconnect.<domain>` is set by whoever owns the domain being claimed).
 * We fetch this host server-side, so it must be a plain public FQDN — this
 * rejects IP literals, ports, userinfo (`@`), paths, and reserved/internal
 * suffixes to prevent the discovery step from being used for SSRF.
 */
export function isValidProviderHost(host: string): boolean {
    const h = host.trim().toLowerCase();
    // Strict FQDN: dotted labels ending in an alphabetic TLD. Excludes IPv4
    // (numeric TLD), IPv6 (colons), and anything with `:`/`/`/`@`/whitespace.
    const FQDN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
    if (!FQDN.test(h)) return false;
    // Reserved / internal-only suffixes that could resolve to private hosts.
    const RESERVED = ['.local', '.localhost', '.internal', '.intranet', '.corp', '.home', '.lan', '.arpa'];
    if (RESERVED.some((suffix) => h.endsWith(suffix))) return false;
    return true;
}

/**
 * Discover whether a domain's DNS provider supports Domain Connect.
 * 1. Look up `_domainconnect.<domain>` TXT → provider host
 * 2. Fetch `https://<host>/v2/<domain>/settings` → provider settings
 */
export async function discoverDomainConnect(
    domain: string,
): Promise<{ supported: false } | { supported: true; settings: DomainConnectSettings; host: string }> {
    const txtRecords = await lookupTXT(`_domainconnect.${domain}`);
    if (txtRecords.length === 0) {
        return { supported: false };
    }

    const host = txtRecords[0];
    if (!isValidProviderHost(host)) {
        return { supported: false };
    }

    try {
        // `redirect: 'error'` stops a validated public host from 3xx-redirecting
        // the request into an internal target.
        const res = await fetch(`https://${host}/v2/${encodeURIComponent(domain)}/settings`, {
            headers: { Accept: 'application/json' },
            redirect: 'error',
        });
        if (!res.ok) {
            return { supported: false };
        }
        const settings = (await res.json()) as DomainConnectSettings;
        if (!settings.urlSyncUX) {
            return { supported: false };
        }
        return { supported: true, settings, host };
    } catch {
        return { supported: false };
    }
}

/**
 * Build the Domain Connect apply URL that redirects the user to their DNS
 * provider's consent screen.
 */
export function buildApplyUrl(
    settings: DomainConnectSettings,
    domain: string,
    host: string,
    target: string,
    redirectUri: string,
): string {
    const providerName = 'authgravity.org';
    const serviceName = 'auth';

    const params = new URLSearchParams({
        domain,
        host,
        providerName,
        serviceName,
        target,
        redirect_uri: redirectUri,
    });

    // urlSyncUX already includes the base, e.g. https://dcc.godaddy.com/manage
    return `${settings.urlSyncUX}/v2/domainTemplates/providers/${providerName}/services/${serviceName}/apply?${params.toString()}`;
}

/**
 * Sign a Domain Connect request with RSA-SHA256 (required by some providers
 * like Cloudflare). The signature covers the query string.
 */
export async function signDomainConnectRequest(
    queryString: string,
    privateKeyPem: string,
): Promise<string> {
    // Import PEM-encoded PKCS#8 private key
    const pemBody = privateKeyPem
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
    const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

    const key = await crypto.subtle.importKey(
        'pkcs8',
        binaryDer,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['sign'],
    );

    const data = new TextEncoder().encode(queryString);
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, data);

    // Standard Base64 encode (URLSearchParams handles URL-encoding)
    const bytes = new Uint8Array(signature);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}
