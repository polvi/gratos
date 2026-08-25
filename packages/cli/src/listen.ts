import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { networkInterfaces } from 'node:os';

const COOKIE_NAME = 'session_id';
const SESSION_TTL = 604800; // 7 days, matches the server

export type ListenOptions = {
    /** Sandbox auth endpoint, e.g. https://sandbox.authgravity.org/<id>. Minted if omitted. */
    endpoint?: string;
    port: number;
    /** Interface to bind. Non-loopback hosts relax CORS to any origin. */
    host: string;
    /** Host used to mint a sandbox when no endpoint is given. */
    mintHost: string;
    /** Custom WebAuthn RP ID for the minted sandbox (default localhost). */
    rpId?: string;
};

export type MintedSandbox = { id: string; endpoint: string; rp_id?: string };

export async function mintSandbox(mintHost: string, rpId?: string): Promise<MintedSandbox> {
    const res = await fetch(`${mintHost}/sandbox`, {
        method: 'POST',
        ...(rpId
            ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rp_id: rpId }) }
            : {}),
    });
    if (!res.ok) {
        throw new Error(`Failed to mint sandbox (${res.status}): ${await res.text()}`);
    }
    return (await res.json()) as MintedSandbox;
}

export function isLoopbackHost(host: string): boolean {
    const h = host.replace(/^\[|\]$/g, '');
    return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

function isLocalOrigin(origin: string): boolean {
    try {
        const host = new URL(origin).hostname;
        return host === 'localhost' || host === '127.0.0.1';
    } catch {
        return false;
    }
}

// Request headers we never forward upstream. The cookie is translated to a
// Bearer header instead; host/length are set by fetch itself.
const DROP_REQUEST_HEADERS = new Set(['host', 'cookie', 'connection', 'content-length']);

// Response headers we never pass back. Set-Cookie is replaced with our own
// localhost-scoped cookie; CORS headers come from this proxy's middleware; the
// encoding/length headers describe the upstream stream, not our buffered body.
const DROP_RESPONSE_HEADERS = new Set([
    'set-cookie',
    'content-encoding',
    'content-length',
    'transfer-encoding',
    'connection',
]);

export type AppOptions = {
    /** Reflect every Origin instead of only localhost (used when bound off-loopback). */
    allowAnyOrigin?: boolean;
};

export function createApp(endpoint: string, appOpts: AppOptions = {}) {
    const upstream = new URL(endpoint);
    const upstreamBase = upstream.origin + upstream.pathname.replace(/\/$/, '');

    const app = new Hono();

    app.use(
        '/*',
        cors({
            origin: (origin) => (appOpts.allowAnyOrigin || isLocalOrigin(origin) ? origin : ''),
            allowHeaders: ['Content-Type', 'Authorization'],
            allowMethods: ['POST', 'GET', 'OPTIONS', 'DELETE', 'PUT'],
            maxAge: 600,
            credentials: true,
        })
    );

    app.all('/*', async (c) => {
        const url = new URL(c.req.url);
        const target = upstreamBase + url.pathname + url.search;

        const headers = new Headers();
        c.req.raw.headers.forEach((value, key) => {
            if (!DROP_REQUEST_HEADERS.has(key.toLowerCase())) headers.set(key, value);
        });

        // Translate the first-party localhost cookie into the Bearer auth the
        // sandbox accepts (its own cookie is scoped to sandbox.authgravity.org
        // and never reaches us).
        const sessionId = getCookie(c, COOKIE_NAME);
        if (sessionId && !headers.has('Authorization')) {
            headers.set('Authorization', `Bearer ${sessionId}`);
        }

        const method = c.req.method;
        const body = method === 'GET' || method === 'HEAD' ? undefined : await c.req.raw.arrayBuffer();

        let res: Response;
        try {
            res = await fetch(target, { method, headers, body });
        } catch (err) {
            console.error(`  ✖ ${method} ${url.pathname} → upstream unreachable: ${err}`);
            return c.json({ error: 'Upstream unreachable', target }, 502);
        }

        const text = await res.text();

        const responseHeaders = new Headers();
        res.headers.forEach((value, key) => {
            if (!DROP_RESPONSE_HEADERS.has(key.toLowerCase())) responseHeaders.set(key, value);
        });
        c.res = new Response(text, { status: res.status, headers: responseHeaders });

        let note = '';
        const isVerify = url.pathname === '/v1/register/verify' || url.pathname === '/v1/login/verify';
        if (isVerify && res.ok) {
            try {
                const data = JSON.parse(text) as { session_id?: string };
                if (data.session_id) {
                    // Host-only cookie: no Domain, so it scopes to whichever
                    // host the client used (localhost, or a LAN/tailnet IP when
                    // bound to 0.0.0.0); no Secure (plain http); Lax is fine
                    // across ports.
                    setCookie(c, COOKIE_NAME, data.session_id, {
                        httpOnly: true,
                        sameSite: 'Lax',
                        path: '/',
                        maxAge: SESSION_TTL,
                    });
                    note = ' (session cookie set on localhost)';
                }
            } catch {
                // non-JSON verify response; pass through untouched
            }
        }
        if (url.pathname === '/v1/logout') {
            deleteCookie(c, COOKIE_NAME, { path: '/' });
            note = ' (session cookie cleared)';
        }

        console.log(`  → ${method} ${url.pathname} ${res.status}${note}`);
        return c.res;
    });

    return app;
}

export async function listen(opts: ListenOptions) {
    let endpoint = opts.endpoint;
    let mintedId: string | undefined;
    let rpId: string | undefined;

    if (!endpoint) {
        const minted = await mintSandbox(opts.mintHost, opts.rpId);
        endpoint = minted.endpoint;
        mintedId = minted.id;
        rpId = minted.rp_id;
    }

    const loopback = isLoopbackHost(opts.host);
    const app = createApp(endpoint, { allowAnyOrigin: !loopback });
    const server = Bun.serve({ hostname: opts.host, port: opts.port, fetch: app.fetch });

    const displayHost = loopback ? 'localhost' : opts.host;
    const proxyUrl = `http://${displayHost}:${server.port}`;
    // When bound to all interfaces, list the concrete addresses a device can use.
    const reachable: string[] = [];
    if (opts.host === '0.0.0.0' || opts.host === '::') {
        for (const addrs of Object.values(networkInterfaces())) {
            for (const a of addrs ?? []) {
                if (!a.internal && a.family === 'IPv4') reachable.push(`http://${a.address}:${server.port}`);
            }
        }
    }

    return { server, endpoint, mintedId, rpId, proxyUrl, reachable };
}
