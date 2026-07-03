import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

const COOKIE_NAME = 'session_id';
const SESSION_TTL = 604800; // 7 days, matches the server

export type ListenOptions = {
    /** Sandbox auth endpoint, e.g. https://sandbox.authgravity.org/<id>. Minted if omitted. */
    endpoint?: string;
    port: number;
    /** Host used to mint a sandbox when no endpoint is given. */
    mintHost: string;
};

export async function mintSandbox(mintHost: string): Promise<{ id: string; endpoint: string }> {
    const res = await fetch(`${mintHost}/sandbox`, { method: 'POST' });
    if (!res.ok) {
        throw new Error(`Failed to mint sandbox (${res.status}): ${await res.text()}`);
    }
    return (await res.json()) as { id: string; endpoint: string };
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

export function createApp(endpoint: string) {
    const upstream = new URL(endpoint);
    const upstreamBase = upstream.origin + upstream.pathname.replace(/\/$/, '');

    const app = new Hono();

    app.use(
        '/*',
        cors({
            origin: (origin) => (isLocalOrigin(origin) ? origin : ''),
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
        const isVerify = [
            '/register/verify',
            '/login/verify',
            '/v1/register/verify',
            '/v1/login/verify',
        ].includes(url.pathname);
        if (isVerify && res.ok) {
            try {
                const data = JSON.parse(text) as { session_id?: string };
                if (data.session_id) {
                    // Host-only localhost cookie: no Domain, no Secure (plain
                    // http://localhost), Lax is fine across localhost ports.
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
        if (url.pathname === '/logout' || url.pathname === '/v1/logout') {
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

    if (!endpoint) {
        const minted = await mintSandbox(opts.mintHost);
        endpoint = minted.endpoint;
        mintedId = minted.id;
    }

    const app = createApp(endpoint);
    const server = Bun.serve({ port: opts.port, fetch: app.fetch });

    return { server, endpoint, mintedId, proxyUrl: `http://localhost:${server.port}` };
}
