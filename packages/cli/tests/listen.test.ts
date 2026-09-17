import { describe, expect, test } from 'bun:test';
import { createApp, isLoopbackHost } from '../src/listen';

const UPSTREAM = 'https://sandbox.example.invalid/abc';

function preflight(app: ReturnType<typeof createApp>, origin: string) {
    return app.request('/v1/whoami', {
        method: 'OPTIONS',
        headers: { Origin: origin, 'Access-Control-Request-Method': 'GET' },
    });
}

describe('createApp CORS', () => {
    test('default only reflects localhost origins', async () => {
        const app = createApp(UPSTREAM);
        const ok = await preflight(app, 'http://localhost:5173');
        expect(ok.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
        const bad = await preflight(app, 'http://100.86.171.55');
        expect(bad.headers.get('access-control-allow-origin')).toBeNull();
    });

    test('allowAnyOrigin reflects every origin', async () => {
        const app = createApp(UPSTREAM, { allowAnyOrigin: true });
        const res = await preflight(app, 'http://100.86.171.55');
        expect(res.headers.get('access-control-allow-origin')).toBe('http://100.86.171.55');
        expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    });
});

test('isLoopbackHost', () => {
    expect(isLoopbackHost('localhost')).toBe(true);
    expect(isLoopbackHost('127.0.0.1')).toBe(true);
    expect(isLoopbackHost('[::1]')).toBe(true);
    expect(isLoopbackHost('0.0.0.0')).toBe(false);
});

describe('createApp verify translation', () => {
    const withUpstream = async (path: string, body: unknown, run: (app: ReturnType<typeof createApp>) => Promise<Response>) => {
        const realFetch = globalThis.fetch;
        const seen: { url?: string; auth?: string | null } = {};
        globalThis.fetch = (async (input: any, init?: RequestInit) => {
            seen.url = String(input);
            seen.auth = new Headers(init?.headers).get('Authorization');
            return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
        }) as any;
        try {
            const app = createApp(UPSTREAM);
            const res = await run(app);
            return { res, seen };
        } finally {
            globalThis.fetch = realFetch;
        }
    };

    const post = (app: ReturnType<typeof createApp>, path: string, cookie?: string) =>
        app.request(path, {
            method: 'POST',
            headers: { Origin: 'http://localhost:5173', 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
            body: '{}',
        });

    test('passkey verify: session cookie + last-used mirror land on localhost', async () => {
        const { res } = await withUpstream('/v1/login/verify', { verified: true, session_id: 'sess-1', last_used: 'login.webauthn' }, (app) =>
            post(app, '/v1/login/verify')
        );
        const cookies = res.headers.getSetCookie().join('\n');
        expect(cookies).toContain('session_id=sess-1');
        expect(cookies).toMatch(/session_id=[^\n]*HttpOnly/);
        expect(cookies).toContain('ag_last_used=login.webauthn');
        // the app's UI reads this one, so it is NOT HttpOnly
        expect(cookies).not.toMatch(/ag_last_used=[^\n]*HttpOnly/i);
        expect(cookies).toMatch(/ag_last_used=[^\n]*Max-Age=31536000/);
        // the upstream's own Set-Cookie never leaks through
        expect(cookies).not.toContain('Domain=');
    });

    test('account-key and device-key verifies are translated too', async () => {
        for (const path of ['/v1/key/register/verify', '/v1/key/login/verify']) {
            const { res } = await withUpstream(path, { verified: true, session_id: 'sess-k', last_used: 'register.key' }, (app) => post(app, path));
            const cookies = res.headers.getSetCookie().join('\n');
            expect(cookies).toContain('session_id=sess-k');
            expect(cookies).toContain('ag_last_used=register.key');
        }
    });

    test('a verify without last_used (credential added to a signed-in user) leaves the hint alone', async () => {
        const { res, seen } = await withUpstream('/v1/key/register/verify', { verified: true, session_id: 'sess-2', credential_id: 'c' }, (app) =>
            post(app, '/v1/key/register/verify', 'session_id=sess-1; ag_last_used=register.webauthn')
        );
        const cookies = res.headers.getSetCookie().join('\n');
        expect(cookies).toContain('session_id=sess-2');
        expect(cookies).not.toContain('ag_last_used');
        expect(seen.auth).toBe('Bearer sess-1');
    });

    test('credential management passes through with the cookie translated to Bearer', async () => {
        const { res, seen } = await withUpstream('/v1/credentials/row-1', { deleted: true }, (app) =>
            app.request('/v1/credentials/row-1', {
                method: 'DELETE',
                headers: { Origin: 'http://localhost:5173', Cookie: 'session_id=sess-1' },
            })
        );
        expect(res.status).toBe(200);
        expect(seen.url).toMatch(/\/v1\/credentials\/row-1$/);
        expect(seen.auth).toBe('Bearer sess-1');
        // not a ceremony: the localhost session cookie is left alone
        expect(res.headers.getSetCookie().join('\n')).not.toContain('session_id');
    });

    test('garbage last_used is ignored', async () => {
        const { res } = await withUpstream('/v1/login/verify', { verified: true, session_id: 's', last_used: 'login.password; Path=/evil' }, (app) =>
            post(app, '/v1/login/verify')
        );
        expect(res.headers.getSetCookie().join('\n')).not.toContain('ag_last_used');
    });
});
