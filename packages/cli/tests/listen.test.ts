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
