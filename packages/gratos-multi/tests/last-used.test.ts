import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { formatLastUsed, parseLastUsed, setLastUsed, LAST_USED_COOKIE, LAST_USED_TTL } from '../src/last-used';

describe('last-used wire form', () => {
    test('round-trips every action × method', () => {
        for (const action of ['login', 'register'] as const) {
            for (const method of ['webauthn', 'device', 'key', 'otp'] as const) {
                const v = formatLastUsed(action, method);
                expect(v).toBe(`${action}.${method}`);
                expect(parseLastUsed(v)).toEqual({ action, method });
            }
        }
    });

    test('rejects anything else', () => {
        expect(parseLastUsed(null)).toBeNull();
        expect(parseLastUsed(undefined)).toBeNull();
        expect(parseLastUsed('')).toBeNull();
        expect(parseLastUsed('login')).toBeNull();
        expect(parseLastUsed('login.password')).toBeNull();
        expect(parseLastUsed('signup.webauthn')).toBeNull();
        expect(parseLastUsed('login.webauthn.extra')).toBeNull();
    });
});

describe('setLastUsed', () => {
    const tenantInfo = { tenant: 'myapp.com', cookieDomain: 'myapp.com' } as any;

    test('sets a year-long, JS-readable cookie on the tenant domain and returns the value', async () => {
        const app = new Hono();
        let returned = '';
        app.get('/', (c) => {
            returned = setLastUsed(c, tenantInfo, 'register', 'key');
            return c.json({ ok: true });
        });
        const res = await app.request('/');
        const cookie = res.headers.get('set-cookie') || '';
        expect(returned).toBe('register.key');
        expect(cookie).toContain(`${LAST_USED_COOKIE}=register.key`);
        expect(cookie).toContain('Domain=myapp.com');
        expect(cookie).toContain(`Max-Age=${LAST_USED_TTL}`);
        expect(cookie).toContain('SameSite=None');
        expect(cookie).toContain('Secure');
        // the app's sign-in UI must be able to read it
        expect(cookie.toLowerCase()).not.toContain('httponly');
    });
});
