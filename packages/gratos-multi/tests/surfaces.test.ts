import { describe, expect, test } from 'bun:test';
import { validateReturnTo, SURFACE_PATHS, renderSurface } from '../src/surfaces';

describe('validateReturnTo', () => {
    const tenant = 'myapp.com';
    const host = 'authgravity.myapp.com';

    test('accepts the registrable domain and its subdomains', () => {
        expect(validateReturnTo('https://myapp.com/dashboard', tenant, host)).toBe('https://myapp.com/dashboard');
        expect(validateReturnTo('https://www.myapp.com/x', tenant, host)).toBe('https://www.myapp.com/x');
        expect(validateReturnTo('https://authgravity.myapp.com/y', tenant, host)).toBe('https://authgravity.myapp.com/y');
    });

    test('accepts the surface host itself', () => {
        expect(validateReturnTo(`https://${host}/back`, tenant, host)).toBe(`https://${host}/back`);
    });

    test('rejects external domains (open-redirect / phishing guard)', () => {
        expect(validateReturnTo('https://evil.com/', tenant, host)).toBeNull();
        expect(validateReturnTo('https://myapp.com.evil.com/', tenant, host)).toBeNull();
        expect(validateReturnTo('https://notmyapp.com/', tenant, host)).toBeNull();
    });

    test('rejects non-http(s) schemes and garbage', () => {
        expect(validateReturnTo('javascript:alert(1)', tenant, host)).toBeNull();
        expect(validateReturnTo('data:text/html,x', tenant, host)).toBeNull();
        expect(validateReturnTo('not a url', tenant, host)).toBeNull();
        expect(validateReturnTo(null, tenant, host)).toBeNull();
        expect(validateReturnTo(undefined, tenant, host)).toBeNull();
    });

    test('allows localhost in dev / localhost tenant', () => {
        expect(validateReturnTo('http://localhost:3000/app', 'localhost', 'localhost')).toBe('http://localhost:3000/app');
        expect(validateReturnTo('http://localhost:5173/x', tenant, host)).toBe('http://localhost:5173/x');
    });
});

describe('renderSurface', () => {
    test('surface set + rendered pages carry the expected shape', () => {
        expect([...SURFACE_PATHS].sort()).toEqual(['/demo', '/login', '/logout', '/recover', '/register']);
        const login = renderSurface('/login', 'https://myapp.com/back');
        expect(login).toContain('esm.sh/@authgravity/browser');
        expect(login).toContain('trySilentLogin');
        expect(login).toContain('"returnTo":"https://myapp.com/back"');
        expect(renderSurface('/register', null)).toContain('Create account with a passkey');
        expect(renderSurface('/recover', null)).toContain('claimOrRecover');
    });
});
