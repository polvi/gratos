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
        expect([...SURFACE_PATHS].sort()).toEqual(['/consent', '/demo', '/login', '/logout', '/recover', '/register']);
        const login = renderSurface('/login', 'https://myapp.com/back');
        expect(login).toContain('esm.sh/@authgravity/browser');
        expect(login).toContain('trySilentLogin');
        expect(login).toContain('"returnTo":"https://myapp.com/back"');
        // first-run users get create-account right on the login page; the
        // 12-words path is demoted behind "Recover your account"
        expect(login).toContain('Create an account');
        expect(login).toContain('Recover your account');
        expect(renderSurface('/register', null)).toContain('Create account with a passkey');
        expect(renderSurface('/recover', null)).toContain('claimOrRecover');
    });

    test('the consent surface talks to the aauth consent API and offers attenuation', () => {
        const consent = renderSurface('/consent', null);
        expect(consent).toContain('/v1/aauth/consent');
        // login round-trip for signed-out users, budget narrowing, chat
        expect(consent).toContain("'/login?return_to='");
        expect(consent).toContain('Skip this one');
        expect(consent).toContain('Send question');
        expect(consent).toContain('Approve mission');
        // untrusted agent text is rendered via textContent (el helper), never innerHTML
        expect(consent).toContain('n.textContent = String(text)');
    });

    test('the account-key setup follows the gentle write-it-down model', () => {
        const reg = renderSurface('/register', null);
        // three-step, pen-and-paper-first flow with a numbered grid, print, and confirm
        for (const m of ['Step 1 of 3', 'Step 2 of 3', 'Step 3 of 3', 'I have pen and paper', 'word-grid', 'Print them instead', 'what is word number', 'print-sheet']) {
            expect(reg).toContain(m);
        }
        // passkey-first creation; the 12-words path stays as a quiet fallback
        expect(reg).toContain('Create account with a passkey');
        expect(reg).toContain('No passkey on this device? Use 12 words');
        const rec = renderSurface('/recover', null);
        expect(rec).toContain('Type your 12 words from the paper');
    });
});
