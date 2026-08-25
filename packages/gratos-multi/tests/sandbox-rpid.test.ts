import { describe, expect, test } from 'bun:test';
import { hostMatchesRpId, resolveTenant, validateSandboxRpId, withSandboxRpId } from '../src/tenant';

describe('validateSandboxRpId', () => {
    test('accepts registrable hostnames, normalised to lowercase', () => {
        expect(validateSandboxRpId('macmini.tailb55c1.ts.net')).toBe('macmini.tailb55c1.ts.net');
        expect(validateSandboxRpId('  Dev.Example.COM ')).toBe('dev.example.com');
    });

    test('rejects junk: ports, schemes, paths, single labels, non-strings', () => {
        for (const bad of ['host:8444', 'https://a.b', 'a.b/c', 'localhost', '', 42, null, '-a.b', 'a..b']) {
            expect(validateSandboxRpId(bad)).toBeNull();
        }
    });

    test("refuses AuthGravity's own domains", () => {
        expect(validateSandboxRpId('authgravity.org')).toBeNull();
        expect(validateSandboxRpId('sandbox.authgravity.org')).toBeNull();
        expect(validateSandboxRpId('notauthgravity.org')).toBe('notauthgravity.org');
    });
});

describe('sandbox rpId override', () => {
    const url = new URL('https://sandbox.authgravity.org/abc123/v1/register/options');

    test('defaults to localhost and is only applied to sandbox tenants', () => {
        const info = resolveTenant(url);
        expect(info.rpId).toBe('localhost');
        expect(withSandboxRpId(info, null).rpId).toBe('localhost');
        expect(withSandboxRpId(info, 'macmini.tailb55c1.ts.net').rpId).toBe('macmini.tailb55c1.ts.net');

        const prod = resolveTenant(new URL('https://authgravity.example.com/v1/whoami'));
        expect(withSandboxRpId(prod, 'evil.example').rpId).toBe('example.com');
    });

    test('hostMatchesRpId accepts the RP ID and its subdomains only', () => {
        expect(hostMatchesRpId('macmini.tailb55c1.ts.net', 'macmini.tailb55c1.ts.net')).toBe(true);
        expect(hostMatchesRpId('app.macmini.tailb55c1.ts.net', 'macmini.tailb55c1.ts.net')).toBe(true);
        expect(hostMatchesRpId('evilmacmini.tailb55c1.ts.net', 'macmini.tailb55c1.ts.net')).toBe(false);
        expect(hostMatchesRpId('tailb55c1.ts.net', 'macmini.tailb55c1.ts.net')).toBe(false);
    });
});
