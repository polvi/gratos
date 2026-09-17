// RFC 9421 verifier vectors (seam §1 profile): a reference signer built on
// WebCrypto Ed25519 signs canonical bases; the verifier must accept the good
// ones and reject every tamper/staleness/coverage violation.

import { describe, test, expect } from 'bun:test';

import {
    parseSignatureHeaders,
    buildSignatureBase,
    canonicalAuthority,
    verifyHttpSignature,
} from '../src/aauth/httpsig';
import { AAuthError } from '../src/aauth/encoding';

const enc = new TextEncoder();

async function genKeys() {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as { x: string };
    return { pair, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } as any };
}

/** Reference signer: builds headers the way an AAuth agent would. */
async function sign(opts: {
    pair: CryptoKeyPair;
    method: string;
    authority: string;
    protocol?: 'http:' | 'https:';
    path: string;
    components?: string[];
    created?: number;
    jwt?: string;
    extraHeaders?: Record<string, string>;
}): Promise<Headers> {
    const created = opts.created ?? Math.floor(Date.now() / 1000);
    const components = opts.components ?? ['@method', '@authority', '@path', 'signature-key'];
    const jwt = opts.jwt ?? 'test.agent.jwt';
    const signatureKeyValue = `sig=jwt;jwt="${jwt}"`;
    const list = components.map((c) => `"${c}"`).join(' ');
    const signatureParams = `(${list});created=${created}`;

    const headerValues: Record<string, string> = {
        'signature-key': signatureKeyValue,
        ...Object.fromEntries(Object.entries(opts.extraHeaders ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
    };
    const base = buildSignatureBase({
        method: opts.method,
        authority: canonicalAuthority(opts.authority, opts.protocol ?? 'https:'),
        path: opts.path,
        components,
        signatureParams,
        headerValues,
    });
    const sig = new Uint8Array(
        await crypto.subtle.sign({ name: 'Ed25519' }, opts.pair.privateKey, enc.encode(base) as BufferSource)
    );
    const headers = new Headers(opts.extraHeaders ?? {});
    headers.set('Signature-Input', `sig=${signatureParams}`);
    headers.set('Signature', `sig=:${Buffer.from(sig).toString('base64')}:`);
    headers.set('Signature-Key', signatureKeyValue);
    return headers;
}

async function verify(headers: Headers, publicJwk: any, req: Partial<Parameters<typeof verifyHttpSignature>[0]> = {}) {
    const parsed = parseSignatureHeaders(headers);
    await verifyHttpSignature({
        parsed,
        method: 'POST',
        authority: 'authgravity.example.com',
        protocol: 'https:',
        path: '/v1/aauth/token',
        headers,
        publicJwk,
        ...req,
    });
    return parsed;
}

describe('httpsig', () => {
    test('valid signature verifies and exposes the agent jwt', async () => {
        const { pair, publicJwk } = await genKeys();
        const headers = await sign({
            pair,
            method: 'POST',
            authority: 'authgravity.example.com',
            path: '/v1/aauth/token',
            jwt: 'a.b.c',
        });
        const parsed = await verify(headers, publicJwk);
        expect(parsed.agentJwt).toBe('a.b.c');
        expect(parsed.components).toContain('@authority');
    });

    test('tampered path / method / authority / Signature-Key reject', async () => {
        const { pair, publicJwk } = await genKeys();
        const mk = () => sign({ pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token' });

        expect(verify(await mk(), publicJwk, { path: '/v1/aauth/other' })).rejects.toThrow('did not verify');
        expect(verify(await mk(), publicJwk, { method: 'GET' })).rejects.toThrow('did not verify');
        expect(verify(await mk(), publicJwk, { authority: 'evil.example.com' })).rejects.toThrow('did not verify');

        const tampered = await mk();
        tampered.set('Signature-Key', 'sig=jwt;jwt="swapped.agent.jwt"');
        expect(verify(tampered, publicJwk)).rejects.toThrow('did not verify');
    });

    test('created outside the acceptance window rejects (stale and future)', async () => {
        const { pair, publicJwk } = await genKeys();
        const now = Math.floor(Date.now() / 1000);
        const stale = await sign({
            pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token',
            created: now - 400,
        });
        expect(verify(stale, publicJwk)).rejects.toThrow('acceptance window');
        const future = await sign({
            pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token',
            created: now + 120,
        });
        expect(verify(future, publicJwk)).rejects.toThrow('acceptance window');
    });

    test('missing required covered component rejects', async () => {
        const { pair, publicJwk } = await genKeys();
        const headers = await sign({
            pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token',
            components: ['@method', '@authority', '@path'], // signature-key uncovered
        });
        expect(verify(headers, publicJwk)).rejects.toThrow('must include signature-key');
    });

    test('Authorization / AAuth-Mission present but uncovered reject', async () => {
        const { pair, publicJwk } = await genKeys();
        const withAuthz = await sign({
            pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token',
            extraHeaders: { Authorization: 'AAuth abc' },
        });
        expect(verify(withAuthz, publicJwk)).rejects.toThrow('authorization header is present but not covered');

        const withMission = await sign({
            pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token',
            extraHeaders: { 'AAuth-Mission': 'approver="x"; s256="y"' },
        });
        expect(verify(withMission, publicJwk)).rejects.toThrow('aauth-mission header is present but not covered');
    });

    test('covered Authorization header verifies (and its tampering rejects)', async () => {
        const { pair, publicJwk } = await genKeys();
        const headers = await sign({
            pair, method: 'POST', authority: 'authgravity.example.com', path: '/v1/aauth/token',
            components: ['@method', '@authority', '@path', 'signature-key', 'authorization'],
            extraHeaders: { Authorization: 'AAuth tok' },
        });
        await verify(headers, publicJwk);
        headers.set('Authorization', 'AAuth other');
        expect(verify(headers, publicJwk)).rejects.toThrow('did not verify');
    });

    test('canonicalization: mixed-case host and default port match the signed authority', async () => {
        const { pair, publicJwk } = await genKeys();
        const headers = await sign({
            pair, method: 'post', authority: 'AuthGravity.Example.COM:443', path: '/v1/aauth/token',
        });
        // Receiver sees a differently-written but equivalent authority.
        await verify(headers, publicJwk, { authority: 'authgravity.example.com', method: 'POST' });
    });

    test('sandbox-prefixed path: signed with prefix, verified with reconstructed path', async () => {
        const { pair, publicJwk } = await genKeys();
        const headers = await sign({
            pair, method: 'POST', authority: 'sandbox.authgravity.org', path: '/abc123/v1/aauth/token',
        });
        await verify(headers, publicJwk, { authority: 'sandbox.authgravity.org', path: '/abc123/v1/aauth/token' });
        expect(
            verify(headers, publicJwk, { authority: 'sandbox.authgravity.org', path: '/v1/aauth/token' })
        ).rejects.toThrow('did not verify');
    });

    test('malformed structured fields reject', () => {
        const h = (o: Record<string, string>) => new Headers(o);
        expect(() => parseSignatureHeaders(h({}))).toThrow(AAuthError);
        expect(() =>
            parseSignatureHeaders(
                h({ 'Signature-Input': 'sig=nope', Signature: 'sig=:aa:', 'Signature-Key': 'sig=jwt;jwt="x"' })
            )
        ).toThrow('malformed Signature-Input');
        expect(() =>
            parseSignatureHeaders(
                h({
                    'Signature-Input': 'sig=("@method");created=1',
                    Signature: 'other=:aa:',
                    'Signature-Key': 'sig=jwt;jwt="x"',
                })
            )
        ).toThrow('labels differ');
        expect(() =>
            parseSignatureHeaders(
                h({
                    'Signature-Input': 'sig=("@method")', // no created
                    Signature: 'sig=:aa:',
                    'Signature-Key': 'sig=jwt;jwt="x"',
                })
            )
        ).toThrow('created parameter is required');
    });
});
