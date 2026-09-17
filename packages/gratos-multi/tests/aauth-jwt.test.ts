// AAuth token mint/verify vectors: both aa-auth+jwt identity profiles
// (budgeted tokens must carry NO sub), Ed25519-only enforcement, agent /
// resource token verification against issuer JWKS, budget attestation
// roundtrip. Remote JWKS fetches are served by a stubbed global fetch.

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { SignJWT, jwtVerify, importJWK, decodeProtectedHeader, decodeJwt } from 'jose';

import {
    verifyAgentToken,
    verifyResourceToken,
    mintAuthToken,
    mintBudgetAttestation,
} from '../src/aauth/jwt';
import { jwkThumbprint, type SigningKey } from '../src/aauth/pskeys';

function memoryKV(): KVNamespace {
    const store = new Map<string, string>();
    return {
        get: async (k: string, type?: string) => {
            const v = store.get(k) ?? null;
            return v !== null && type === 'json' ? JSON.parse(v) : v;
        },
        put: async (k: string, v: string) => void store.set(k, v),
        delete: async (k: string) => void store.delete(k),
    } as unknown as KVNamespace;
}

type Issuer = {
    iss: string;
    kid: string;
    privateKey: CryptoKey;
    publicJwk: { kty: string; crv: string; x: string; kid: string };
};

const issuers = new Map<string, Issuer>();
const realFetch = globalThis.fetch;

async function makeIssuer(iss: string): Promise<Issuer> {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as { x: string };
    const kid = await jwkThumbprint({ crv: 'Ed25519', kty: 'OKP', x: jwk.x });
    const issuer: Issuer = {
        iss,
        kid,
        privateKey: pair.privateKey,
        publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid },
    };
    issuers.set(iss, issuer);
    return issuer;
}

beforeAll(() => {
    // Serve every registered issuer's JWKS at {iss}/.well-known/{dwk}.
    globalThis.fetch = (async (input: any) => {
        const url = String(input instanceof Request ? input.url : input);
        for (const issuer of issuers.values()) {
            if (url.startsWith(issuer.iss + '/.well-known/')) {
                return new Response(JSON.stringify({ keys: [issuer.publicJwk] }), {
                    headers: { 'Content-Type': 'application/json' },
                });
            }
        }
        return new Response('not found', { status: 404 });
    }) as typeof fetch;
});

afterAll(() => {
    globalThis.fetch = realFetch;
});

async function agentKeys() {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as { x: string };
    const cnfJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
    return { pair, cnfJwk, jkt: await jwkThumbprint({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }) };
}

async function mintAgentToken(issuer: Issuer, cnfJwk: object, overrides: Record<string, unknown> = {}, typ = 'aa-agent+jwt') {
    return new SignJWT({ dwk: 'aauth-agent.json', cnf: { jwk: cnfJwk }, ...overrides })
        .setProtectedHeader({ alg: 'EdDSA', typ, kid: issuer.kid })
        .setIssuer(issuer.iss)
        .setSubject((overrides.sub as string) ?? 'aauth:local@agents.example')
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(issuer.privateKey);
}

async function mintResourceToken(
    issuer: Issuer,
    claims: Record<string, unknown>,
    lifetimeS = 120
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ dwk: 'aauth-resource.json', ...claims })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-resource+jwt', kid: issuer.kid })
        .setIssuer(issuer.iss)
        .setJti(crypto.randomUUID())
        .setIssuedAt(now)
        .setExpirationTime(now + lifetimeS)
        .sign(issuer.privateKey);
}

async function tenantSigningKey(): Promise<SigningKey> {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as { x: string };
    const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x } as any;
    return { kid: await jwkThumbprint({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }), privateKey: pair.privateKey, publicJwk };
}

const TENANT_ISS = 'https://authgravity.example.com';

describe('agent token verification', () => {
    test('valid agent token verifies and exposes identity + jkt', async () => {
        const issuer = await makeIssuer('https://agents.example');
        const { cnfJwk, jkt } = await agentKeys();
        const token = await mintAgentToken(issuer, cnfJwk);
        const agent = await verifyAgentToken(memoryKV(), token);
        expect(agent.iss).toBe(issuer.iss);
        expect(agent.sub).toBe('aauth:local@agents.example');
        expect(agent.jkt).toBe(jkt);
    });

    test('ES256 agent token → unsupported_algorithm (Ed25519-only v1)', async () => {
        const { privateKey } = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const token = await new SignJWT({ dwk: 'aauth-agent.json' })
            .setProtectedHeader({ alg: 'ES256', typ: 'aa-agent+jwt' })
            .setIssuer('https://agents.example')
            .setExpirationTime('5m')
            .sign(privateKey);
        expect(verifyAgentToken(memoryKV(), token)).rejects.toThrow('Ed25519');
    });

    test('alg:none rejects', async () => {
        const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
        const token = `${b64({ alg: 'none', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://a.example' })}.`;
        expect(verifyAgentToken(memoryKV(), token)).rejects.toThrow('Ed25519');
    });

    test('wrong typ rejects (auth token where agent expected)', async () => {
        const issuer = await makeIssuer('https://agents2.example');
        const { cnfJwk } = await agentKeys();
        const token = await mintAgentToken(issuer, cnfJwk, {}, 'aa-auth+jwt');
        expect(verifyAgentToken(memoryKV(), token)).rejects.toThrow('expected typ aa-agent+jwt');
    });

    test('missing cnf.jwk rejects', async () => {
        const issuer = await makeIssuer('https://agents3.example');
        const token = await new SignJWT({ dwk: 'aauth-agent.json' })
            .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-agent+jwt', kid: issuer.kid })
            .setIssuer(issuer.iss)
            .setSubject('a')
            .setJti('j')
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(issuer.privateKey);
        expect(verifyAgentToken(memoryKV(), token)).rejects.toThrow('cnf.jwk');
    });

    test('expired agent token rejects', async () => {
        const issuer = await makeIssuer('https://agents4.example');
        const { cnfJwk } = await agentKeys();
        const now = Math.floor(Date.now() / 1000);
        const token = await new SignJWT({ dwk: 'aauth-agent.json', cnf: { jwk: cnfJwk } })
            .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-agent+jwt', kid: issuer.kid })
            .setIssuer(issuer.iss)
            .setSubject('a')
            .setJti('j')
            .setIssuedAt(now - 600)
            .setExpirationTime(now - 300)
            .sign(issuer.privateKey);
        expect(verifyAgentToken(memoryKV(), token)).rejects.toThrow();
    });
});

describe('resource token verification', () => {
    // Wire identifier is the composite `iss#sub` (seam §2).
    const agentBinding = { iss: 'https://agents.example', sub: 'local', jkt: '' };
    const compositeId = `${agentBinding.iss}#${agentBinding.sub}`;

    test('valid resource token: iss is the matching identity, aud only routes', async () => {
        const issuer = await makeIssuer('https://api.notes.example');
        const { jkt } = await agentKeys();
        const token = await mintResourceToken(issuer, {
            aud: TENANT_ISS,
            agent: compositeId,
            agent_jkt: jkt,
            scope: 'notes.read',
        });
        const rt = await verifyResourceToken(memoryKV(), token, { ...agentBinding, jkt });
        expect(rt.resource).toBe('https://api.notes.example');
        expect(rt.aud).toBe(TENANT_ISS);
        expect(rt.scope).toBe('notes.read');
    });

    test('lifetime over 5 minutes rejects', async () => {
        const issuer = await makeIssuer('https://api.long.example');
        const { jkt } = await agentKeys();
        const token = await mintResourceToken(
            issuer,
            { aud: TENANT_ISS, agent: compositeId, agent_jkt: jkt },
            600
        );
        expect(verifyResourceToken(memoryKV(), token, { ...agentBinding, jkt })).rejects.toThrow('5 minutes');
    });

    test('agent / agent_jkt mismatch rejects', async () => {
        const issuer = await makeIssuer('https://api.mismatch.example');
        const { jkt } = await agentKeys();
        const token = await mintResourceToken(issuer, { aud: TENANT_ISS, agent: 'https://agents.example#someone-else', agent_jkt: jkt });
        expect(verifyResourceToken(memoryKV(), token, { ...agentBinding, jkt })).rejects.toThrow('agent');

        const token2 = await mintResourceToken(issuer, { aud: TENANT_ISS, agent: compositeId, agent_jkt: 'wrong' });
        expect(verifyResourceToken(memoryKV(), token2, { ...agentBinding, jkt })).rejects.toThrow('agent_jkt');
    });

    test('mission ref passes through', async () => {
        const issuer = await makeIssuer('https://api.mission.example');
        const { jkt } = await agentKeys();
        const mission = { approver: TENANT_ISS, s256: 'abc' };
        const token = await mintResourceToken(issuer, {
            aud: 'https://as.tokenpony.example/token',
            agent: compositeId,
            agent_jkt: jkt,
            mission,
        });
        const rt = await verifyResourceToken(memoryKV(), token, { ...agentBinding, jkt });
        expect(rt.mission).toEqual(mission);
        expect(rt.aud).toBe('https://as.tokenpony.example/token');
    });
});

describe('auth token minting', () => {
    test('base profile carries sub and nothing else about the person', async () => {
        const key = await tenantSigningKey();
        const { cnfJwk } = await agentKeys();
        const { token, expiresIn } = await mintAuthToken({
            key,
            iss: TENANT_ISS,
            aud: 'https://api.notes.example',
            cnfJwk: cnfJwk as any,
            scope: 'notes.read',
            identity: { kind: 'base', sub: 'user-uuid-1' },
        });
        expect(expiresIn).toBe(600);
        const header = decodeProtectedHeader(token);
        expect(header.typ).toBe('aa-auth+jwt');
        expect(header.alg).toBe('EdDSA');
        expect(header.kid).toBe(key.kid);
        const verified = await jwtVerify(token, await importJWK({ ...key.publicJwk, alg: 'EdDSA' } as any, 'EdDSA'));
        expect(verified.payload.sub).toBe('user-uuid-1');
        expect(verified.payload.dwk).toBe('aauth-person.json');
        expect(verified.payload.jti).toBeDefined();
        expect((verified.payload as any).agent).toBeUndefined();
        expect((verified.payload as any).email).toBeUndefined();
    });

    test('budgeted profile is identityless: no sub, carries agent/mission/budget', async () => {
        const key = await tenantSigningKey();
        const { cnfJwk } = await agentKeys();
        const budget = { resource: 'https://api.tokenpony.dev', amount: '2.00', currency: 'USD', models: ['pony-8b'] };
        const mission = { approver: TENANT_ISS, s256: 'xyz' };
        const { token } = await mintAuthToken({
            key,
            iss: TENANT_ISS,
            aud: 'https://api.tokenpony.dev',
            cnfJwk: cnfJwk as any,
            scope: 'inference',
            identity: { kind: 'budgeted', agent: 'aauth:local@agents.example', mission, budget },
        });
        const payload = decodeJwt(token);
        expect(payload.sub).toBeUndefined();
        expect((payload as any).agent).toBe('aauth:local@agents.example');
        expect((payload as any).mission).toEqual(mission);
        expect((payload as any).budget).toEqual(budget);
        expect((payload as any).email).toBeUndefined();
    });

    test('budget attestation roundtrip verifies against the tenant key', async () => {
        const key = await tenantSigningKey();
        const budget = { resource: 'https://api.tokenpony.dev', amount: '1.50', currency: 'USD' };
        const jws = await mintBudgetAttestation({
            key,
            iss: TENANT_ISS,
            aud: 'https://as.tokenpony.example/token',
            resource: 'https://api.tokenpony.dev',
            mission: { approver: TENANT_ISS, s256: 's' },
            agentJkt: 'jkt-1',
            budget,
        });
        const header = decodeProtectedHeader(jws);
        expect(header.typ).toBe('aauth-budget-attestation+jwt');
        const verified = await jwtVerify(jws, await importJWK({ ...key.publicJwk, alg: 'EdDSA' } as any, 'EdDSA'), {
            audience: 'https://as.tokenpony.example/token',
        });
        expect((verified.payload as any).budget).toEqual(budget);
        expect((verified.payload as any).agent_jkt).toBe('jkt-1');
        const life = (verified.payload.exp as number) - (verified.payload.iat as number);
        expect(life).toBeLessThanOrEqual(60);
    });
});
