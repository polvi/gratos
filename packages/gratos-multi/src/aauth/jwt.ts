// AAuth JWT mint + verify (jose). All tenant-key signing lives here:
// aa-auth+jwt (both identity profiles) and the aauth-budget-attestation+jwt
// used by the federation relay. Verification is Ed25519-only per the seam
// contract (§1) — ES256 and everything else is `unsupported_algorithm`.

import { SignJWT, jwtVerify, importJWK, decodeProtectedHeader, decodeJwt } from 'jose';

import { AAuthError } from './encoding';
import { fetchIssuerJwks, checkOutboundUrl } from './jwksfetch';
import { jwkThumbprint, type SigningKey, type PublicJwk } from './pskeys';

const CLOCK_SKEW_S = 60;
export const AUTH_TOKEN_TTL_S = 600;
const RESOURCE_TOKEN_MAX_LIFE_S = 5 * 60;
const ATTESTATION_TTL_S = 60;

export type MissionRef = { approver: string; s256: string };
export type BudgetEntry = { resource: string; amount: string; currency: string; models?: string[] };

export type AgentIdentity = {
    iss: string;
    sub: string;
    jti: string;
    cnfJwk: PublicJwk;
    /** RFC 7638 thumbprint of cnfJwk. */
    jkt: string;
    /** The raw compact JWT, for federation relay passthrough. */
    token: string;
};

export type ResourceTokenInfo = {
    /** The resource identifier: the token's `iss`. Budget entries match THIS. */
    resource: string;
    /** Routing only: our iss → we mint; an AS token endpoint URL → relay. */
    aud: string;
    scope?: string;
    mission?: MissionRef;
    token: string;
};

/** Identity payload: base (sub-carrying) or budgeted (identityless). */
export type TokenIdentity =
    | { kind: 'base'; sub: string }
    | { kind: 'budgeted'; agent: string; mission: MissionRef; budget: BudgetEntry };

function requireEdDSA(token: string): { alg: string; typ?: string; kid?: string } {
    let header;
    try {
        header = decodeProtectedHeader(token);
    } catch {
        throw new AAuthError('invalid_token', 'malformed JWT', 401);
    }
    if (header.alg !== 'EdDSA') {
        throw new AAuthError('unsupported_algorithm', 'Ed25519 (EdDSA) is the only supported algorithm', 401);
    }
    return header as { alg: string; typ?: string; kid?: string };
}

async function verifyAgainstIssuer(
    kv: KVNamespace,
    token: string,
    iss: string,
    dwk: string,
    kid: string | undefined
): Promise<Record<string, unknown>> {
    const keys = await fetchIssuerJwks(kv, iss, dwk);
    const candidates = kid ? keys.filter((k) => k.kid === kid) : keys;
    if (candidates.length === 0) {
        throw new AAuthError('invalid_token', 'no matching key in issuer JWKS', 401);
    }
    for (const jwk of candidates) {
        if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') continue;
        try {
            const key = await importJWK({ ...jwk, alg: 'EdDSA' }, 'EdDSA');
            const { payload } = await jwtVerify(token, key, {
                algorithms: ['EdDSA'],
                clockTolerance: CLOCK_SKEW_S,
            });
            return payload as Record<string, unknown>;
        } catch (e) {
            if (e instanceof AAuthError) throw e;
            // try next candidate key
        }
    }
    throw new AAuthError('invalid_signature', 'token signature did not verify', 401);
}

/**
 * Verify an agent token (`aa-agent+jwt`) from the Signature-Key header:
 * typ/dwk, issuer JWKS, signature, iat/exp (±60s via jose), cnf.jwk present.
 * The HTTP-signature check against cnf.jwk (proof of key possession) is the
 * caller's job — see httpsig.ts.
 */
export async function verifyAgentToken(kv: KVNamespace, token: string): Promise<AgentIdentity> {
    const header = requireEdDSA(token);
    if (header.typ !== 'aa-agent+jwt') {
        throw new AAuthError('invalid_token', `expected typ aa-agent+jwt, got ${header.typ ?? 'none'}`, 401);
    }
    let unverified;
    try {
        unverified = decodeJwt(token);
    } catch {
        throw new AAuthError('invalid_token', 'malformed JWT payload', 401);
    }
    if (unverified.dwk !== 'aauth-agent.json') {
        throw new AAuthError('invalid_token', 'agent token dwk must be aauth-agent.json', 401);
    }
    const iss = String(unverified.iss || '');
    checkOutboundUrl(iss);

    const payload = await verifyAgainstIssuer(kv, token, iss, 'aauth-agent.json', header.kid);
    const sub = payload.sub;
    const jti = payload.jti;
    const cnf = payload.cnf as { jwk?: PublicJwk } | undefined;
    if (typeof sub !== 'string' || !sub) throw new AAuthError('invalid_token', 'agent token missing sub', 401);
    if (typeof jti !== 'string' || !jti) throw new AAuthError('invalid_token', 'agent token missing jti', 401);
    if (!cnf?.jwk || cnf.jwk.kty !== 'OKP' || cnf.jwk.crv !== 'Ed25519' || !cnf.jwk.x) {
        throw new AAuthError('invalid_token', 'agent token missing Ed25519 cnf.jwk', 401);
    }
    const jkt = await jwkThumbprint({ crv: 'Ed25519', kty: 'OKP', x: cnf.jwk.x });
    return { iss, sub, jti, cnfJwk: cnf.jwk, jkt, token };
}

/**
 * Verify a resource token (`aa-resource+jwt`) bound to the requesting agent.
 * Seam §2/§3: exp ≤ 5m; `iss` is the resource identifier that budget entries
 * match; `aud` only routes mint-vs-relay (base path requires aud == tenantIss,
 * enforced by the route, not here).
 */
/** The wire agent identifier (seam §2): the agent token's iss and sub, joined. */
export function agentId(agent: { iss: string; sub: string }): string {
    return `${agent.iss}#${agent.sub}`;
}

export async function verifyResourceToken(
    kv: KVNamespace,
    token: string,
    agent: { iss: string; sub: string; jkt: string }
): Promise<ResourceTokenInfo> {
    const header = requireEdDSA(token);
    if (header.typ !== 'aa-resource+jwt') {
        throw new AAuthError('invalid_token', `expected typ aa-resource+jwt, got ${header.typ ?? 'none'}`, 401);
    }
    let unverified;
    try {
        unverified = decodeJwt(token);
    } catch {
        throw new AAuthError('invalid_token', 'malformed JWT payload', 401);
    }
    if (unverified.dwk !== 'aauth-resource.json') {
        throw new AAuthError('invalid_token', 'resource token dwk must be aauth-resource.json', 401);
    }
    const iss = String(unverified.iss || '');
    checkOutboundUrl(iss);

    const payload = await verifyAgainstIssuer(kv, token, iss, 'aauth-resource.json', header.kid);
    const iat = Number(payload.iat);
    const exp = Number(payload.exp);
    if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp - iat > RESOURCE_TOKEN_MAX_LIFE_S + CLOCK_SKEW_S) {
        throw new AAuthError('invalid_token', 'resource token lifetime exceeds 5 minutes', 401);
    }
    if (typeof payload.jti !== 'string' || !payload.jti) {
        throw new AAuthError('invalid_token', 'resource token missing jti', 401);
    }
    // `agent` is the composite identifier `«iss»#«sub»` (seam §2) — the bare
    // sub is ambiguous across agent providers.
    if (payload.agent !== agentId(agent)) {
        throw new AAuthError('invalid_token', 'resource token agent does not match requester', 401);
    }
    if (payload.agent_jkt !== agent.jkt) {
        throw new AAuthError('invalid_token', 'resource token agent_jkt does not match requester key', 401);
    }
    const aud = payload.aud;
    if (typeof aud !== 'string' || !aud) {
        throw new AAuthError('invalid_token', 'resource token missing aud', 401);
    }
    let mission: MissionRef | undefined;
    const m = payload.mission as MissionRef | undefined;
    if (m) {
        if (typeof m.approver !== 'string' || typeof m.s256 !== 'string') {
            throw new AAuthError('invalid_token', 'resource token mission ref malformed', 401);
        }
        mission = { approver: m.approver, s256: m.s256 };
    }
    return {
        resource: iss,
        aud,
        scope: typeof payload.scope === 'string' ? payload.scope : undefined,
        mission,
        token,
    };
}

/**
 * Mint an `aa-auth+jwt`. Base profile carries `sub` and nothing else about the
 * person; the budgeted profile is identityless — `agent`, `mission`, `budget`
 * and NO sub (TPX-A §9). Every token gets a `jti`.
 */
export async function mintAuthToken(opts: {
    key: SigningKey;
    iss: string;
    aud: string;
    cnfJwk: PublicJwk;
    scope?: string;
    ttl?: number;
    identity: TokenIdentity;
}): Promise<{ token: string; expiresIn: number }> {
    const ttl = Math.min(opts.ttl ?? AUTH_TOKEN_TTL_S, AUTH_TOKEN_TTL_S);
    const claims: Record<string, unknown> = {
        dwk: 'aauth-person.json',
        cnf: { jwk: { kty: opts.cnfJwk.kty, crv: opts.cnfJwk.crv, x: opts.cnfJwk.x } },
    };
    if (opts.scope) claims.scope = opts.scope;
    if (opts.identity.kind === 'base') {
        claims.sub = opts.identity.sub;
    } else {
        claims.agent = opts.identity.agent;
        claims.mission = opts.identity.mission;
        claims.budget = opts.identity.budget;
    }
    const token = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-auth+jwt', kid: opts.key.kid })
        .setIssuer(opts.iss)
        .setAudience(opts.aud)
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + ttl)
        .sign(opts.key.privateKey);
    return { token, expiresIn: ttl };
}

/**
 * Mint the seam-§4 budget attestation for the PS→AS federation relay: a
 * 60-second PS-signed statement of the granted (possibly attenuated) budget
 * entry for one mission + agent, addressed to the AS endpoint being POSTed to.
 */
export async function mintBudgetAttestation(opts: {
    key: SigningKey;
    iss: string;
    aud: string;
    resource: string;
    mission: MissionRef;
    agentJkt: string;
    budget: BudgetEntry;
}): Promise<string> {
    return new SignJWT({
        resource: opts.resource,
        mission: opts.mission,
        agent_jkt: opts.agentJkt,
        budget: opts.budget,
    })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'aauth-budget-attestation+jwt', kid: opts.key.kid })
        .setIssuer(opts.iss)
        .setAudience(opts.aud)
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + ATTESTATION_TTL_S)
        .sign(opts.key.privateKey);
}
