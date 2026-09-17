// Minimal RFC 9421 HTTP Message Signature verification for the AAuth profile
// (seam §1). Deliberately narrow — one signature label, Ed25519 only, covered
// components restricted to what AAuth signs — with the same spec-with-vectors
// philosophy as tests/keyspec-ref.ts. Not a general structured-fields parser.
//
// Profile: covered components MUST include "@method" "@authority" "@path"
// "signature-key"; "authorization" and "aauth-mission" MUST be covered
// whenever those headers are present (present-but-uncovered → reject).
// `created` required, 300s acceptance window ±60s skew.

// @ts-ignore
import { Buffer } from 'node:buffer';

import { AAuthError } from './encoding';
import type { PublicJwk } from './pskeys';

const REQUIRED_COMPONENTS = ['@method', '@authority', '@path', 'signature-key'];
const COVER_IF_PRESENT = ['authorization', 'aauth-mission'];
const CREATED_WINDOW_S = 300;
const CLOCK_SKEW_S = 60;

export type ParsedSignature = {
    label: string;
    /** Covered component identifiers, lowercased, in signed order. */
    components: string[];
    /** The raw Signature-Input member value — becomes the @signature-params base line. */
    signatureParams: string;
    created: number;
    signatureBytes: Uint8Array;
    /** The agent token carried in Signature-Key (jwt=...). */
    agentJwt: string;
    /** Raw Signature-Key field value (a covered component). */
    signatureKeyValue: string;
};

/**
 * Parse Signature-Input / Signature / Signature-Key. All three must be present
 * and share one label.
 */
export function parseSignatureHeaders(headers: Headers): ParsedSignature {
    const input = headers.get('signature-input');
    const signature = headers.get('signature');
    const signatureKey = headers.get('signature-key');
    if (!input || !signature || !signatureKey) {
        throw new AAuthError('invalid_signature', 'Signature-Input, Signature and Signature-Key are required', 401);
    }

    // Signature-Input: label=("comp" "comp" ...);param=value;...
    const inputMatch = input.trim().match(/^([A-Za-z0-9_-]+)=(\((?:[^)]*)\)(?:;.*)?)$/s);
    if (!inputMatch) throw new AAuthError('invalid_signature', 'malformed Signature-Input', 401);
    const label = inputMatch[1];
    const signatureParams = inputMatch[2].trim();

    const listMatch = signatureParams.match(/^\(([^)]*)\)/);
    if (!listMatch) throw new AAuthError('invalid_signature', 'malformed covered component list', 401);
    const components: string[] = [];
    const compRe = /"([^"]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = compRe.exec(listMatch[1])) !== null) components.push(m[1].toLowerCase());

    const createdMatch = signatureParams.match(/;\s*created=(\d+)/);
    if (!createdMatch) throw new AAuthError('invalid_signature', 'created parameter is required', 401);
    const created = parseInt(createdMatch[1], 10);

    // Signature: label=:base64:
    const sigMatch = signature.trim().match(/^([A-Za-z0-9_-]+)=:([A-Za-z0-9+/=]+):$/);
    if (!sigMatch) throw new AAuthError('invalid_signature', 'malformed Signature', 401);
    if (sigMatch[1] !== label) {
        throw new AAuthError('invalid_signature', 'Signature and Signature-Input labels differ', 401);
    }
    const signatureBytes = new Uint8Array(Buffer.from(sigMatch[2], 'base64'));

    // Signature-Key: label=jwt;jwt="<compact JWT>"
    const keyMatch = signatureKey.trim().match(/^([A-Za-z0-9_-]+)=jwt;\s*jwt="([^"]+)"$/);
    if (!keyMatch) throw new AAuthError('invalid_signature', 'malformed Signature-Key', 401);
    if (keyMatch[1] !== label) {
        throw new AAuthError('invalid_signature', 'Signature-Key and Signature-Input labels differ', 401);
    }

    return {
        label,
        components,
        signatureParams,
        created,
        signatureBytes,
        agentJwt: keyMatch[2],
        signatureKeyValue: signatureKey.trim(),
    };
}

/** Canonicalize @authority: lowercase host, strip default port (seam §1). */
export function canonicalAuthority(authority: string, protocol: 'http:' | 'https:'): string {
    let a = authority.toLowerCase();
    if (protocol === 'https:' && a.endsWith(':443')) a = a.slice(0, -4);
    if (protocol === 'http:' && a.endsWith(':80')) a = a.slice(0, -3);
    return a;
}

/**
 * Build the RFC 9421 signature base. Pure — fully unit-testable. `path` is the
 * signed path (for sandbox hosts: sandboxPrefix + stripped path).
 */
export function buildSignatureBase(opts: {
    method: string;
    authority: string;
    path: string;
    components: string[];
    signatureParams: string;
    headerValues: Record<string, string>;
}): string {
    const lines: string[] = [];
    for (const comp of opts.components) {
        let value: string;
        if (comp === '@method') value = opts.method.toUpperCase();
        else if (comp === '@authority') value = opts.authority;
        else if (comp === '@path') value = opts.path;
        else {
            const v = opts.headerValues[comp];
            if (v === undefined) {
                throw new AAuthError('invalid_signature', `covered component ${comp} not present`, 401);
            }
            value = v.trim();
        }
        lines.push(`"${comp}": ${value}`);
    }
    lines.push(`"@signature-params": ${opts.signatureParams}`);
    return lines.join('\n');
}

/**
 * Verify a signed request against the agent's cnf.jwk. Also enforces the
 * covered-component profile and the created window. Returns the parsed
 * signature so callers can replay-guard on sha256(signatureBytes).
 */
export async function verifyHttpSignature(opts: {
    parsed: ParsedSignature;
    method: string;
    /** Request authority as received (Host), pre-canonicalized by caller or not. */
    authority: string;
    protocol: 'http:' | 'https:';
    /** The signed path — includes the sandbox prefix when applicable. */
    path: string;
    headers: Headers;
    publicJwk: PublicJwk;
    now?: number;
}): Promise<void> {
    const { parsed } = opts;

    for (const comp of REQUIRED_COMPONENTS) {
        if (!parsed.components.includes(comp)) {
            throw new AAuthError('invalid_signature', `covered components must include ${comp}`, 401);
        }
    }
    for (const header of COVER_IF_PRESENT) {
        if (opts.headers.get(header) !== null && !parsed.components.includes(header)) {
            throw new AAuthError('invalid_signature', `${header} header is present but not covered`, 401);
        }
    }

    const now = Math.floor((opts.now ?? Date.now()) / 1000);
    if (parsed.created > now + CLOCK_SKEW_S || now - parsed.created > CREATED_WINDOW_S + CLOCK_SKEW_S) {
        throw new AAuthError('invalid_signature', 'signature created outside acceptance window', 401);
    }

    const headerValues: Record<string, string> = { 'signature-key': parsed.signatureKeyValue };
    for (const header of COVER_IF_PRESENT) {
        const v = opts.headers.get(header);
        if (v !== null) headerValues[header] = v;
    }

    const base = buildSignatureBase({
        method: opts.method,
        authority: canonicalAuthority(opts.authority, opts.protocol),
        path: opts.path,
        components: parsed.components,
        signatureParams: parsed.signatureParams,
        headerValues,
    });

    if (opts.publicJwk.kty !== 'OKP' || opts.publicJwk.crv !== 'Ed25519' || !opts.publicJwk.x) {
        throw new AAuthError('unsupported_algorithm', 'Ed25519 keys only', 401);
    }
    const key = await crypto.subtle.importKey(
        'jwk',
        { kty: 'OKP', crv: 'Ed25519', x: opts.publicJwk.x },
        { name: 'Ed25519' },
        false,
        ['verify']
    );
    const ok = await crypto.subtle.verify(
        { name: 'Ed25519' },
        key,
        parsed.signatureBytes as BufferSource,
        new TextEncoder().encode(base) as BufferSource
    );
    if (!ok) throw new AAuthError('invalid_signature', 'HTTP signature did not verify', 401);
}
