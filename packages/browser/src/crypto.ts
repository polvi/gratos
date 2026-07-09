// Account-key crypto — the browser port of the reference implementation
// (packages/gratos-multi/tests/keyspec-ref.ts). Kept byte-for-byte faithful so
// the golden vectors in keyspec.test.ts (mirrored in crypto.test.ts) still pin
// it down. The only differences from the reference are browser-safe base64url /
// hex (no Node Buffer) and the vendored wordlist.
//
// Spec: 16 bytes of entropy → interchangeable renderings (compact "agak1_…" or
// 12 BIP39 words); per-tenant P-256 key via HKDF-SHA256(entropy, salt=tenant,
// info="authgravity/softkey/v1", 40); signatures are 64-byte r||s ECDSA-SHA256
// over `${context}\n${challenge}\n${tenant}`.

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { WORDLIST } from './wordlist';

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
export const COMPACT_PREFIX = 'agak1_';
export const DERIVATION_INFO = 'authgravity/softkey/v1';

// --- browser-safe encodings (no Node Buffer) ---

export function b64u(bytes: Uint8Array): string {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hex(bytes: Uint8Array): string {
    let s = '';
    for (const b of bytes) s += b.toString(16).padStart(2, '0');
    return s;
}

export function fromHex(s: string): Uint8Array {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
}

// --- base32 (RFC 4648 lowercase, no padding) ---

function base32Encode(bytes: Uint8Array, chars: number): string {
    let bits = 0;
    let value = 0;
    let out = '';
    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    return out.slice(0, chars);
}

function base32Decode(s: string, byteLen: number): Uint8Array {
    let bits = 0;
    let value = 0;
    const out: number[] = [];
    for (const ch of s) {
        const idx = BASE32_ALPHABET.indexOf(ch);
        if (idx === -1) throw new Error(`invalid base32 character "${ch}"`);
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(out.slice(0, byteLen));
}

function checksum4(entropy: Uint8Array): string {
    const digest = sha256(entropy);
    const val = (digest[0] << 12) | (digest[1] << 4) | (digest[2] >>> 4); // 20 bits
    return (
        BASE32_ALPHABET[(val >>> 15) & 31] +
        BASE32_ALPHABET[(val >>> 10) & 31] +
        BASE32_ALPHABET[(val >>> 5) & 31] +
        BASE32_ALPHABET[val & 31]
    );
}

export function encodeCompact(entropy: Uint8Array): string {
    if (entropy.length !== 16) throw new Error('entropy must be 16 bytes');
    return COMPACT_PREFIX + base32Encode(entropy, 26) + checksum4(entropy);
}

export function decodeCompact(s: string): Uint8Array {
    const normalized = s.trim().toLowerCase();
    if (!normalized.startsWith(COMPACT_PREFIX)) throw new Error('not an account key');
    const body = normalized.slice(COMPACT_PREFIX.length);
    if (body.length !== 30) throw new Error('wrong length');
    const entropy = base32Decode(body.slice(0, 26), 16);
    if (checksum4(entropy) !== body.slice(26)) throw new Error('checksum mismatch — check for typos');
    return entropy;
}

export function encodeWords(entropy: Uint8Array): string[] {
    if (entropy.length !== 16) throw new Error('entropy must be 16 bytes');
    const check = sha256(entropy)[0] >>> 4;
    let bits = '';
    for (const b of entropy) bits += b.toString(2).padStart(8, '0');
    bits += check.toString(2).padStart(4, '0');
    const words: string[] = [];
    for (let i = 0; i < 12; i++) {
        words.push(WORDLIST[parseInt(bits.slice(i * 11, (i + 1) * 11), 2)]);
    }
    return words;
}

export function decodeWords(words: string[]): Uint8Array {
    if (words.length !== 12) throw new Error('expected 12 words');
    let bits = '';
    for (const raw of words) {
        const idx = WORDLIST.indexOf(raw.trim().toLowerCase());
        if (idx === -1) throw new Error(`unknown word "${raw}"`);
        bits += idx.toString(2).padStart(11, '0');
    }
    const entropy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) entropy[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
    if ((sha256(entropy)[0] >>> 4) !== parseInt(bits.slice(128), 2)) {
        throw new Error('checksum mismatch — check the words');
    }
    return entropy;
}

export function derivePrivateKey(entropy: Uint8Array, tenant: string): Uint8Array {
    const okm = hkdf(sha256, entropy, new TextEncoder().encode(tenant), new TextEncoder().encode(DERIVATION_INFO), 40);
    let x = 0n;
    for (const b of okm) x = (x << 8n) | BigInt(b);
    const d = (x % (p256.Point.Fn.ORDER - 1n)) + 1n;
    const bytes = new Uint8Array(32);
    let v = d;
    for (let i = 31; i >= 0; i--) {
        bytes[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return bytes;
}

export function publicKeyFor(priv: Uint8Array): Uint8Array {
    return p256.getPublicKey(priv, false); // 65-byte uncompressed
}

export function signPayload(priv: Uint8Array, payload: string): Uint8Array {
    return p256.sign(new TextEncoder().encode(payload), priv, { prehash: true });
}
