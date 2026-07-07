// REFERENCE IMPLEMENTATION of the account-key spec. This is the executable
// specification that browser clients (the /demo page, the llms.txt recipe)
// must match — the golden vectors in keyspec.test.ts pin it down.
//
// Spec summary:
// - Secret: 16 bytes of entropy. Two interchangeable renderings:
//   - compact: "agak1_" + base32(entropy, 26 chars) + base32(checksum, 4 chars)
//     where base32 uses lowercase RFC 4648 alphabet (a-z, 2-7), no padding,
//     and checksum = first 20 bits of SHA-256(entropy).
//   - words: standard BIP39 entropy->mnemonic (12 words: 128 bits + first
//     4 bits of SHA-256(entropy), 11 bits per word, English wordlist).
// - Key derivation, per tenant:
//     okm = HKDF-SHA256(ikm=entropy, salt=utf8(tenantKey), info="authgravity/softkey/v1", len=40)
//     d   = (BigInt(okm) mod (n-1)) + 1        // P-256 private scalar
//     public key = 65-byte uncompressed point, base64url on the wire
// - Signatures: ECDSA P-256 / SHA-256, 64-byte r||s, over the utf8 payload
//     `${context}\n${challenge}\n${tenant}`
//   with context "authgravity-key-register-v1" or "authgravity-key-login-v1".

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { WORDLIST } from '../src/wordlist';

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
export const COMPACT_PREFIX = 'agak1_';
export const DERIVATION_INFO = 'authgravity/softkey/v1';

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
    // First 20 bits of SHA-256(entropy) as 4 base32 chars.
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
    // BIP39: 128 entropy bits + first 4 bits of SHA-256 -> 12 x 11-bit indices.
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
    // 64-byte r||s over SHA-256(payload) — what WebCrypto verify expects.
    return p256.sign(new TextEncoder().encode(payload), priv, { prehash: true });
}

export const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
export const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
export const fromHex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
