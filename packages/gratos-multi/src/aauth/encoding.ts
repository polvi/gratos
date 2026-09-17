// Shared byte/base64url helpers for the AAuth modules (nodejs_compat Buffer,
// same approach as keys.ts).

// @ts-ignore
import { Buffer } from 'node:buffer';

export function b64u(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

export function b64uDecode(s: string): Uint8Array {
    return new Uint8Array(Buffer.from(s, 'base64url'));
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

export async function sha256B64u(input: string | Uint8Array): Promise<string> {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    return b64u(await sha256(bytes));
}

/**
 * AAuth protocol error → OAuth-shaped `{error, error_description}` JSON with an
 * HTTP status. Thrown by the verification pipeline; routes catch and render.
 */
export class AAuthError extends Error {
    constructor(
        public code: string,
        public description: string,
        public status: 400 | 401 | 403 | 404 | 429 | 502 = 400
    ) {
        super(`${code}: ${description}`);
    }

    body(): { error: string; error_description: string } {
        return { error: this.code, error_description: this.description };
    }
}
