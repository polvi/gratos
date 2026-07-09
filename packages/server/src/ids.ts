// Object-id escaping — a shared storage/wire contract.
//
// AuthGravity object ids may not contain ':' or '#' (they delimit
// "type:id#relation"), and the server's ID_RE allows only
// [A-Za-z0-9_@./=+-]{1,128}. App-native ids routinely contain ':' (ISO
// timestamps, URNs) or other characters, so they must be escaped into that
// alphabet — reversibly, or two callers write different stored ids for the same
// logical id.
//
// Scheme "v1" (quoted-printable with '=' as sentinel): every byte outside the
// safe set is emitted as '=' + two uppercase hex digits (per UTF-8 byte);
// everything else is emitted verbatim. The output alphabet is a strict subset
// of ID_RE, so the SERVER NEEDS NO CHANGE — the escaped form is the canonical
// stored form. This exact scheme must be mirrored byte-for-byte in
// @authgravity/browser and documented for raw-HTTP callers.

/** ID_RE minus the '=' sentinel — bytes emitted verbatim. */
const SAFE = /[A-Za-z0-9_@./+-]/;

/** The server's ID_RE length cap. Applies to the ESCAPED form. */
export const MAX_OBJECT_ID_LENGTH = 128;

/**
 * Escape an arbitrary app id into the AuthGravity object-id alphabet.
 * Throws (never truncates) if the escaped form exceeds the length cap —
 * truncation would alias two distinct ids onto one authorization scope.
 */
export function escapeObjectId(id: string): string {
    const bytes = new TextEncoder().encode(id);
    let out = '';
    for (const b of bytes) {
        if (b < 0x80 && SAFE.test(String.fromCharCode(b))) {
            out += String.fromCharCode(b);
        } else {
            out += '=' + b.toString(16).toUpperCase().padStart(2, '0');
        }
    }
    if (out.length > MAX_OBJECT_ID_LENGTH) {
        throw new Error(
            `object id is too long after escaping (${out.length} > ${MAX_OBJECT_ID_LENGTH} chars): shorten the id`
        );
    }
    return out;
}

/** Inverse of escapeObjectId. Throws on a malformed escape sequence. */
export function unescapeObjectId(escaped: string): string {
    const bytes: number[] = [];
    for (let i = 0; i < escaped.length; i++) {
        const c = escaped[i];
        if (c === '=') {
            const hex = escaped.slice(i + 1, i + 3);
            if (!/^[0-9A-Fa-f]{2}$/.test(hex)) {
                throw new Error(`malformed escape at index ${i} in "${escaped}"`);
            }
            bytes.push(parseInt(hex, 16));
            i += 2;
        } else {
            bytes.push(c.charCodeAt(0) & 0xff);
        }
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
}

/** Build an object ref "type:escape(id)" from a raw app id. */
export function objectRef(type: string, rawId: string): string {
    return `${type}:${escapeObjectId(rawId)}`;
}

/**
 * Parse a stored ref "type:id" back to its raw form. Splits on the first ':'
 * (server semantics) and unescapes ONLY the id segment — type/relation names
 * are never escaped.
 */
export function parseObjectRef(ref: string): { type: string; id: string } {
    const i = ref.indexOf(':');
    if (i === -1) throw new Error(`not an object ref: "${ref}"`);
    return { type: ref.slice(0, i), id: unescapeObjectId(ref.slice(i + 1)) };
}
