// SHA-256 → lowercase hex. Used to key the sandbox rate limiter on a hash of
// the caller's IP rather than the raw IP: per the project's privacy rule, we
// may *use* the (already-public) IP in the moment but must never store or log
// it, and a KV key is stored state.

export async function sha256Hex(input: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    const bytes = new Uint8Array(digest);
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    return hex;
}
