// Capability detection: which auth method should this device lead with. Every
// app was hand-rolling a slightly-wrong version of this; ship one.

export type AuthMethod = 'passkey' | 'account-key';

/** True if the browser exposes the WebAuthn API at all. */
export function supportsPasskeys(): boolean {
    return typeof (globalThis as any).PublicKeyCredential !== 'undefined';
}

/**
 * Suggest whether to lead with a passkey or an account key. Leads with passkeys
 * only when a user-verifying PLATFORM authenticator is actually available
 * (biometric / device PIN); otherwise account keys, which work everywhere.
 * Errs toward account keys when detection is unavailable or throws.
 */
export async function suggestedMethod(): Promise<AuthMethod> {
    try {
        const PKC = (globalThis as any).PublicKeyCredential;
        if (PKC && typeof PKC.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
            const available = await PKC.isUserVerifyingPlatformAuthenticatorAvailable();
            return available ? 'passkey' : 'account-key';
        }
    } catch {
        // fall through
    }
    return 'account-key';
}
