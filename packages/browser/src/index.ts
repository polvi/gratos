// @authgravity/browser — account keys, device keys, and client helpers.

export {
    mintKey,
    decodeKey,
    keyFromEntropy,
    registerAccountKey,
    loginWithAccountKey,
    claimOrRecover,
} from './account-key';
export type { AccountKey, VerifyResult } from './account-key';

export {
    enableDeviceKey,
    trySilentLogin,
    hasDeviceKey,
    forgetDeviceKey,
} from './device-key';
export type { EnableDeviceKeyResult } from './device-key';

export { suggestedMethod, supportsPasskeys } from './capabilities';
export type { AuthMethod } from './capabilities';

export { createAccountKeySetup } from './setup';
export type { AccountKeySetup, SetupState, SetupContext, SetupOptions } from './setup';

export { runCeremony } from './ceremony';
export type { CeremonyResult, Signer } from './ceremony';

// Object-id escaping (mirror of @authgravity/server — shared storage contract).
export { escapeObjectId, unescapeObjectId, objectRef, parseObjectRef, MAX_OBJECT_ID_LENGTH } from './ids';

// Low-level crypto (the executable spec) for advanced/interop use.
export {
    encodeCompact,
    decodeCompact,
    encodeWords,
    decodeWords,
    derivePrivateKey,
    publicKeyFor,
    signPayload,
    COMPACT_PREFIX,
    DERIVATION_INFO,
} from './crypto';
