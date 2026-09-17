-- Passkey metadata for multi-passkey accounts: the authenticator AAGUID (used
-- to derive a provider display name such as "iCloud Keychain") and the WebAuthn
-- signature counter (clone detection). Existing rows: unknown AAGUID, counter 0.
ALTER TABLE public_keys ADD COLUMN aaguid TEXT;
ALTER TABLE public_keys ADD COLUMN counter INTEGER NOT NULL DEFAULT 0;
