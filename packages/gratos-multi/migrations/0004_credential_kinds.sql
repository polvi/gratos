-- Credential kinds for non-WebAuthn credentials (account keys, device keys).
-- Existing rows are passkeys.
ALTER TABLE public_keys ADD COLUMN kind TEXT NOT NULL DEFAULT 'webauthn';
ALTER TABLE public_keys ADD COLUMN label TEXT;
ALTER TABLE public_keys ADD COLUMN created_at INTEGER;
ALTER TABLE public_keys ADD COLUMN last_used_at INTEGER;
