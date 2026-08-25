-- Optional WebAuthn RP ID for a sandbox. NULL keeps the default ("localhost").
-- Set at mint time (POST /sandbox {rp_id}) so a dev proxy served on a real
-- hostname (e.g. a tailnet HTTPS host) can run the passkey ceremony there.
ALTER TABLE sandboxes ADD COLUMN rp_id TEXT;
