-- Ephemeral sandbox tenants minted via POST /sandbox.
-- `id` is the full sandbox host (e.g. "abc123.sandbox.authgravity.org"), which
-- is also the tenant key used in users/public_keys. `created_at` (unix ms) drives
-- TTL cleanup of throwaway sandbox pools.
CREATE TABLE sandboxes (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_sandboxes_created_at ON sandboxes(created_at);
