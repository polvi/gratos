-- Add per-claim token for unique CNAME challenges (authgravity-{token}.{domain}).
-- Multiple pending claims per domain are now allowed.
ALTER TABLE pending_claims ADD COLUMN token TEXT NOT NULL DEFAULT '';

-- Drop the UNIQUE constraint on domain by recreating the table.
-- SQLite doesn't support DROP CONSTRAINT, so we migrate data.
CREATE TABLE pending_claims_new (
  id TEXT PRIMARY KEY,
  identity_id TEXT,
  domain TEXT NOT NULL,
  token TEXT NOT NULL,
  cf_hostname_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_pending_claims_domain ON pending_claims_new(domain);

INSERT INTO pending_claims_new (id, identity_id, domain, token, cf_hostname_id, created_at)
  SELECT id, identity_id, domain, '', cf_hostname_id, created_at FROM pending_claims;

DROP TABLE pending_claims;
ALTER TABLE pending_claims_new RENAME TO pending_claims;
