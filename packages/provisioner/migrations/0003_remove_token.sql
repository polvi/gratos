-- Remove token column: CNAME target is now always cname.authgravity.net.
-- Claims expire after 4 hours instead of using per-claim tokens.
-- Re-add UNIQUE constraint on domain (one pending claim per domain).
CREATE TABLE pending_claims_new (
  id TEXT PRIMARY KEY,
  identity_id TEXT,
  domain TEXT NOT NULL UNIQUE,
  cf_hostname_id TEXT,
  created_at INTEGER NOT NULL
);

INSERT INTO pending_claims_new (id, identity_id, domain, cf_hostname_id, created_at)
  SELECT id, identity_id, domain, cf_hostname_id, created_at FROM pending_claims;

DROP TABLE pending_claims;
ALTER TABLE pending_claims_new RENAME TO pending_claims;
