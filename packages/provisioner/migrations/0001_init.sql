CREATE TABLE pending_claims (
  id TEXT PRIMARY KEY,
  identity_id TEXT,
  domain TEXT NOT NULL UNIQUE,
  cf_hostname_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE domains (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  cf_hostname_id TEXT NOT NULL,
  claimed_at INTEGER NOT NULL
);
