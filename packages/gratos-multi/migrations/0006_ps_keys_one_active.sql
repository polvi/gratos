-- One ACTIVE signing key per tenant, enforced by SQLite. Before this,
-- concurrent first-use generates could both land (readers converged on the
-- oldest row but the loser stayed in the JWKS forever). Retire all but the
-- oldest active row per tenant, then add a partial unique index so
-- generateKey's INSERT OR IGNORE serializes the race at the database.

UPDATE ps_keys
SET retired_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000
WHERE retired_at IS NULL
  AND kid <> (
    SELECT p.kid FROM ps_keys p
    WHERE p.tenant = ps_keys.tenant AND p.retired_at IS NULL
    ORDER BY p.created_at ASC, p.kid ASC
    LIMIT 1
  );

CREATE UNIQUE INDEX idx_ps_keys_one_active ON ps_keys(tenant) WHERE retired_at IS NULL;
