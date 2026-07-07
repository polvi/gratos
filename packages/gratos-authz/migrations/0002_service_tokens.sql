-- Per-tenant service tokens: owner-minted credentials that let the tenant's
-- application backend write relationships and run checks at runtime
-- (Authorization: Bearer agk_...). Only the SHA-256 hash is stored.
CREATE TABLE service_tokens (
    id           TEXT PRIMARY KEY,
    tenant       TEXT NOT NULL,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE INDEX idx_service_tokens_tenant ON service_tokens (tenant);
