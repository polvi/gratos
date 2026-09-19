-- App-delivered sign-in codes (src/codes.ts). One row per browser-started
-- ticket. D1, not KV: the try counter and single-use claim must be atomic
-- (conditional UPDATE/DELETE … RETURNING), or parallel guesses could lose
-- increments and exceed the attempt budget. Only hashes are stored.
CREATE TABLE code_tickets (
    tenant  TEXT NOT NULL,
    ticket  TEXT NOT NULL,
    vh      TEXT NOT NULL,             -- sha256(verifier), b64u
    exp     INTEGER NOT NULL,          -- ms epoch
    mints   INTEGER NOT NULL DEFAULT 0,
    tries   INTEGER NOT NULL DEFAULT 0,
    user_id TEXT,                      -- set by the first mint; never rebinds
    ch      TEXT,                      -- sha256(ticket:code) of the current code
    PRIMARY KEY (tenant, ticket)
);

CREATE INDEX idx_code_tickets_exp ON code_tickets (exp);
