-- AAuth Person Server: per-tenant signing keys, durable consent grants,
-- missions (agent governance) and their append-only log.

-- Ed25519 tenant signing keys. Private halves are AES-256-GCM-wrapped with a
-- KEK derived from the PS_KEK secret (dev fallback KEK when unset), so a D1
-- export alone yields nothing usable.
CREATE TABLE ps_keys (
  kid TEXT PRIMARY KEY,            -- RFC 7638 JWK thumbprint
  tenant TEXT NOT NULL,
  public_jwk TEXT NOT NULL,        -- {"kty":"OKP","crv":"Ed25519","x":...}
  private_wrapped TEXT NOT NULL,   -- base64url( iv || AES-256-GCM(KEK, pkcs8) )
  kek_id TEXT NOT NULL,            -- 'dev' or sha256-prefix of PS_KEK
  created_at INTEGER NOT NULL,
  retired_at INTEGER
);
CREATE INDEX idx_ps_keys_tenant ON ps_keys(tenant);

-- Durable "remember this approval" consent: (agent identity, resource) → user.
CREATE TABLE aauth_grants (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  user_id TEXT NOT NULL,
  agent_iss TEXT NOT NULL,
  agent_sub TEXT NOT NULL,
  resource TEXT NOT NULL,          -- resource token iss == auth token aud
  scope TEXT NOT NULL,             -- space-separated, sorted
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  expires_at INTEGER,
  revoked_at INTEGER,
  UNIQUE(tenant, agent_iss, agent_sub, resource)
);
CREATE INDEX idx_aauth_grants_tenant_user ON aauth_grants(tenant, user_id);

-- Missions: D1-backed so proposals can await consent for days (asynchronous,
-- possibly third-party approval). s256 identifies the APPROVED blob.
CREATE TABLE aauth_missions (
  id TEXT PRIMARY KEY,             -- uuid
  s256 TEXT UNIQUE,                -- base64url sha256 of approved mission_json bytes
  tenant TEXT NOT NULL,
  user_id TEXT,                    -- approver; stamped at consent
  approver_hint TEXT,              -- intended approver UUID from proposal; NULL = code-holder
  agent_iss TEXT NOT NULL,
  agent_sub TEXT NOT NULL,
  agent_jwk TEXT NOT NULL,         -- proposal-time cnf snapshot
  proposal_json TEXT NOT NULL,     -- as proposed (incl. budgets)
  mission_json TEXT,               -- exact approved blob; s256 hashes these bytes
  code_hash TEXT,                  -- sha256 of the single-use consent code
  status TEXT NOT NULL,            -- proposed|active|completed|declined|revoked|expired
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,     -- proposal window (default 7d, <= 30d)
  approved_at INTEGER,
  closed_at INTEGER
);
CREATE INDEX idx_aauth_missions_tenant_user ON aauth_missions(tenant, user_id);
CREATE INDEX idx_aauth_missions_code ON aauth_missions(tenant, code_hash);

-- Ordered record of agent<->PS interactions per mission.
CREATE TABLE aauth_mission_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,   -- token_request|permission|audit|interaction|clarification|approval|completion|revocation|federation
  entry_json TEXT NOT NULL
);
CREATE INDEX idx_aauth_mission_log ON aauth_mission_log(tenant, mission_id, id);
