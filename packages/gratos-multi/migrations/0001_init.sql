CREATE TABLE users (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL
);
CREATE INDEX idx_users_tenant ON users(tenant);

CREATE TABLE public_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tenant TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  user_backed_up BOOLEAN,
  transports TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(tenant, credential_id)
);
CREATE INDEX idx_public_keys_tenant ON public_keys(tenant);
CREATE INDEX idx_public_keys_credential ON public_keys(tenant, credential_id);
