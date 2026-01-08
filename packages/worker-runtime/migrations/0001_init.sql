-- Migration number: 0001 	 2026-01-08T23:11:37.815Z

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT
);

CREATE TABLE public_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  user_backed_up BOOLEAN,
  transports TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
