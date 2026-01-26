-- Migration number: 0002 	 2026-01-26T13:52:00.000Z

CREATE TABLE clients (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  domain_setting TEXT NOT NULL,
  created_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
