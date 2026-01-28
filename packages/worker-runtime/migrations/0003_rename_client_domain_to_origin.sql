-- Migration number: 0003 	 2026-01-27T16:42:00.000Z

ALTER TABLE clients RENAME COLUMN domain TO origin;
