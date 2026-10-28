-- ECNUchat v2 production relay — Cloudflare D1 schema (see worker.mjs).
-- Envelopes are opaque base64; no plaintext, private key, password,
-- or passphrase is ever stored here. Apply once with:
--   wrangler d1 execute ecnu-chat-v2-relay --file schema.sql
CREATE TABLE IF NOT EXISTS devices (
  username TEXT NOT NULL, device TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (username, device)
);
CREATE TABLE IF NOT EXISTS envelopes (
  id TEXT PRIMARY KEY, username TEXT NOT NULL, device TEXT NOT NULL,
  data TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked (
  username TEXT NOT NULL, device TEXT NOT NULL, revoked_at TEXT NOT NULL,
  PRIMARY KEY (username, device)
);
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL
);
