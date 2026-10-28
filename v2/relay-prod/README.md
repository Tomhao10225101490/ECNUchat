# ECNUchat v2 — Production relay (Track C, code written, NOT deployed)

**Status: code written + Node-tested against an in-memory store;
NOT deployed, NOT run on Workers.** Exact blocker: no Cloudflare
account, API token, or `wrangler` installation is available to
Track C, and Track C must not touch the user's accounts. The D1
store SQL in `worker.mjs` is reviewed but has NOT been executed
against a real D1 database. Do not claim this relay is live.

## What it is

`worker.mjs` is the same HTTP JSON mailbox API as
`../relay/relay.py` (register, device list, consuming bundle fetch,
envelopes, inbox pop, inbox count, revoke), ported to Cloudflare
Workers + D1 (`schema.sql`, `wrangler.toml`). Envelopes stay opaque
base64; the worker never decrypts, never holds a private key, and
never stores a password. Rate limiting is per-client-IP fixed
window (120/min reads, 60/min writes; 429 + `retry_after_seconds`),
backed by D1 in production so it survives across isolates.

## TLS / WSS termination

- **TLS:** Cloudflare terminates TLS automatically for the
  `*.workers.dev` URL and for any custom domain proxied through
  Cloudflare. The deployed relay URL is therefore `https://...`
  Clients must refuse a non-loopback `http://` production URL (see
  `../desktop/config.js`). This worker itself serves no plain HTTP
  in production.
- **WSS:** NOT implemented. This is HTTP JSON, not WebSocket, like
  the dev relay. Clients poll `GET /v1/inbox`. No WS endpoint is
  provided or claimed, even though Workers support upgrades.
- **No long-poll:** `GET /v1/inbox` returns immediately; the dev
  relay's `wait_seconds` is accepted and ignored (documented
  difference). Use push wakes (`../push/`) to learn when to fetch.

## Known production gaps (not hidden)

- No authentication (same as the dev relay): anyone who knows a
  `username:device` can register it or send to it. Rate limiting
  is abuse friction, not auth.
- No sealed sender / metadata hiding: the relay sees sender,
  recipient, size, timestamp by design.

## Deploy (developer machine + Cloudflare account only)

```sh
cd relay-prod
npx wrangler d1 create ecnu-chat-v2-relay   # put the id in wrangler.toml
npx wrangler d1 execute ecnu-chat-v2-relay --file schema.sql
npx wrangler deploy
# Relay URL is then https://ecnu-chat-v2-relay.<subdomain>.workers.dev
```

## Relay URL configurability (clients)

Clients resolve the relay URL in this order (see
`../desktop/config.js` and the PWA's relay-URL field):

1. `ECNU_RELAY_URL` environment variable (desktop/CLI)
2. `relayUrl` in the desktop JSON config file
3. The PWA's stored relay URL / `?relay=<url>`-style user setting
4. Default `http://127.0.0.1:8765` (local dev only)

Point a client at production by setting (1) or (3) to the deployed
`https://...` URL. Never set a production URL to `http://`.
