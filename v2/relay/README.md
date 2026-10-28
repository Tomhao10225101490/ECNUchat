# ECNUchat v2 relay — local development relay

> ⚠️ **LOCAL DEVELOPMENT ONLY — PLAIN HTTP, NO TLS, NO WEBSOCKET, NO AUTHENTICATION.**
>
> This relay runs plain HTTP on loopback for local development only.
> It must **never** be exposed to the internet as-is. In production,
> TLS/WSS must be terminated by the deployment (reverse proxy /
> Cloudflare) in front of a production relay implementation — see
> [Deployment](#deployment). This local relay does **not** provide
> that TLS layer, and it deliberately does **not** invent
> self-signed certificates in code.
>
> This relay is a **dumb mailbox only**, per
> `../PLAN.md`: it sees ciphertext envelopes, public keys and
> metadata (who → whom, when, how big). It never sees plaintext.

## What it is

Single-file, Python standard library only — no `pip install`:

| File | Purpose |
|---|---|
| `relay.py` | The relay server (the whole implementation) |
| `relay_client.py` | Small stdlib-only test/demo client |
| `VERIFICATION.md` | Exact commands run and their outputs |
| `README.md` | This file |

Run it:

```bash
cd ~/workspace/ecnu-chat-v2/relay
python3 relay.py
# listening on http://127.0.0.1:8765 (default, matching v1)
```

Configurable host/port (client passes the relay URL; the server
binds to the configured host/port):

```bash
python3 relay.py --host 127.0.0.1 --port 8765
python3 relay.py --host 127.0.0.1 --port 9000 --db relay.db
ECNU_RELAY_HOST=127.0.0.1 ECNU_RELAY_PORT=8765 python3 relay.py
ECNU_RELAY_DB=relay.db python3 relay.py
```

Storage:

- Default: **in-memory** — everything is lost when the process stops.
- `--db <path>` / `ECNU_RELAY_DB=<path>`: **SQLite file backend** —
  device directory, queued envelopes and revocations persist across
  restarts. Pending long-polls are always in-memory by nature.

Demo client (relay URL is configurable):

```bash
python3 relay_client.py --relay-url http://127.0.0.1:8765 health
python3 relay_client.py --relay-url http://127.0.0.1:8765 register \
    --username alice --device phone --identity-key DEMO-IDENTITY-KEY-ALICE-PHONE
python3 relay_client.py --relay-url http://127.0.0.1:8765 list --username bob
python3 relay_client.py --relay-url http://127.0.0.1:8765 send \
    --sender alice:phone --recipient bob:laptop --ciphertext aGVsbG8td29ybGQ=
python3 relay_client.py --relay-url http://127.0.0.1:8765 fetch \
    --recipient bob:laptop
python3 relay_client.py --relay-url http://127.0.0.1:8765 fetch \
    --recipient bob:laptop --wait 25
python3 relay_client.py --relay-url http://127.0.0.1:8765 count \
    --recipient bob:laptop
python3 relay_client.py --relay-url http://127.0.0.1:8765 revoke \
    --username bob --device laptop
```

## Transport: HTTP JSON, NOT WebSocket — read this first

Python's standard library has no WebSocket server, so this local
relay uses **HTTP JSON** as a development substitute, with the
exact same envelope fields a WebSocket variant would carry.
**Do not describe this relay as a WebSocket server.**

How the HTTP substitute maps to the WebSocket behaviour:

| WebSocket behaviour | HTTP JSON substitute here |
|---|---|
| Recipient connected → forward immediately | Recipient has a long-poll fetch pending (`GET /v1/inbox?wait_seconds=…`, max 30 s) → the pending fetch returns immediately with the envelope; the send response reports `"delivered_online": true` |
| Recipient offline → queue | No long-poll pending → envelope is queued; send reports `"delivered_online": false, "queued": true`; a later fetch delivers it |
| "Online" flag | A device is reported `"online": true` in device listings while it has a long-poll request pending, and `false` otherwise |

A WebSocket production variant is a **TODO**, not something this
file implements. It would need the same envelope fields, a
persistent connection per device, and TLS/WSS (below).

## API

Base URL: `http://127.0.0.1:8765` by default. All request/response
bodies are JSON. All error bodies have the shape
`{"error": "<CODE>", "message": "<human-readable>"}`.

Addresses are always the string `username:device`, e.g.
`alice:phone`. Usernames: 3–20 characters, letters/digits/`_`/`.`/`-`.
Devices: 1–64 characters, same alphabet. These limits follow the
PLAN.md username rule (3–20 chars); the device alphabet is this
relay's own validation and is documented as such.

### `GET /health` and `GET /`

Service info. No user data.

```json
{
  "status": "ok",
  "service": "ecnu-chat-v2-relay",
  "transport": "http-json-dev (NOT WebSocket)",
  "protocol_version": "v1",
  "tls": "none-local-dev-only; production must terminate TLS at the deployment"
}
```

### `POST /v1/devices/register` — register or update a device

Registers a device's **public keys only**. Registering an already
registered `username:device` **updates** its public keys (keeping
the original `registered_at`, refreshing `updated_at`) and does
**not** drop its queued envelopes. Updating is not revocation.

Request:

| Field | Required | Meaning |
|---|---|---|
| `username` | yes | 3–20 chars (see above) |
| `device` | yes | 1–64 chars (see above) |
| `identity_key` | no | Public identity key (opaque string, e.g. base64) |
| `signed_prekey` | no | Public signed prekey (opaque string) |
| `one_time_prekeys` | no | List of public one-time prekeys (opaque strings) |
| `public_keys` | no | Object of additional public keys, stored verbatim — this is where the PWA publishes its post-quantum bundle fields (see below) |
| any other public field | no | Stored verbatim and returned on list (see below) |

### Post-quantum bundle fields (inside `public_keys`)

The PWA publishes its ML-KEM-768 bundle inside the same
`public_keys` object, stored verbatim like any other public key:

| Field | Meaning |
|---|---|
| `pq_pub` | Long-term PQK public key (1184 bytes, base64) |
| `pq_sig` | Ed25519 signature over `pq_pub \|\| username` (base64) |
| `pq_opks` | List of one-time PQOPKs, each `{pub, sig}`; `sig` is Ed25519 over `"pq-opk-v1\x00" \|\| pub \|\| username`. Pool of 8, refill below 2 (v1 rule) |

Only public keys and signatures are ever published. The relay
**rejects** (400 `PRIVATE_DATA_REJECTED`) any request containing
`private_key`, `privatekey`, `secret_key`, `password`,
`passphrase`, `seed`, `mnemonic`, or any field ending in `_seed`
(in particular `pq_seed`), at any nesting level. Private keys
never leave a device; a client that tries to upload one is
refused, not silently stored. No password is ever accepted or
stored by this relay.

Response (200):

```json
{
  "username": "bob",
  "device": "laptop",
  "address": "bob:laptop",
  "identity_key": "DEMO-IK-BOB-LAPTOP",
  "signed_prekey": null,
  "one_time_prekeys": null,
  "public_keys": null,
  "registered_at": "2026-10-28T07:22:33Z",
  "updated_at": "2026-10-28T07:22:33Z",
  "online": false
}
```

### `GET /v1/devices?username=<username>` and `GET /v1/devices/<username>` — device list

List all registered devices for one username, with their public
keys. No private data is ever returned because none is ever stored.

Response (200):

```json
{
  "username": "bob",
  "devices": [
    {
      "username": "bob", "device": "laptop", "address": "bob:laptop",
      "identity_key": "DEMO-IK-BOB-LAPTOP",
      "signed_prekey": null, "one_time_prekeys": null,
      "public_keys": null,
      "registered_at": "2026-10-28T07:22:33Z",
      "updated_at": "2026-10-28T07:22:33Z",
      "online": true
    }
  ]
}
```

`online` is true only while that device has a long-poll fetch
pending (see "Transport" above).

### `POST /v1/bundles/fetch` — fetch one device's bundle, consuming one OPK

This is the ONLY consuming endpoint. It returns one device's bundle
with exactly one one-time prekey consumed (mirroring v1's
`fetch_bundle`, which deletes one OPK row per fetch): the returned
`opk_pub` is the consumed key, and it is removed from every pool
field in the stored record before returning, so it is never
re-served as fresh. `opks_remaining` is the pool size left after
consumption. If the pool is empty, `opk_pub` is `null` (v1 allows
an initial message without DH4); the caller must not invent an OPK.

Use it ONLY when an initiator starts a NEW session. A receiver
verifying a sender's identity must use the non-consuming device
list above — consuming the sender's OPK on receipt would burn the
sender's pool for no session. Device listing never consumes.

PQ analogue, same rule, separate pool: the fetch additionally
consumes exactly one PQOPK and returns it as `pq_opk`
(`{pub, sig}`), with `pq_opk_pub` / `pq_opk_sig` conveniences and
`pq_opks_remaining` (pool size left after consumption), plus the
peer's `pq_pub` / `pq_sig` for verification. The initiator MUST
encapsulate to the returned `pq_opk` — after this fetch,
`public_keys.pq_opks` in the response holds only the unconsumed
remainder, and encapsulating to one of those would let a later
fetch re-serve the same key. A consumed PQOPK is never re-served
as fresh, exactly like a classical OPK. If the peer publishes a
PQK but no PQOPK, `pq_opk` is `null` and `pq_opks_remaining` is
`0` (the initiator falls back to the long-term PQK). If the peer
publishes no PQ fields at all, `pq_opk` is `null` and
`pq_opks_remaining` is `null`. Classical OPK consumption is
unchanged and independent of PQOPK consumption.

Request: `{"username": "<username>", "device": "<device>"}` (or
`{"recipient": "<username:device>"}`). Errors: 400
`INVALID_ADDRESS`, 404 `DEVICE_NOT_FOUND`, 410 `DEVICE_REVOKED`.

### `POST /v1/envelopes` — send an envelope

Stores an opaque envelope for the recipient device, or wakes its
pending long-poll (online forwarding). **The relay does not
decrypt, parse or re-encode the ciphertext.** It checks only that
`ciphertext` is well-formed base64 and ≤ 1,048,576 base64
characters; anything beyond that is the client's crypto, which
the relay treats as opaque bytes.

Request:

| Field | Required | Meaning |
|---|---|---|
| `sender` | yes | `"username:device"` of the sender |
| `recipient` | yes | `"username:device"` of the recipient device (one envelope per recipient device; a sender messaging a user with several devices sends one envelope per device, as in v1 group messaging) |
| `ciphertext` | yes | Opaque ciphertext, base64-encoded. The relay never logs or inspects its decoded bytes |
| `envelope_id` | no | Client-supplied id; server generates a UUID if absent |
| `protocol_version` | no | Defaults to `"v1"` (the frozen v1 envelope format) |
| `message_type` | no | Opaque passthrough, e.g. `"text"` |
| `pq_ct` | no | Opaque passthrough for hybrid envelopes: the 1088-byte (base64) ML-KEM encapsulation of the current ratchet chain, carried on every hybrid message |
| any other field | no | **Opaque passthrough**: stored verbatim and returned verbatim on delivery. This is how future crypto header fields (ratchet headers, nonces, sender-key material, …) survive the relay without the relay needing to understand them |

The sender does **not** need to be registered with this dev relay
(no authentication — see "What is NOT implemented"). The
recipient device **must** be registered and not revoked.

Response (201):

```json
{
  "envelope_id": "a78db6e3-a970-4bec-a42b-67305393cea4",
  "sender": "alice:phone",
  "recipient": "bob:laptop",
  "timestamp": "2026-10-28T07:22:33Z",
  "delivered_online": false,
  "queued": true
}
```

`delivered_online: true` means a long-poll fetch for that device
was pending at send time and was woken; `queued: true` means the
envelope is stored for a later fetch.

### `GET /v1/inbox?recipient=<username:device>[&wait_seconds=<0–30>]` and `POST /v1/inbox/fetch`

Deliver the recipient device's queued envelopes **and delete them
after delivery** (at-most-once, pop semantics). A second fetch
returns an empty list. If the client crashes after fetching but
before processing, those envelopes are lost — that is this dev
relay's documented delivery semantics; a production relay should
use explicit acknowledgement before deletion (TODO, see below).

`wait_seconds` (GET query, or `wait_seconds` in the POST JSON
body) enables long-polling: if the inbox is empty, the request
waits up to that many seconds (clamped to 0–30, default 0) for a
new envelope instead of returning empty immediately. This is the
HTTP substitute for "recipient is online" (see "Transport").

The POST form takes `{"recipient": "bob:laptop"}` or
`{"recipient_username": "bob", "recipient_device": "laptop"}`,
plus optional `wait_seconds`. The GET form takes
`recipient=bob:laptop` (URL-encoded as `bob%3Alaptop`) or
`recipient_username` + `recipient_device`.

Response (200) — every envelope field, exactly as sent, plus
server-added routing/timestamp fields:

```json
{
  "recipient": "bob:laptop",
  "delivered_count": 1,
  "envelopes": [
    {
      "envelope_id": "a78db6e3-a970-4bec-a42b-67305393cea4",
      "sender": "alice:phone",
      "sender_username": "alice",
      "sender_device": "phone",
      "recipient": "bob:laptop",
      "recipient_username": "bob",
      "recipient_device": "laptop",
      "ciphertext": "aGVsbG8td29ybGQ=",
      "ciphertext_encoding": "base64",
      "protocol_version": "v1",
      "timestamp": "2026-10-28T07:22:33Z",
      "message_type": "text"
    }
  ]
}
```

Field notes:

- `sender` / `recipient` are the canonical `"username:device"`
  strings supplied by the sender; `sender_username`,
  `sender_device`, `recipient_username`, `recipient_device` are
  the same addresses split by the server for convenience.
- `ciphertext_encoding` is always `"base64"` (server-set).
- `timestamp` is the server receipt time (UTC, ISO-8601 `Z`).
- `protocol_version` defaults to `"v1"` unless the sender supplied
  another value; the relay does not enforce a version, it records it.
- Any extra field the sender included (e.g. a ratchet header) is
  returned verbatim in the same envelope object.

### `GET /v1/inbox/count?recipient=<username:device>` — queue size only

Returns only metadata, never envelope contents:

```json
{ "recipient": "bob:laptop", "queued": 1 }
```

### Revocation: `POST /v1/devices/<username>/<device>/revoke` and `DELETE /v1/devices/<username>/<device>`

Both forms do the same thing. Response (200):

```json
{
  "username": "bob", "device": "laptop", "address": "bob:laptop",
  "revoked": true, "was_registered": true,
  "queued_envelopes_dropped": true,
  "revoked_at": "2026-10-28T07:22:42Z"
}
```

Revocation semantics (exact):

1. The device is removed from the public-key directory: it no
   longer appears in device listings.
2. Its queued envelopes are **dropped** (deleted, never delivered).
3. It stops receiving new messages: sending to it returns
   **410 `DEVICE_REVOKED`**, and fetching its inbox returns
   **410 `DEVICE_REVOKED`** (not 404, so callers can tell
   "deliberately revoked" from "never existed").
4. Revoking a never-registered device still records the revocation,
   so later sends to it also get 410 rather than a misleading 404.
   `was_registered` tells the caller whether it had existed.
5. **Explicit re-registration is a new device:** if the same
   `username:device` is registered again after revocation, the
   revocation record is cleared and the device receives messages
   again. Revocation blocks the *old* device record; it is not a
   permanent ban on that device name, because a user who
   deliberately re-adds a device (e.g. after reinstall) must be
   able to. Clients that need a permanent block must enforce it
   above the relay.
6. Revocation does **not** delete messages already delivered to
   the device, and does **not** affect the user's other devices.

## Error cases

All errors: HTTP status + `{"error": "<CODE>", "message": "…"}`.

| HTTP | Code | When |
|---|---|---|
| 400 | `INVALID_JSON` | Body is not a JSON object |
| 400 | `PRIVATE_DATA_REJECTED` | Body contains `private_key` / `password` / `seed` / `pq_seed` / any `*_seed` field (never sent to a relay) |
| 400 | `INVALID_USERNAME` | Username not 3–20 chars of letters/digits/`_`/`.`/`-` |
| 400 | `INVALID_DEVICE` | Device not 1–64 chars of the same alphabet |
| 400 | `INVALID_ADDRESS` | `sender`/`recipient` not a well-formed `username:device` |
| 400 | `INVALID_SENDER` / `INVALID_RECIPIENT` | `sender` / `recipient` field malformed |
| 400 | `MISSING_CIPHERTEXT` | No `ciphertext` field |
| 400 | `INVALID_CIPHERTEXT` | `ciphertext` is not valid base64 |
| 400 | `ENVELOPE_TOO_LARGE` | `ciphertext` exceeds 1,048,576 base64 chars |
| 400 | `MISSING_USERNAME` | `GET /v1/devices` without `username` |
| 400 | `INVALID_WAIT` | `wait_seconds` is not a number (clamped to 0–30 if numeric) |
| 404 | `DEVICE_NOT_FOUND` | Recipient device never registered (and never revoked) |
| 404 | `NOT_FOUND` | Unknown route |
| 410 | `DEVICE_REVOKED` | Recipient device revoked (send, fetch and count all return this) |
| 500 | `INTERNAL_ERROR` | Unexpected server error (details go to the server log only, never to the client, and never include payload data) |

## Logging and privacy

- Logs contain **only**: operation, username, device, envelope id,
  envelope size (base64 character count), delivered/queued flag,
  and timestamp. Example:
  `envelope id=… sender=alice:phone recipient=bob:laptop size=16 delivered_online=False`
- Logs **never** contain: ciphertext, decoded envelope bytes,
  public-key values, or any extra passthrough field.
- The relay **never decrypts** anything, **never stores** a
  password or private key, and **never accepts** one (see above).
- Metadata the relay *can* still see (by design, PLAN.md): who
  messaged whom, when, and how large the envelope was. This relay
  is not anonymous and does not claim to be: stronger metadata
  protection (sealed sender / header encryption) is a separate
  protocol upgrade, not something this relay provides.

## Deployment

### Local development (this code)

Plain HTTP on loopback only, default `127.0.0.1:8765`. Binding to
a non-loopback host with this code is not recommended: there is
no TLS and no authentication, so anyone who can reach it can
register devices and read queued envelopes for any device they
name. Keep it on `127.0.0.1`.

### Production target (not implemented by this code)

Per PLAN.md, the production target is **Cloudflare Workers +
D1/R2 (free tier)**. That deployment is a separate implementation
of the same API contract, and it must provide what this dev relay
deliberately does not:

1. **TLS/WSS required.** All production traffic must be `https://`
   / `wss://`. TLS is terminated by the deployment (Cloudflare /
   reverse proxy), not by application code generating certificates.
2. **WebSocket variant** of this API (persistent per-device
   connections, same envelope fields), replacing HTTP long-polling.
3. **Authentication / authorisation** for register/send/fetch
   (this dev relay has none), and rate limiting.
4. **Acknowledged delivery** (delete after explicit client ack)
   instead of this dev relay's pop-on-fetch semantics.
5. Durable storage (D1 for the directory/queues, R2 for larger
   payloads if needed) with the same revocation semantics above.

Until those exist, do not describe any deployment of this file as
production, and do not point real users at it over a network.

## What is NOT implemented (stubs / TODOs — not claimed as done)

- ❌ WebSocket transport — HTTP JSON long-poll only (this file).
- ❌ TLS/WSS in the relay itself — must come from the deployment.
- ❌ Authentication, authorisation, rate limiting — anyone who can
  reach this dev server can use it.
- ❌ End-to-end encryption itself — the relay only carries opaque
  envelopes; X3DH + double ratchet + AES-256-GCM + ML-KEM-768
  live in the clients (v1 `protocol.py`, frozen as v1).
- ❌ Sealed sender / metadata hiding — the relay sees sender,
  recipient, size and timestamp by design.
- ❌ MLS / large-group Sender Keys — not a relay function; listed
  here only so it is not mistaken for implemented.
- ❌ Push notifications, voice/WebRTC signalling beyond carrying
  opaque envelopes, backup storage beyond opaque envelopes —
  none of these are implemented by this relay.
- ❌ Acknowledged (ack-before-delete) delivery — fetch deletes
  immediately (pop semantics); see above.
- ❌ Interoperability testing against the existing Python v1
  client — the envelope fields are designed to match v1, but no
  v1-client interop run was part of this relay-only build, and
  none is claimed. That is stage-1 follow-up work for the client
  side, not something this relay can prove alone.
- ❌ Production Cloudflare Workers/D1/R2 deployment — target
  architecture only (see "Deployment").

## Security notes for integrators

- Treat envelope ids and timestamps as relay-assigned metadata,
  not as cryptographic proof of anything.
- Clients must verify public keys out-of-band (fingerprint /
  QR, per PLAN.md) — this dev relay does not vouch for a key
  because it does not authenticate the registrant.
- Do not put secrets, passwords or private keys in relay URLs,
  query strings or request bodies; query strings are logged by
  many HTTP stacks, and this relay's rejection of private-key
  fields covers bodies, not URLs.
