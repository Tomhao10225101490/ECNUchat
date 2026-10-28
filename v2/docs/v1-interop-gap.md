# ECNUchat v2 ↔ Python v1 interop gap — precise analysis

Status: **NOT interoperable.** No wrapper-only bridge can deliver a v2
message to a v1 client (or vice versa) today with end-to-end
authentication intact. This document lists every incompatible item found
by reading the v1 sources, what a bridge would have to translate for
each item, and what must NOT be weakened. It is the Track 2 outcome
(option b: gap document, not a bridge) because the blockers below are
endpoint-level, not transport-level — a translator that only rewrites
wrappers cannot fix them without holding private keys or dropping
signature checks, both of which are forbidden (see §5).

Sources read (page-text fetch only; v1 was never downloaded, modified,
or run here — the original repo is untouched):
`https://github.com/Tomhao10225101490/ECNUchat`, branch `main`,
`src/protocol.py`, `src/x3dh.py`, `src/double_ratchet.py`,
`src/prekeys.py`, `src/client.py`, `src/server.py`, `src/store.py`.
V2 side: `pwa/crypto.js`, `pwa/app.js`, `relay/relay.py` in this tree.

## 1. Verdict in one paragraph

The classical wire crypto is compatible (proven, §2). Everything
around it is not: the bundle signature covers a different message
(§3 G1), a real v1 client refuses classical handshakes when it has a
PQ key (§3 G2), the inner plaintext has a different format (§3 G3),
one-time prekeys are consumed on the v1 side and re-served forever on
the v2 side (§3 G6), and the v1 server demands a signed login
challenge plus a friendship edge before delivering anything (§3 G8).
A bridge can translate the transport wrapper (§3 G4) and field names
(§3 G5) — that is the easy 20%. The other 80% needs endpoint changes
on the v2 side (§6), in that order. Until then, any claim of "v2 talks
to v1" is false, and this document must stay attached to any bridge
proposal that claims otherwise.

## 2. What IS compatible (proven by test, not just by reading)

Run: `/tmp/ecnu-venv/bin/python tests/test_v1_classical_crosscheck.py`
— **11/11 PASS** (plus 2 controls). Both directions, first message +
reply + second message after a full DH-ratchet turn, JS
(`pwa/crypto.js`, real tweetnacl + WebCrypto) on one side and a
spec-derived Python model of v1's classical path on the other
(the model is NOT the v1 code — see the test header for the exact
scope; v1 code was read, not executed).

| Item | v1 | v2 | Evidence |
|---|---|---|---|
| X3DH classical DH order | DH1 = IK_A × SPK_B, DH2 = EK_A × IK_B, DH3 = EK_A × SPK_B, DH4 = EK_A × OPK_B (`x3dh.py` initiator/responder) | identical order (`crypto.js` x3dhInitiatorSecret / x3dhResponderSecret) | crosscheck directions A + B decrypt |
| X3DH KDF | HKDF-SHA256, salt 32 zero bytes, info `x3dh-v1`, 32 bytes (`X3DH_INFO`) | identical (`hkdfSk`) | same |
| Initial-message signature (classical) | Ed25519 over `ik_dh_pub \|\| ek_pub \|\| (opk_pub or "")` plus empty PQ fields (`verify_initial`) | identical bytes (`x3dhInitiatorSecret` / `x3dhResponderSecret`) | Python verifies JS initial sig; JS verifies Python initial sig |
| Ratchet KDF | `kdf_rk`: HKDF(ikm = dh_out, salt = rk, info `dr-v1`, 64) → RK\|\|CK; `kdf_ck`: MK = HMAC(ck, 0x01), CK' = HMAC(ck, 0x02) | identical (`kdfRk`, `kdfCk`) | ratchet turn in both directions decrypts |
| AAD | `sender \|\| receiver \|\| n (4-byte BE) \|\| pn (4-byte BE) \|\| dh_pub` (`build_aad`) | identical (`buildAad`); both sides use **bare usernames** — v2 `app.js` passes `profile.username` / friend username, NOT `username:device` | same |
| AEAD | AES-256-GCM, 12-byte nonce, 16-byte tag | identical (WebCrypto) | same |
| Skip / replay | `MAX_SKIP = 40`, `MAX_SEEN = 160`, skipped-key cache keyed by dh_pub + n, retired-key replay rejection | identical constants and rules (`MAX_SKIP = 40`, skipped map, retired set, seen set) | — (same rules; crosscheck runs in-order, skip behaviour already covered by v2's own Node tests) |
| Ratchet payload fields | `dh_pub, n, pn, nonce, ciphertext, kind` (default `chat`), plus `x3dh` on the first message only, plus `pq_ct` / `group` when present (`encode/decode_ratchet_payload`) | identical field names, `x3dh` on the first message only | payloads translate field-for-field |
| Fingerprint | SHA-256 of IK_sign public key, hex upper, 16 groups of 4 joined by a space (`fingerprint`) | identical rendering (`fingerprintOf`) | — (display only, but it means out-of-band verification strings match) |
| Username rule | `^[A-Za-z0-9_]{3,20}$` (`USERNAME_RE`) | same rule enforced by the relay | — |

Conclusion from §2: **the crypto core is not the blocker.** A future
bridge does not need to redesign X3DH or the ratchet. It needs the
endpoint/format fixes in §6.

## 3. Every incompatible item

Severity: BLOCKER = a message cannot be delivered end-to-end today;
TRANSLATABLE = a wrapper-only bridge can fix it; LOSS = bridgeable
only by giving up a feature.

### G1. SPK signature covers a different message — BLOCKER (endpoint change)

- v1: `sign_spk` = Ed25519 over `spk_pub || username`
  (`prekeys.py`). Verified in **two** places: the server on `register`
  and on `upload_prekeys` (`server.py`: "SPK 签名无效，拒绝入库"), and
  the client on every `start_session` (`client.py` `verify_spk`, else
  "对方预密钥签名无效").
- v2: `generateIdentity` signs `spk_pub` only; `parseBundle` verifies
  `spk_pub` only (`pwa/crypto.js`).
- Proven empirically (crosscheck negatives C + D, with controls):
  a v1-style signature is rejected by JS `parseBundle()`, and a
  JS-style signature fails verification under the v1 rule.
- What a bridge would have to translate: nothing can be translated —
  re-signing needs the owner's IK_sign private key, which the bridge
  must never hold. Dropping the check on either side is weakening (§5).
- Fix: v2 adopts the v1 rule (`spk_pub || username`) for newly
  generated identities. That is a strengthening (it binds the key to
  the name), not a weakening — but it means existing v2 identities
  must re-register, and the v2 relay's stored bundles must be rebuilt.

### G2. Post-quantum handshake + anti-downgrade — BLOCKER (endpoint change)

- v1: `generate_identity` creates an ML-KEM-768 long-term key (PQK,
  1184-byte public key, signed as `pq_pub || username`) plus 8
  one-time PQ keys, whenever `cryptography` supports ML-KEM
  (`prekeys.py`, `MLKEM_SUPPORTED`). `start_session` uses the hybrid
  path whenever both sides publish a PQK (`initiator_hybrid_secret`:
  ikm = DH material || kem_ss || SHA-256(pq_ek_pub), info `pqxdh-v1`).
  Every new sending chain in a hybrid session encapsulates to the
  peer's long-term PQK (`kdf_rk_pq`, info `pq-dr-v1`, `pq_ct` on the
  message). Receiving side: `_decrypt_envelope` **refuses** a
  classical initial message when the local identity has a PQ private
  key ("缺少 PQ 握手，已拒绝降级"); a hybrid session that later sees
  a message without `pq_ct` is likewise rejected.
- v2: `PQ_SUPPORTED = false`. Classical only. PQ fields are ignored,
  not carried: no `ik_pq_pub`, `pq_ek_pub`, `pq_ct` anywhere in
  `crypto.js` or the relay envelope.
- What a bridge would have to translate: nothing — a bridge cannot
  retrofit a KEM encapsulation. The KEM shared secret must be mixed
  into the sender's SK computation; a bridge-side encapsulation would
  produce a different `kem_ss`, so the receiver's derived SK would
  differ and GCM decryption would fail. Stripping the PQ requirement
  is a downgrade (§5).
- Fix: implement ML-KEM-768 + PQXDH + hybrid ratchet in the JS core
  (a WASM KEM library; tweetnacl does not provide it), OR run the v1
  side in a documented no-ML-KEM mode. The second option is a real
  security downgrade for that v1 user and must be their explicit,
  visible choice — never a silent bridge default.

### G3. Inner plaintext format — BLOCKER for v1 receiving (endpoint change)

- v1: after ratchet decryption, `_decrypt_envelope` parses the
  plaintext as JSON and requires `{"v": 1, "text", "group", "kind",
  "gstate", "thread", "thread_title", "privacy", ...}`, and
  cross-checks `kind` against the outer payload's `kind` and `group`
  against the outer payload's `group`; any mismatch raises GCMError
  ("消息语义元数据不一致"). Group messages additionally require the
  `gstate` hash to match a verified group state.
- v2: `app.js` encrypts the raw chat text (`sessionEncrypt(session,
  text)`); there is no inner JSON envelope.
- What a bridge would have to translate: nothing — the inner bytes
  are inside the GCM ciphertext and the bridge holds no keys, so it
  cannot re-wrap them. A v2 raw-text message would decrypt (crypto
  matches) and then be rejected by the v1 client as malformed.
- Fix: v2 wraps plaintext in the v1 inner JSON (and sets outer
  `kind`/`group` consistently) — an endpoint change on the v2 side.
  Reverse direction (v1 → v2) "works" cryptographically but renders
  as raw JSON text in the v2 UI until v2 parses the inner format.

### G4. Transport + envelope wrapper — TRANSLATABLE (the bridgeable part)

- v1: WebSocket (`ws://…`, documented run `127.0.0.1:8765`, no
  TLS/WSS in the repo), JSON text messages with `type` +
  `request_id`, request/response correlation via waiters.
  Envelope: `{"type": "envelope", "from": A, "to": B, "payload": {...}}`;
  server replies `{"type": "envelope_ok", "to": B}`; offline
  envelopes are pushed on login (`_push_offline`). JSON messages are
  capped at 64 KiB (`MAX_WS_MESSAGE`); larger binary goes through
  `ECB1` blob frames (8 MiB frames).
- v2 relay: HTTP JSON. `POST /v1/envelopes {sender, recipient,
  ciphertext, protocol_version: "v1", message_type, dh_pub, n, pn,
  nonce, kind, x3dh}` (flat, not nested under `payload`);
  `GET /v1/inbox?recipient=username:device` (pop-on-fetch,
  delete-after-delivery, optional `wait_seconds` 0–30 long-poll).
  Ciphertext base64 capped at 1,048,576 chars.
- Translation table (field-for-field, no crypto touched):
  `from`/`to` ↔ `sender`/`recipient`; `payload.dh_pub/n/pn/nonce/
  ciphertext/kind/x3dh` ↔ the flat fields of the same names;
  `type: "envelope"` + `request_id` ↔ the HTTP request/response
  pair; `envelope_ok` ↔ HTTP 200; v1 offline push on login ↔ v2
  inbox polling. The bridge must synthesize `envelope_ok` only after
  the v2 relay has durably accepted the envelope, and must not ack
  the v1 side before that (see G9).

### G5. Bundle format + key publication — PARTLY TRANSLATABLE

- v1 register: `{"type": "register", "username", "ik_sign_pub",
  "ik_dh_pub", "spk_pub", "spk_sig", "spk_created",
  "opks": [≤100 base64 32-byte pubs], "pq_pub", "pq_sig",
  "pq_opks": [{"pub", "sig"}]}`. Bundle response:
  `{"type": "bundle", "username", "ik_sign_pub", "ik_dh_pub",
  "spk_pub", "spk_sig", "spk_created", "opk": <one pub or null>,
  "pq_pub", "pq_sig", "pq_opk", "pq_opk_sig"}`.
- v2 relay register: `{"username", "device", "identity_key",
  "signed_prekey", "one_time_prekeys": [...],
  "public_keys": {"ik_sign_pub", "ik_dh_pub", "spk_pub",
  "spk_signature", "opk_pub"}}`; directory returns per-device
  `public_keys` objects.
- Renames a bridge CAN do: `spk_sig` ↔ `spk_signature`,
  `opk` ↔ `opk_pub`, `opks[]` ↔ `one_time_prekeys[]`,
  `identity_key`/`signed_prekey` ↔ the `public_keys` fields.
- What a bridge CANNOT do here: satisfy v1's SPK verification (G1),
  supply PQ fields (G2), or invent `spk_created` semantics (v1 stores
  it but does not enforce rotation on it — a bridge may pass 0, and
  that is the one harmless default in this document).
- Missing in v2, needed for parity: `spk_created`, PQ fields, and a
  pool-shaped OPK publication (see G6).

### G6. One-time prekey pool + consumption — BLOCKER without endpoint change

- v1 server `fetch_bundle` **deletes** one classical OPK row on every
  fetch (`store.py`: `DELETE FROM one_time_prekeys WHERE id=…`), and
  one PQ OPK row when `consume_pq_opk` is true (which `start_session`
  always sets). Clients publish 20 classical OPKs + 8 PQ OPKs and
  refill below thresholds (5 / 2) via `upload_prekeys`.
- v2 publishes exactly **one** OPK per device registration and never
  replenishes it; the relay serves that same OPK to every fetcher,
  forever (no consumption, no refill endpoint use on first-message
  receipt).
- What a bridge would have to translate: it cannot mint OPK private
  keys the recipient holds. Serving the single v2 OPK to a second
  v1 initiator is OPK reuse: DH4 repeats across sessions, which
  weakens forward secrecy for those sessions and must not be
  presented as fresh (§5).
- Fix: v2 publishes a pool (20, matching v1) and replenishes on
  first-message receipt (relay-side consumption + client refill) —
  an endpoint change on the v2 side, plus a relay change to consume
  rather than re-serve.

### G7. Device addressing + identity model — TRANSLATABLE WITH LOSS

- v2: `username:device`; one session and one envelope per recipient
  device (fan-out from the relay directory); revocation is per device.
- v1: username only. Sessions are keyed by peer username
  (`sessions: dict[str, RatchetState]`); the server keeps **one**
  online socket per username and kicks the previous one on a new
  login (`_bind`: "账号在其他终端登录"). Peer keys are pinned in the
  local store (`load_peer`); a changed IK_sign/IK_dh/PQK is refused
  ("身份密钥发生变化").
- Bridge behaviour: collapse `username:device` → `username` for the
  v1 side. Multi-device fan-out is lost in that direction (deliver to
  the one online socket, or the first device — a policy choice the
  bridge must document, not hide). A v2 user with two devices
  bridged to v1 would kick their own sessions. Key identity per
  username must stay stable across bridge restarts, or pinned v1
  clients will refuse the "changed" identity.

### G8. Authentication + friendship gate — BLOCKER for a bridge-as-client

- v1: no message type except `register`/`login` is accepted before
  authentication. Login is a signed challenge: server sends a 32-byte
  random challenge (`login_challenge`), client signs it with IK_sign
  and the server verifies against the registered IK_sign_pub
  (`login_ok`). Envelope delivery additionally requires
  `are_friends(sender, recipient)` (or shared group membership),
  else "需要对方同意好友申请后才能发消息".
- v2 relay: no auth, no friendship, no signed challenge (local-dev
  relay by design).
- What a bridge would have to translate: it cannot sign the login
  challenge for a v2 user without that user's IK_sign private key —
  copying the key into the bridge is forbidden (§5). A bridge that
  registers its **own** v1 identity and forwards messages breaks
  end-to-end authentication: the v1 peer sees the bridge's identity
  and fingerprint, not the v2 user's, and the bridge would have to
  decrypt and re-encrypt to do it, which it cannot do without the
  keys and must not do even if it could (§5).
- Fix: dual-stack endpoints — a v2 user who wants v1 interop holds
  their own v1 identity and the bridge forwards ciphertext opaquely
  between the two relay protocols (see §6, step 5). The bridge is a
  relay, never a client.

### G9. Delivery semantics + size limits — TRANSLATABLE WITH CAVEATS

- v1: online push, else offline queue, deleted after successful push
  (per-envelope delete in `_push_offline`). JSON cap 64 KiB; files
  use blob frames (8 MiB chunks, 8 GiB plaintext cap).
- v2 relay: pop-on-fetch, deleted on fetch. Known documented loss
  window: crash between fetch and decrypt loses the message (no ack
  protocol). Ciphertext cap 1,048,576 base64 chars (~768 KiB).
- Bridge rules: do not ack the v1 side (`envelope_ok`) until the v2
  relay has accepted the envelope; do not delete from the v1 offline
  queue until the v2 fetch succeeds (otherwise the bridge widens the
  loss window from "crash loses it" to "bridge loses it silently").
  Messages over v1's 64 KiB JSON cap cannot pass without blob
  framing — out of scope for a minimal text bridge; the bridge must
  reject them with an error, not truncate them.

### G10. Groups, voice, files, calls — OUT OF SCOPE for a 1-to-1 bridge

- v1 groups are NOT Sender Keys: one double-ratchet envelope per
  recipient (max 8 members) plus a signed, hash-linked group-state
  chain (`groups.py`), with `group` + `gstate` binding checks on
  receipt. v2's large-group design (Sender Keys, rekey on kick) is
  design-only and differs in construction. Voice calls use binary
  call frames; files use blob frames; social/moments/presence are
  separate subsystems — none has a v2 counterpart.
- A 1-to-1 text bridge must reject group/voice/file payloads with an
  explicit error, never silently drop or downgrade them to plain text.

## 4. What a bridge would have to translate (checklist)

| # | Item | Bridge-only? | Notes |
|---|---|---|---|
| G1 | SPK signature domain | NO — endpoint | v2 must sign `spk_pub \|\| username` |
| G2 | PQ handshake / hybrid ratchet | NO — endpoint | JS ML-KEM-768, or explicit no-PQ mode |
| G3 | Inner plaintext JSON | NO — endpoint | v2 must wrap/parse v1 inner JSON |
| G4 | WS ↔ HTTP wrapper | YES | §3 G4 table; synthesize acks carefully |
| G5 | Bundle field renames | YES, except G1/G2/G6 | `spk_sig`↔`spk_signature`, `opk`↔`opk_pub`, pools |
| G6 | OPK pool + consumption | NO — endpoint + relay | pool of 20 + refill; relay must consume |
| G7 | `username:device` → `username` | YES, with loss | fan-out lost v1-ward; document the policy |
| G8 | Login challenge + friendship | NO — dual-stack | bridge must not hold IK_sign keys |
| G9 | Delivery acks + size caps | YES, with rules | ack-after-accept; reject >64 KiB JSON |
| G10 | Groups/voice/files | NO — out of scope | reject explicitly, never downgrade |

## 5. What must NOT be weakened (hard rules for any future bridge)

1. Never copy a private key across — not IK_sign, IK_dh, SPK, OPK,
   PQK, ratchet `dhs_priv`, or any seed/mnemonic — into a bridge,
   a relay, a log, or another device. Multi-device means each device
   generates its own keys (the v2 design already does this).
2. Never downgrade a hybrid/PQ session to classical, and never strip
   the PQ encapsulation from a hybrid session's messages.
3. Never skip, stub, or "translate away" SPK verification or
   initial-message signature verification, on either side.
4. Never accept an unsigned bundle as authenticated, and never forge
   a bundle, a login-challenge signature, or a friendship edge.
5. Never present a bridge identity as a user identity (no fingerprint
   mismatch hidden behind a relay).
6. Never re-serve a consumed OPK as fresh, and never reuse one OPK
   across sessions while calling it one-time.
7. Never decrypt-and-re-encrypt in the bridge. The bridge forwards
   ciphertext opaquely; if a message cannot be forwarded opaquely
   (wrong format, over cap, group/voice/file kind), it refuses it
   with an error instead of opening it.
8. Never downgrade to a static key: every session still starts from a
   fresh X3DH exchange (ephemeral EK, fresh ratchet keys). A
   "compatibility mode" that reuses one ECDH secret across messages
   is not compatibility, it is a different, weaker protocol.

## 6. Minimal viable path to real interop (in order)

1. **v2 adopts the v1 SPK rule** (`spk_pub || username`) for new
   identities; existing v2 bundles are re-registered. (Unblocks G1;
   also the cheapest fix in this document.)
2. **v2 wraps/parses the v1 inner JSON** (`v: 1`, `text`, `kind`,
   `group`, `gstate`, `thread`) and keeps outer `kind`/`group`
   consistent. (Unblocks G3.)
3. **v2 publishes an OPK pool + replenishment** (20 classical OPKs,
   relay consumes one per bundle fetch, client refills below 5).
   (Unblocks G6.)
4. **PQ decision, made explicitly:** either implement ML-KEM-768 +
   PQXDH + hybrid ratchet in JS (preferred — keeps parity with real
   v1 clients), or document a classical-only mode that both sides
   opt into knowingly. A silent downgrade is not an option. (Unblocks
   G2; this is the largest work item.)
5. **Then** a thin transport bridge becomes sufficient for 1-to-1
   text: WebSocket JSON (`type`/`request_id`/`envelope`/`envelope_ok`)
   ↔ HTTP relay (`POST /v1/envelopes`, `GET /v1/inbox`), with the
   field renames of G5, the addressing collapse of G7 (documented
   fan-out loss), and the ack/size rules of G9. v2 users hold their
   own v1 identities for the v1 side (dual-stack, G8) — the bridge
   never logs in as a user.
6. **Not in this path:** multi-device fan-out to v1 (v1 is
   single-socket-per-user by design), groups/voice/files (G10), and
   sealed sender / metadata hiding (both protocols expose
   sender/recipient to the relay; that is a separate protocol
   upgrade, not a bridge feature).

## 7. Test evidence

- `tests/test_v1_classical_crosscheck.py` (driver) +
  `tests/v1_crosscheck_node.js` (Node helper running the real
  `pwa/crypto.js`): **11/11 PASS** — controls (2), SPK negatives
  (C, D), direction A (JS→Python first + reply + 2nd), direction B
  (Python→JS first + reply + 2nd). Command:
  `/tmp/ecnu-venv/bin/python tests/test_v1_classical_crosscheck.py`
  (system python3 lacks `cryptography`; the script exits 2 with the
  venv command instead of claiming anything).
- The Python side of that test is a spec-derived model of v1's
  classical path, not the v1 code. It proves the formulas agree; it
  does not prove the v1 client accepts v2 traffic — §§3/5 explain
  why that proof cannot exist until §6 steps 1–4 land.
- No v1 server or client was run in this pass, no v1 account was
  created, and no message was sent to any v1 user. Any future bridge
  test must run against a real v1 server + client (locally, with
  throwaway accounts) and show a v1 client rendering a v2-sent
  message, and vice versa, before interop is claimed.

## 8. Addendum — endpoint fixes applied 2026-10-28 (§6 steps 1–3 DONE)

The analysis in §§1–7 above is the pre-fix state and is kept
verbatim for audit. On 2026-10-28 the v2 side applied §6 steps 1–3,
with tests (see STATUS.md for the run list):

1. **G1 FIXED in v2:** `pwa/crypto.js` `generateIdentity(username)`
   signs `spk_pub || username` and `parseBundle(bundle, username)`
   verifies it. Old spk_pub-only bundles are rejected, and a bundle
   for the wrong username is rejected. Existing v2 identities must
   re-register. (Tests: `tests/test_endpoint_fixes.js` SPK cases,
   plus the updated `tests/test_v1_classical_crosscheck.py` SPK
   cases — v1-style now ACCEPTED, old-style now REJECTED.)
2. **G3 FIXED in v2:** `sessionEncrypt` wraps the v1 inner JSON
   (`v: 1, text, group: null, kind: "chat", gstate/thread/
   thread_title/privacy: null`) and `sessionDecrypt` parses it and
   cross-checks kind/group against the outer payload before
   committing ratchet state, exactly as v1 does for 1-to-1 chat.
   Raw-text plaintexts are rejected, not rendered.
3. **G6 FIXED in v2:** identities hold 20 OPKs (`OPK_POOL_SIZE`),
   `POST /v1/bundles/fetch` consumes exactly one per fetch (device
   listing never consumes), the receiver drops its consumed OPK
   after first-message success and refills below 5, and a consumed
   OPK is never re-served as fresh. (`pwa/app.js` uses the
   consuming fetch only for new initiator sessions, never for
   receiver-side identity verification.)
4. **G2 NOT FIXED (PQ decision, §6 step 4):** ML-KEM-768 is still
   NOT IMPLEMENTED in JS (`PQ_SUPPORTED = false`). A candidate
   vendored implementation exists in the ecosystem (`mlkem-wasm`,
   a single JS file with WASM inlined, based on mlkem-native,
   described by its author as beta) but it was NOT vendored in this
   pass: vendoring requires a proper download + licence check +
   NIST test-vector verification, which a page-text-fetch-only
   subagent cannot do reliably for a ~50 KB minified bundle, and
   transcribing it by hand would be unverifiable. Peer matrix,
   stated exactly:
   - **v1 peers WITH a PQ key (the default v1 identity when
     `cryptography` supports ML-KEM): will still REFUSE v2**
     classical initial messages (v1 anti-downgrade in
     `_decrypt_envelope`), and v2 cannot initiate a hybrid session
     with them. No PQ peer interop is claimed.
   - **v1 peers WITHOUT a PQ key (identity generated with
     ML-KEM unavailable, `pq_priv` None): format-compatible** on
     SPK, inner JSON, and OPK pool, but still NOT proven
     end-to-end — the remaining blockers are G8 (signed login
     challenge + friendship gate, needs dual-stack identities) and
     the transport bridge, and no real v1 run has happened yet.
5. **Step 5 PARTIALLY built (transport only):** a thin WS↔HTTP
   adapter exists as a test harness (`tests/ws_http_bridge.py`,
   tested by `tests/test_ws_http_bridge.py`): wrapper translation
   G4/G5, ack-after-accept, 64 KiB cap, non-chat kinds refused,
   ciphertext forwarded opaquely. It is NOT a production bridge:
   it does no login, no challenge signing, no friendship check,
   and its WS "hello" binding is routing only. Do not present it
   as a v1 login or as proof of v1 interop.

What still blocks a real v1 interop claim, unchanged from §6:
PQ (step 4), dual-stack auth (G8), and a run against a REAL v1
server + client (see STATUS.md for the exact blocker).

## Addendum, 2026-10-28 — step 4 + G8 dual-stack path CLOSED by a real v1 PQ run

The blocker above is now closed at the crypto/protocol level
(see STATUS.md top verdict for the full evidence). A new
dual-stack PQ test endpoint, `tests/v1_ws_js_pq_client.js`
(real `pwa/crypto.js` + `pwa/crypto-pq.js`), holds its OWN v1
identity, registers it on the REAL v1 server with
`pq_pub`/`pq_sig`/`pq_opks` (pool of 8), passes the real
friendship gate, fetches the peer bundle consuming exactly one
classical OPK AND exactly one PQOPK, negotiates hybrid via
`decideMode` (must be `pqxdh`, otherwise it throws — never a
silent downgrade), and exchanges hybrid messages through the
real v1 server untouched. No v2 crypto code had to change: the
JS wire format already matched v1 exactly (PQXDH `pqxdh-v1`,
hybrid ratchet `pq-dr-v1`, x3dh fields `ik_pq_pub`/`pq_ek`/
`pq_ct`, 1088-byte `pq_ct` on every hybrid message, PQK
signature over `pq_pub || username`, PQOPK signature over
`pq-opk-v1\x00 || pq_opk_pub || username`).

`tests/test_v2_pq_to_real_v1.py` proves it, 12/12: (D) JS PQ →
real v1 PQ first renders on v1, v1 reply renders on JS, v1
session records the peer PQK with handshake `pqopk`; (E) v1 PQ
→ JS PQ first renders on JS, JS reply renders on v1; (F) a
second JS message on the post-turn sending chain renders on
v1. The classical-only endpoint's refusal of a PQ peer (the
old scenario C) remains correct and is still covered by
`tests/test_v2_js_to_real_v1.py`.

What this does NOT close: the PWA app itself still talks to
the v2 HTTP relay, not to the v1 WebSocket server, so a
PWA-UI-to-v1-server run is not claimed; a bridge-as-client
that signs for another user is still forbidden (G8's
bridge-as-client blocker stands — the honest path remains
dual-stack endpoints, each holding its own identity).
