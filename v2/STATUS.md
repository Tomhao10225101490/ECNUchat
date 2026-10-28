# ECNUchat v2 — FINAL CONSOLIDATED VERDICT (2026-10-28, all tracks complete, coordinator-verified)

## Works end-to-end against REAL v1
- v1↔v1 baseline: PASS 9/9 (real v1 server + real ChatEngine clients, friendship gate, first/reply/post-turn messages, default hybrid-PQ identities).
- v2 JS ↔ real v1, classical peers: PASS 11/11 (dual-stack: JS registers its own v1 identity on the real v1 server, friend gate, envelopes through the real v1 server untouched, both directions).
- **REAL V1 PQ INTEROP PASS 12/12 (2026-10-28, this pass):** v2 JS PQ endpoint (real `pwa/crypto.js` + `pwa/crypto-pq.js`, ML-KEM-768 noble bundle) ↔ a REAL v1 ChatEngine peer with its default hybrid-PQ identity, through the REAL v1 server, both directions, no v2 crypto fix needed — the wire formats matched v1 exactly as documented (PQXDH `pqxdh-v1`, hybrid ratchet `pq-dr-v1`, bundle fields `pq_pub`/`pq_sig`/`pq_opks`, x3dh fields `ik_pq_pub`/`pq_ek`/`pq_ct`, 1088-byte `pq_ct` on every hybrid message). Scenarios in `tests/test_v2_pq_to_real_v1.py`: (D) JS PQ → v1 PQ first message renders on v1, v1 reply renders on JS, v1 session records peer PQK with handshake `pqopk`; (E) v1 PQ → JS PQ first renders on JS, JS reply renders on v1; (F) second JS message on the post-turn sending chain renders on v1. New harness: `tests/v1_ws_js_pq_client.js` (dual-stack PQ WS client holding its OWN v1 identity; never downgrades — `decideMode` must be `pqxdh`, and it verifies the initial `ik_pq_pub` against the server's `fetch_user` record, as v1 does). The classical-only endpoint's refusal (below) still stands and is still covered by the classical test — it is the correct behaviour for a classical-only endpoint, not a contradiction.
- v2 JS (classical-only) → real v1 PQ peer: REFUSED by the v1 client itself ("缺少 PQ 握手，已拒绝降级"), no plaintext renders. This is a real anti-downgrade result, not a bug to hide.
- Bridge with real ciphertext: PASS 8/8 (real crypto.js first message through WS↔HTTP bridge, byte-identical in the v2 relay inbox, still decrypts end-to-end). Bridge does no login/challenge/bundle/friendship; real interop goes via the real v1 server.

## Works v2-to-v2 (coordinator re-ran these)
- Relay (local dev, HTTP JSON, CORS fixed): 5/5. PWA relay, DOM, endpoint fixes 17/17, crypto cross-checks, bridge, PQ relay, PQ DOM: ALL PASS (re-run by coordinator).
- Real browser, shipped two-port topology: Firefox 159, two separate profiles, ALL 13 PASS (register, friend lists, UI send, bob decrypts + renders with E2EE hybrid tag, revoke → 410). The old Chromium loopback block does not apply to this Firefox result; the shipped CORS gap that caused the two-port failure is fixed in relay/relay.py (CORS headers + OPTIONS).
- Hybrid PQ in the app: v2 PQ identities negotiate hybrid via decideMode, exchange through the real relay, PQOPK consumed once + refill, PQK fallback, no-PQ peer stays classical, reload resumes hybrid — proven by test_pq_relay.js and test_pq_dom.js and the Firefox hybrid-tag run.
- Large groups Sender Keys code, wake-only push code, encrypted backup/restore code, OPK fan-out robustness: DONE with tests (Track C). Voice signalling: DONE, media is a labelled stub only. Desktop scaffold + production relay worker: PARTIAL (never launched/deployed, no Electron/Cargo/Cloudflare here).

## Still stub / NOT claimed
- The PWA app itself (`pwa/app.js`) still talks to the v2 HTTP relay, NOT to the v1 WebSocket server: the real-v1-PQ result above is proven at the crypto/protocol level via the dual-stack JS endpoint (the gap doc's prescribed G8 path), not by running the PWA UI against a v1 server. A PWA-to-v1-server UI run is not claimed.
- Voice media (mic/Opus/DTLS-SRTP), desktop packaging/launch, production relay deployment, WSS transport, relay auth, sealed sender / metadata hiding.
- No GitHub push, no original-repo edit, no credentials in any file, no relay/browser/v1 process left running after this pass.

## Next blocker (in order)
1. Production deployment: Cloudflare account + WSS + relay auth, and desktop packaging on a machine with Electron/Cargo. (The former blocker 1, the real v1 PQ peer run, is now CLOSED — see the PASS line above.)
2. Voice media and sealed sender, as separate protocol/implementation upgrades.

---

# ECNUchat v2 — STATUS (honest, as of 2026-10-28, endpoint fixes §6 steps 1–3 applied)

## PQ wiring, 2026-10-28 (this pass — v2↔v2 hybrid DONE, v1 run still open)

- **PQ is now wired into the real app + relay** (full account:
  [tests/TRACK_PQ_WIRING_STATUS.md](sandbox://workspace/ecnu-chat-v2/tests/TRACK_PQ_WIRING_STATUS.md)).
  `pwa/index.html` loads the ML-KEM bundle + `crypto-pq.js`;
  `pwa/app.js` generates a PQ identity alongside the classical
  one, publishes `pq_pub` / `pq_sig` / `pq_opks` (pool of 8) in
  the registration bundle, parses peer PQ bundles, negotiates
  hybrid via `decideMode` (hybrid iff BOTH sides hold a PQK —
  never a silent downgrade or upgrade), creates hybrid sessions,
  drops/refills PQOPKs on first-message success, and persists
  hybrid sessions across reload. `relay/relay.py`
  `POST /v1/bundles/fetch` consumes exactly one PQOPK per fetch
  and reports `pq_opks_remaining`, never re-serving a consumed
  key; classical consumption is unchanged. The relay's
  private-field rejection was also widened (any `*_seed` field,
  after the new test caught `pq_seed` being accepted).
- **Proven:** `tests/test_pq_relay.js` (ALL PASS, incl. PQK
  fallback + no-PQ-peer-stays-classical) and
  `tests/test_pq_dom.js` (ALL PASS, real `app.js`, hybrid tag,
  pool 8→7, reload resumes the hybrid session) against the real
  relay, plus a re-run of the **Firefox two-port** test
  (`ECNU_TWO_PORT=1`, ALL 13 PASS, hybrid tag) — the shipped
  topology now passes in a real browser. All prior regressions
  re-run green (relay 5/5, PWA relay, DOM, endpoint fixes, PQ
  ACVP, crypto + v1-classical + PQ cross-checks, bridge).
- **`ECNUcrypto.PQ_SUPPORTED` stays `false` deliberately:** that
  flag describes the classical core alone; the plug-in flag
  (`ECNUcryptoPQ.PQ_SUPPORTED`) is the honest PQ claim.
- **Update 2026-10-28 (this pass): the "v1 interop remains
  unproven" line above is SUPERSEDED.** The real v1 PQ run in
  `tests/test_v2_pq_to_real_v1.py` passes 12/12 (see the top
  verdict). What remains unclaimed is narrower: a PWA-UI run
  against a v1 server (the PWA talks to the v2 relay, not to
  the v1 WebSocket server), and a bridge-as-client (still
  forbidden by G8 — dual-stack endpoints only).

Source plan: [PLAN.md](sandbox://workspace/ecnu-chat-v2/PLAN.md)
Original project (NOT modified, NOT pushed to): https://github.com/Tomhao10225101490/ECNUchat
All work in this tree only. No private key, password, or real credential is in any file
(secret scan for key patterns: none found). No relay process is left running.

## Endpoint fixes, 2026-10-28 (gap doc §6 steps 1–3 DONE; step 4 PQ still open)

- **Step 1 — SPK rule (G1) DONE:** `pwa/crypto.js` now signs/verifies
  `spk_pub || username` exactly as v1 (`prekeys.py sign_spk`).
  `generateIdentity(username)` requires a username; `parseBundle`
  requires the peer username. Old spk_pub-only identities are
  rejected and must re-register. Proven by
  `tests/test_endpoint_fixes.js` (SPK cases) and the updated
  `tests/test_v1_classical_crosscheck.py` — v1-style signatures now
  ACCEPTED, old-style now REJECTED (13/13 pass, up from 11/11).
- **Step 2 — inner JSON (G3) DONE:** `sessionEncrypt` wraps the v1
  inner JSON (`v: 1, text, group: null, kind: "chat", gstate/
  thread/thread_title/privacy: null`); `sessionDecrypt` parses and
  cross-checks kind/group against the outer payload before
  committing ratchet state. Raw-text plaintexts are rejected, and a
  failed semantic check does not advance the ratchet.
- **Step 3 — OPK pool (G6) DONE:** identities hold 20 OPKs; new
  relay endpoint `POST /v1/bundles/fetch` consumes exactly one per
  fetch (device listing never consumes); `pwa/app.js` uses the
  consuming fetch only for new initiator sessions, and on
  first-message success the receiver drops its consumed OPK,
  refills below 5, and re-registers. A consumed OPK is never
  re-served as fresh.
- **Step 4 — PQ decision: NOT IMPLEMENTED, explicitly.** No silent
  downgrade. Peer matrix (see gap doc §8): v1 peers WITH a PQ key
  (default v1 identity) will still REFUSE v2 classical initials
  (v1 anti-downgrade) — no PQ peer interop is claimed. V1 peers
  WITHOUT a PQ key are format-compatible on SPK/inner/OPK but still
  unproven end-to-end (G8 auth + real-v1 run outstanding). A
  candidate vendored implementation (`mlkem-wasm`, single JS file
  with WASM inlined, based on mlkem-native, author-described beta)
  was identified by web search but NOT vendored in this pass:
  vendoring needs a proper download + licence check + NIST
  test-vector verification, which cannot be done reliably by
  transcribing a ~50 KB minified bundle from page text.
- **Step 5 — transport bridge: TEST HARNESS ONLY.**
  `tests/ws_http_bridge.py` + `tests/test_ws_http_bridge.py` prove
  wrapper translation (G4/G5), ack-after-accept, the 64 KiB cap,
  non-chat kinds refused, and opaque ciphertext forwarding in both
  directions. It does NO login, NO challenge signing, NO friendship
  check; its WS "hello" binding is routing only. It is not a
  production bridge and not proof of v1 interop.
- **Real v1 run: still NOT TESTED — exact blocker.** The task
  required obtaining v1 sources by page-text fetch only. Page-text
  fetch returns rendered text in the agent's context, not files;
  reconstructing the full v1 tree (notably `client.py`, ~6000
  lines, plus `server.py`/`store.py` and their websockets/rich/
  PySide6 dependencies, none installed here) from paged text is
  not reliable, and a generic subagent may not fetch code via the
  shell. The strongest test actually run is therefore the updated
  spec-derived Python model crosscheck (13/13, both directions,
  first + reply + 2nd message, now with inner JSON and the fixed
  SPK rule) — formula compatibility, not a v1-client run. A real
  v1 run needs a route that can actually obtain the sources
  (e.g. the parent agent cloning the repo into a test-only
  directory) plus dual-stack identities for G8, and must show a
  real v1 client rendering a v2-sent message before any interop
  claim is made.
- **Real browser run: still NOT TESTED.** No browser host other
  than this VM's blocked Chromium was available to this subagent,
  and the same failed Chromium flags were NOT retried. The DOM
  harness result below is not a browser test.
- **Breaking change from this pass:** v2 identities generated
  before this pass (spk_pub-only signatures, single OPK, raw-text
  sessions) are NOT accepted by the new code and must
  re-register; old sessions/messages will not decrypt. This is
  intentional (the old format is exactly what v1 rejects).

## Verdict per full-suite piece (updated rows only; rest unchanged below)

## Verdict per full-suite piece

| Piece | Status | Evidence / caveat |
|---|---|---|
| Mobile (PWA) | REAL CLASSICAL CRYPTO, RELAY WORKING (DOM-harness verified; real-browser run still NOT tested) | [pwa/](sandbox://workspace/ecnu-chat-v2/pwa/) opens with no build step. Relay mode now uses real X3DH + double ratchet ([pwa/crypto.js](sandbox://workspace/ecnu-chat-v2/pwa/crypto.js), tweetnacl 1.0.3 vendored + WebCrypto AES-256-GCM, x3dh-v1 / dr-v1) against the real relay API, with per-device fan-out from the relay directory. Demo mode is kept separate and still uses the labelled stand-in. ML-KEM-768: NOT IMPLEMENTED. The real `app.js` was run through a DOM harness (see below), NOT in a real browser. |
| Desktop (v2, Tauri) | NOT IMPLEMENTED | No Tauri/Electron wrapper was built in this tree. The original Python PySide6 desktop remains the v1 reference only; it was not copied, modified, or claimed as v2 desktop. |
| Large groups | NOT IMPLEMENTED | Design only: [docs/large-groups-sender-keys.md](sandbox://workspace/ecnu-chat-v2/docs/large-groups-sender-keys.md) (Sender Keys, rekey on kick, explicitly NOT MLS). No group code in this tree. Current v1 cap of 8 per-recipient envelopes is unchanged. |
| Voice | NOT IMPLEMENTED | Design only: [docs/voice-webrtc.md](sandbox://workspace/ecnu-chat-v2/docs/voice-webrtc.md) (WebRTC, encrypted signalling, TURN ciphertext-only). No voice code in this tree. V1 desktop voice calls are not in v2. |
| Push | NOT IMPLEMENTED | Design only: [docs/push-wake-only.md](sandbox://workspace/ecnu-chat-v2/docs/push-wake-only.md) (wake-only, no content in push, iOS limits stated). No push code in this tree. |
| Backup | NOT IMPLEMENTED | Design only: [docs/backup-encrypted.md](sandbox://workspace/ecnu-chat-v2/docs/backup-encrypted.md) (PBKDF2-derived encrypted bundle, lost-phone-no-backup stated). No backup code in this tree. |
| Relay (local dev) | DONE (local dev only) | [relay/relay.py](sandbox://workspace/ecnu-chat-v2/relay/relay.py), Python stdlib only. Public-key directory, offline envelope store, online long-poll forwarding, device list, revocation. Verified by tests below. Production Cloudflare Workers/D1/R2 deployment: NOT IMPLEMENTED. WebSocket transport: NOT IMPLEMENTED — this relay is HTTP JSON, stated loudly in its README. |
| 1-to-1 text, relay-mediated | WORKING VIA NODE HARNESSES (classical path) | Relay passes tests (below) AND the PWA's crypto/relay modules pass end-to-end against the real relay in Node ([tests/test_pwa_relay.js](sandbox://workspace/ecnu-chat-v2/tests/test_pwa_relay.js)): register, first message decrypts, reply decrypts, second fetch empty, revocation 410. The real `app.js` additionally passes a DOM harness ([tests/test_pwa_dom.js](sandbox://workspace/ecnu-chat-v2/tests/test_pwa_dom.js)). Interop with the original Python v1 client is ANALYSED and its classical wire crypto proven cross-language, but end-to-end v1 interop does NOT work and is NOT claimed ([docs/v1-interop-gap.md](sandbox://workspace/ecnu-chat-v2/docs/v1-interop-gap.md)). Real-browser end-to-end is NOT tested. |

## What was verified (this pass, 2026-10-28 — DOM harness + v1 gap)

- `tests/test_pwa_dom.js`: **ALL PWA-DOM TESTS PASS, exit 0** — Node
  `vm` harness loads the REAL `pwa/app.js` against the REAL
  `relay/relay.py` on a free loopback port, two instances (alice
  default namespace, bob `?profile=peer` namespace): register through
  the real handler, invite via the relay directory, send through the
  real send handler, fetch + decrypt + render on the other side
  (tagged E2EE classical, NOT demo), no `alert()` on the happy path,
  revoke via relay API (200), UI fetch after revoke shows the 410
  failure, relay log contains no test plaintext. Shim limitations
  (in the test header): no layout/CSS/service worker/clipboard/
  mobile rendering, no real focus/keyboard behaviour, `innerHTML`
  not parsed into a real DOM tree, BroadcastChannel absent; crypto
  is NOT shimmed. This is NOT a browser test.
- Real-browser attempt, re-confirmed blocked: `tests/test_pwa_browser.js`
  (real headless Chromium 152 via CDP, two pages, real relay on 8765)
  reports **FAIL: timeout waiting for alice page ready**. Cause:
  this VM's Chromium blocks loopback navigation with
  `net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`; the flag
  workarounds tried earlier (`--disable-features=
  LocalNetworkAccessChecks`, `--disable-web-security`,
  `--allow-insecure-localhost`, non-loopback serving) all failed.
  A real two-profile browser run is still NOT TESTED and needs a
  different host/browser, not another retry of the same flags.
- Real app bug found by the DOM harness and FIXED in `pwa/app.js`:
  `fetchInbox` passed a full URL to `relayJson()`, which prepends
  the relay base again, producing a doubled URL
  (`http://…http://…/v1/…`) so every inbox fetch — including the
  5-second poll — failed with "Failed to parse URL". Fix: pass only
  the path. Covered by the DOM harness's fetch assertions.
- `tests/test_v1_classical_crosscheck.py` +
  `tests/v1_crosscheck_node.js`: **11/11 PASS, exit 0** — JS
  (`pwa/crypto.js`) ↔ spec-derived Python model of v1's classical
  path, both directions, first message + reply + second message
  after a full ratchet turn, plus two negative SPK cases proving the
  signature-domain mismatch (v1-style sig rejected by JS
  `parseBundle()`; JS-style sig fails under the v1 rule). The Python
  side is a model, NOT the v1 code (v1 was read via page-text fetch
  only, never downloaded, modified, or run). Command:
  `/tmp/ecnu-venv/bin/python tests/test_v1_classical_crosscheck.py`
  (system python3 lacks `cryptography`; the script exits 2 with the
  venv command if run without it). This proves classical wire-crypto
  compatibility; it does NOT prove v1-client interop — see
  [docs/v1-interop-gap.md](sandbox://workspace/ecnu-chat-v2/docs/v1-interop-gap.md).

## What was verified (PWA relay fix, 2026-10-28 — re-run by this pass)

- `tests/test_pwa_relay.js`: **PASS, exit 0** (run twice) — Node loads `pwa/crypto.js`,
  starts the real relay on a free loopback port, registers alice:phone and bob:laptop
  with real key bundles, exchanges a first message (with x3dh) and a reply through
  the relay with both sides decrypting correctly, confirms second fetch empty, and
  confirms revocation returns 410 for send and fetch. Relay log contains no test plaintext.
- `tests/test_crypto_crosscheck.py`: **PASS, exit 0** (Python `cryptography` in a venv,
  JS via Node, both directions) — X25519 shared secret agrees, an Ed25519 signature
  made in JS verifies in Python and vice versa, and an AES-256-GCM message encrypted
  on one side decrypts on the other. Classical path only; ML-KEM is NOT covered.
- Crypto smoke tests (Node, not committed as a test file): two-way ratchet exchange,
  out-of-order delivery via the skipped-key cache, replay rejection, tamper rejection
  without advancing state, and session persistence round-trip — all pass.
- `node --check` on `pwa/crypto.js`, `pwa/app.js`, `pwa/sw.js`,
  `tests/test_pwa_relay.js`, `tests/crypto_js_vectors.js`, `tests/crypto_js_verify.js`: pass.
  `py_compile` on `relay/relay.py`, `relay/relay_client.py`: pass.
- Relay bug found and fixed in this pass: the revoke route never read the request
  body, so a keep-alive client sending `{}` with a revoke desynced the next request
  (`Unsupported method ('{}GET')`, HTTP 501). Fixed by draining the body in the
  revoke routes (`_drain_body` in `relay.py`); the API is unchanged. After the fix,
  the PWA-relay harness passes twice and the original relay tests still pass.

## What was verified (re-run by the coordinator, 2026-10-28)

- `tests/test_relay.py`: **PASS 5/5, exit 0** — see [tests/VERIFICATION.md](sandbox://workspace/ecnu-chat-v2/tests/VERIFICATION.md)
  - A. Opacity: fetched ciphertext byte-identical to sent; relay log contains neither the distinctive fake plaintext, nor the sent ciphertext, nor the decoded fake blob.
  - B. Two-client exchange: carol:phone ↔ dave:laptop, both directions delivered, second fetch empty (delete-after-delivery).
  - C. Revocation: queued message dropped on revoke; fetch/send/count thereafter return 410 DEVICE_REVOKED; device gone from listing.
  - D. Guards: register with `private_key` → 400 PRIVATE_DATA_REJECTED; send to never-registered device → 404 DEVICE_NOT_FOUND.
- `node --check pwa/app.js` and `pwa/sw.js`: pass. `manifest.json` parses.
- `python3 -m py_compile relay/relay.py relay/relay_client.py`: pass.
- Relay processes: none left running after tests.

## Known failure / mismatch — FIXED in this pass, and what remains

The old mismatch is fixed: the PWA's relay mode now uses the real relay API exactly
(`POST /v1/devices/register` with `username, device, identity_key, signed_prekey,
one_time_prekeys, public_keys`; `POST /v1/envelopes` with flat
`sender, recipient, ciphertext, ...`; `GET /v1/inbox?recipient=username:device`;
pop-on-fetch, no ack; default relay port 8765), and demo-1 envelopes are never
sent to the relay (demo mode is offline-only and separately labelled).

What remains, stated plainly — do not claim otherwise:

- **Python v1 interop: endpoint fixes 1–3 DONE, end-to-end interop
  still NOT claimed.** [docs/v1-interop-gap.md](sandbox://workspace/ecnu-chat-v2/docs/v1-interop-gap.md)
  §8 records the fix state: SPK rule, inner JSON, and OPK pool +
  consumption are now v1-compatible and tested; PQ (step 4),
  dual-stack auth (G8), and a real v1 server+client run remain
  outstanding. Classical wire crypto is proven cross-language
  (13/13, now including inner JSON and the fixed SPK rule), but
  that is not a v1-client run.
- **Browser UI: DOM-harness verified, real-browser run NOT tested.**
  The end-to-end relay test loads `crypto.js` in Node, and the DOM
  harness loads `app.js` in a Node `vm` sandbox — neither is a
  browser. A real two-profile browser run (register → invite → send
  → fetch, real relay on 8765) is still required before calling the
  PWA UI "working in a browser".
- **ML-KEM-768 NOT implemented** in the JS core (`PQ_SUPPORTED = false`).
  Sessions are classical only. See the PQ peer matrix above.
- **OPK pool + replenishment: DONE in this pass** (20 OPKs,
  consuming bundle fetch, receiver-side drop + refill below 5).
  Previously single-OPK wording elsewhere in this file is superseded.
- WebSocket transport and TLS/WSS in the relay itself: still NOT implemented
  (production TLS must be terminated by deployment).

## What is still stub / not implemented (complete list)

- ML-KEM-768 / PQXDH / hybrid ratchet in the PWA; frozen-v1 envelope interop
  with the original Python client (endpoint fixes 1–3 done, PQ + dual-stack
  auth + real-v1 run outstanding — see the top section); real-browser PWA
  end-to-end test.
- Production WS↔HTTP bridge (the test harness in tests/ is transport-only;
  a production bridge needs dual-stack identities, login, and friendship
  handling, and must never hold private keys or sign as a user).
- WebSocket transport and TLS/WSS in the relay itself (production TLS must be terminated by deployment).
- Relay auth, rate limiting, sealed sender / metadata hiding (relay sees sender, recipient, size, timestamp by design).
- Large groups, voice, push, backup code (design docs only).
- Desktop v2 packaging, production relay deployment, account recovery beyond the backup design.
- Concurrency ordering, near-1 MiB envelopes, SQLite on-disk leak inspection, ack-before-delete delivery.

## Tree

- [PLAN.md](sandbox://workspace/ecnu-chat-v2/PLAN.md) — original full-suite plan
- [relay/](sandbox://workspace/ecnu-chat-v2/relay/) — relay.py, relay_client.py, README.md, VERIFICATION.md
- [pwa/](sandbox://workspace/ecnu-chat-v2/pwa/) — index.html, app.js, crypto.js, vendor/ (tweetnacl 1.0.3 + licence), styles.css, manifest.json, sw.js, icons, README.md
- [docs/](sandbox://workspace/ecnu-chat-v2/docs/) — large-groups-sender-keys.md, voice-webrtc.md, push-wake-only.md, backup-encrypted.md, v1-interop-gap.md
- [tests/](sandbox://workspace/ecnu-chat-v2/tests/) — TEST_PLAN.md, test_relay.py, test_pwa_relay.js, test_pwa_dom.js, test_pwa_browser.js, test_v1_classical_crosscheck.py, v1_crosscheck_node.js, test_crypto_crosscheck.py, crypto_js_vectors.js, crypto_js_verify.js, VERIFICATION.md, plus this pass: test_endpoint_fixes.js, ws_http_bridge.py (test harness only), test_ws_http_bridge.py
