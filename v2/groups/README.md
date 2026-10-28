# ECNUchat v2 — Large groups via Sender Keys (Track C, WORKING CODE)

`sender_keys.js` implements the design in `../docs/large-groups-sender-keys.md`:
per-sender group chains (HMAC chain step, AES-256-GCM, Ed25519
signatures verified before decrypting), sender-key distribution
**only** inside 1-to-1 double-ratchet envelopes, skipped-key cache
(40), replay rejection, and rekey on kick/member change (every
remaining member rotates its own chain + signing key, epoch bumps,
removed member gets nothing).

**This is NOT MLS.** Never describe it as MLS. Rekey is O(N²)
1-to-1 envelopes; there is no tree key agreement and no formal
post-compromise security. Old messages stay decryptable by a
removed member (it already holds the old keys) — rotation protects
only future messages. New members can decrypt only messages sent
after they joined. Soft cap ~50 members, design cap 100.

Tests: `../tests/test_track_c_groups.js` — join, message,
out-of-order + replay, kick + rekey, former member cannot decrypt
post-kick messages, and distribution carried through a real 1-to-1
ratchet session (crypto.js).
