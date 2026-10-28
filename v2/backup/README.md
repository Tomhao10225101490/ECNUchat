# ECNUchat v2 — Encrypted backup / restore (Track C, WORKING CODE)

`backup.js` implements `../docs/backup-encrypted.md` §3:
PBKDF2-HMAC-SHA256 (600,000 iterations, fresh 16-byte salt),
AES-256-GCM (fresh 12-byte nonce), plaintext header with format /
KDF / iterations / salt / nonce / bundle id only. Wrong passphrase
or corrupted/swapped bundle fails GCM authentication and restore
fails closed with a single generic error — no partial restore, no
hint about which part was wrong. Empty passphrases are refused;
minimum 8 characters. The passphrase is never stored in the bundle
and never sent to a relay. Verify a new bundle decrypts before it
supersedes an old one (`verifyBundle`).

## LOST-PHONE-NO-BACKUP LIMITATION (prominent, by design)

> **No backup = identity lost. No server-side recovery.**
>
> If a phone is lost, stolen, or wiped, and no encrypted backup
> bundle exists, the identity, ratchet sessions, group sender keys
> and history on that device are gone. The relay cannot restore
> them: it holds only ciphertext envelopes, never private keys,
> never the passphrase. A forgotten passphrase with a bundle in
> hand is equally unrecoverable. The UI MUST state this at setup,
> at backup creation, and at restore — not buried in a help page.
> A backup is a snapshot, not a live mirror: refresh it after
> significant changes.

Tests: `../tests/test_track_c_backup.js` — correct-passphrase
restore, wrong-passphrase rejection, tamper rejection, no
passphrase stored in the bundle, and empty-passphrase refusal.
