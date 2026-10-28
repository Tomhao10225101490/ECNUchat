# ECNUchat v2 — Encrypted Passphrase Backup and Restore

> Design document only. See the final section for status.
> Parent plan: `../PLAN.md`. This document does not change the v1 envelope
> format, does not move any private key off a device in plaintext, and
> does not provide any server-side recovery.

## 1. The limitation, first — read this before anything else

> **No backup = identity lost. No server-side recovery, by design.**
>
> If a phone is lost, stolen, or wiped, and no encrypted backup bundle
> exists, the user's identity, contacts' trust state, ratchet sessions,
> group sender keys, and message history on that device are gone. The
> relay cannot restore them: it holds only ciphertext envelopes addressed
> to mailboxes, never the private keys that decrypt them, and never the
> passphrase or any key derived from it. Support cannot recover an account,
> because there is no account password stored anywhere to reset — the
> passphrase exists only in the user's head (and, transiently, on the
> device that created the bundle).
>
> This is not a missing feature to be patched later without changing the
> security model. It is the direct consequence of "private keys never
> leave a device" plus "the relay is a dumb mailbox". Any recovery
> mechanism that let a server restore an identity would also let that
> server (or anyone who compromises it) impersonate the user. The UI must
> state this limitation prominently at setup, at backup creation, and at
> restore — not buried in a help page.

The rest of this document is about making the backup that *does* exist as
reliable, portable, and hard to misuse as possible — within that limit.

## 2. What a backup bundle contains

A backup is a single encrypted bundle. Its plaintext contents are:

- **Identity:** the user's long-term identity keypair (private key
  included — that is the point of the backup), username, and device
  identity for the backed-up device.
- **Ratchet state:** current 1-to-1 double-ratchet session states for
  active contacts, so restored conversations can continue without a fresh
  X3DH handshake for every contact. (Sessions that have already ratcheted
  far past the backup point will need re-handshaking on next contact —
  see §5.)
- **Group state:** group memberships, group sender keys held by this
  device, and admin state, so group chats survive a restore.
- **Message history:** the local message history the user has chosen to
  back up (see §3 for the history scope question).
- **Contact trust state:** contacts, their identity fingerprints, and
  verification status, so the restored client does not silently trust a
  changed key it had previously flagged.

What a bundle does **not** contain:

- The passphrase itself, or any hash of it that could be used to log in
  elsewhere. The passphrase is used only to derive the bundle encryption
  key at creation and restore time, then discarded from memory.
- Any other device's private keys. A bundle backs up one device's state;
  restoring it onto a new device makes that new device a continuation of
  the backed-up device (see §5), it does not merge two devices' states.

## 3. Encryption: passphrase-derived key, PBKDF2 carried over from v1

The design carries over the v1 vault's approach — a passphrase-derived key
with a high-iteration PBKDF2 — rather than inventing a new KDF for v2:

- **KDF:** PBKDF2-HMAC-SHA256 with a fresh random salt per bundle
  (minimum 16 bytes), and a high iteration count. The exact count is an
  implementation parameter to be set at build time and recorded in the
  bundle header in plaintext (the count is not secret); the design target
  is at least 600,000 iterations, consistent with current OWASP guidance
  for PBKDF2-HMAC-SHA256, and it must be revisited at implementation time
  rather than copied blindly if guidance changes. A deliberately slow KDF
  is the main defence against offline guessing of a weak passphrase.
- **Encryption:** AES-256-GCM over the serialised bundle plaintext, with a
  fresh random nonce per bundle. The GCM authentication tag is the
  integrity check: a wrong passphrase (or a corrupted bundle) fails
  authentication, which is what makes restore "fail closed" (§5).
- **Bundle header (plaintext):** format version, KDF identifier and
  iteration count, salt, nonce, and a bundle id. Everything else is
  ciphertext. The header reveals only that "this is an ECNUchat backup
  bundle" and its KDF parameters — no identity, no history, no passphrase
  hint.
- **Passphrase strength is the user's responsibility, and the UI must say
  so.** PBKDF2 slows guessing; it does not make "123456" safe. The UI
  should require a minimum passphrase length, warn against reuse, and
  refuse to create a bundle with an empty passphrase. Whether a
  passphrase-strength meter or a generated passphrase option is offered
  is an open question (§7).

Why PBKDF2 and not a memory-hard KDF here: continuity with the v1 vault
and with the plan's stated approach. If a future revision adopts a
memory-hard KDF, it must be a new bundle version with migration handling,
not a silent change to the same version number.

## 4. Storage options: three ways to hold the same ciphertext

The bundle is ciphertext in all three options. The relay, a file, or a QR
handoff never sees plaintext, and none of them needs — or gets — the
passphrase.

### 4.1 Ciphertext stored on the relay (opt-in)

- The client uploads the encrypted bundle to the relay, which stores it
  as an opaque blob keyed by a bundle id. The relay cannot decrypt it.
- Advantage: restore from anywhere the relay is reachable, without the
  user carrying a file. Disadvantage: the bundle's existence, size, upload
  time, and fetch time are visible to the relay, and a relay that deletes
  or withholds the bundle denies restore — so relay storage must never be
  the *only* copy the user is encouraged to keep.
- Retention and replacement policy (how many bundles, how long, what
  happens on upload of a newer bundle) is an open question (§7).

### 4.2 Local file export

- The client writes the encrypted bundle to a file the user controls
  (e.g. `ecnu-backup-<date>.bin` or similar), for the user to copy to
  another drive, a USB stick, or their own cloud storage.
- Advantage: no third party holds even the ciphertext. Disadvantage: the
  user must actually keep the file safe and findable; a file on the same
  lost phone is no backup at all, and the UI must say that explicitly.
- The file must be treated as sensitive: anyone holding the file can
  attempt offline passphrase guessing at their leisure. File permissions,
  naming, and user guidance ("store this separately from your phone")
  are part of the design, not afterthoughts.

### 4.3 QR-assisted migration (old device → new device)

- For device migration when the old device still works: the old device
  prepares an encrypted bundle (per §3) and shows a QR code. The QR
  encodes **only** a bundle locator (relay bundle id, or a local-transfer
  address) plus a one-time fetch token — it does **not** encode the
  passphrase, the bundle key, or any private key.
- The new device scans the QR, fetches the bundle (from the relay, or
  directly from the old device over a local connection), and then prompts
  for the passphrase separately. Only the passphrase, entered by the user
  on the new device, decrypts the bundle.
- This keeps the QR itself low-value if photographed or shoulder-surfed:
  without the passphrase it yields only ciphertext (and, in the relay
  case, a fetch token that should be single-use and short-lived).
- QR migration is a convenience path for an attended handover, not a
  recovery path for a lost phone — if the old device is gone, there is no
  QR to scan, and §1 applies.

## 5. Restore flow: passphrase + bundle, wrong passphrase fails closed

1. **Obtain a bundle** by one of the §4 paths (relay fetch, file import,
   or QR-assisted fetch).
2. **Enter the passphrase** on the restoring device. The passphrase is
   never sent to the relay, never included in any QR, and never stored.
3. **Derive the key** with the header's salt and iteration count, and
   attempt AES-256-GCM decryption.
4. **On success:** the client installs the identity, ratchet states,
   group keys, contacts, and history, then re-registers the (possibly new)
   device with the relay directory as a continuation of the backed-up
   identity. Contacts see the same identity; they do not need to re-verify
   from scratch, because the identity keypair is the same.
5. **On failure (wrong passphrase or corrupted bundle):** restore fails
   completely, with a generic error ("passphrase or bundle incorrect").
   No partial restore, no decrypted subset, no hint about which part was
   wrong, and no "close, try again" signal that would aid guessing. The
   user retries with the correct passphrase or a different bundle copy.
6. **After restore, sessions may need refresh:** ratchet states captured
   in the bundle are a snapshot. Messages sent by contacts after the
   snapshot, or sessions that advanced beyond the snapshot, will not be
   readable from the snapshot alone — the client must fetch pending relay
   envelopes and, where a session has moved on, re-handshake. The UI must
   not present a restored device as instantly "fully caught up" if pending
   envelopes or stale sessions remain.

### 5.1 Backup freshness and rotation

- A backup is a snapshot, not a live mirror. The user should be prompted
  to refresh their backup after significant changes (new contacts, new
  groups, device changes) and on a periodic reminder — the exact cadence
  is an open question (§7).
- Uploading / exporting a newer bundle supersedes, but should not silently
  delete, the previous bundle until the new one has been verified
  (decryptable with the passphrase) — otherwise a failed new backup could
  destroy the only good copy.

## 6. Threats this design does and does not address

| Threat | Addressed? |
| --- | --- |
| Relay operator reads backup contents | Yes — bundle is ciphertext; relay holds no passphrase or derived key. |
| Thief steals the phone and the backup file together | No — if the attacker has both the file and a guessable passphrase, offline guessing is possible. Mitigation is passphrase strength + KDF cost, not server policy. |
| Attacker guesses the passphrase from the relay copy | Slowed, not prevented — PBKDF2 cost applies per guess; a weak passphrase will eventually fall. No server-side lockout exists for an offline copy. |
| Lost phone, no backup | No recovery, by design (§1). This is the headline limitation, not a gap to be quietly fixed. |
| Forgotten passphrase, bundle exists | No recovery. The bundle is undecryptable without it, and no reset flow exists. |
| Malicious relay swaps the bundle | Detected — GCM authentication fails on a swapped/corrupted bundle, and restore fails closed rather than installing attacker state. |
| Old backup restored over a newer identity (rollback) | Partially — a restore installs whatever the bundle contains, including older ratchet states. Clients should warn when restoring a bundle older than the currently registered device state, and re-handshaking (step 6 of §5) bounds the damage. The exact rollback warning is an open question (§7). |

## 7. Open questions

- What is the exact PBKDF2 iteration count at implementation time, and is
  it tuned per device class (desktop vs low-end phone) or fixed?
- What history scope does a bundle cover — all history, history since a
  date, or history excluding large attachments — and can the user choose?
- How many relay-stored bundles are kept, for how long, and what happens
  when a newer bundle is uploaded (replace, version, or keep both)?
- Should backup creation be prompted at first setup, and what periodic
  "your backup is X days old" reminder cadence is acceptable without
  nagging?
- Is a generated passphrase (e.g. a word list) offered as an option, and
  how is it presented so the user actually writes it down?
- How does QR-assisted migration work when the two devices are not on the
  same network — relay-mediated fetch only, or also a local transfer?
- What warning and confirmation flow applies when restoring a bundle
  older than the device's current state, or onto a device that already
  has an identity (overwrite vs abort)?
- Does the call record (see `voice-webrtc.md`) belong in the bundle, and
  if so, under the same history scope as messages?
- How is a bundle verified after creation ("test-restore" / decrypt check
  with the passphrase) without exposing the passphrase or plaintext to
  any other component?

## Status: DESIGN ONLY -- NOT IMPLEMENTED

No backup bundle format, KDF integration, relay blob storage, file export,
QR migration, or restore flow is implemented by this document. The v1
vault's PBKDF2 approach is referenced as the design basis, not as an
already-ported implementation. The lost-phone-no-backup limitation in §1
is a property of the design itself: without a backup bundle and its
passphrase, identity recovery is impossible, and no server-side recovery
is provided or promised.
