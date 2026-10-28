# ECNUchat v2 — Wake-only push (Track C, WORKING CODE)

`wake_push.js` is the testable core; `push_sw.js` is the service
worker wiring around the same rule (it loads `wake_push.js` via
`importScripts` when available, otherwise enforces the identical
rule inline).

**Rule: push wakes, push never tells.** A push payload must be
exactly `{ type: 'wake', v: 1 }`. Anything carrying content — text,
sender, group, preview, count, thread id — is ignored, never
rendered. The notification is always generic: "New message — Open
ECNUchat to read it". The service worker holds no keys and never
decrypts. After the user opens the app, `fetchAndDecrypt()` fetches
ciphertext envelopes from the relay and decrypts locally, deduping
by envelope id, so a lost/delayed/duplicate push never loses or
duplicates a message.

## iOS limits (stated honestly, not hidden)

- PWA push on iOS needs iOS 16.4+, Home-Screen install (not a
  Safari tab), and explicit permission. Older iOS / Safari-tab
  users get **no** push wakes; polling on next open is their path.
- iOS may delay, coalesce, or throttle background push, and there
  is no iOS VoIP-push equivalent for a PWA — a voice-call invite
  delivered via a late push may already be past its ~45s window.
- **Native-app push reliability on iOS is NOT promised.** A future
  native iOS app via APNs would be a separate project.

Tests: `../tests/test_track_c_push.js`.
