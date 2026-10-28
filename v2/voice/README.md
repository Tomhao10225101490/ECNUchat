# ECNUchat v2 — Voice signalling (Track C, SIGNALLING ONLY)

`signalling.js` implements the invite / accept / reject / hangup
state machine from `../docs/voice-webrtc.md` §3, with the ~45s
invite expiry enforced by both sides' local timers, busy rejection
for a second concurrent call, and call-id mismatch rejection.
Signalling messages must be carried inside encrypted 1-to-1
double-ratchet envelopes; this module never encrypts or sends
anything itself.

**Media is NOT implemented here.** `connectMedia()` only records
that a caller-supplied WebRTC stack reports connected, and exposes
a clearly-labelled `AUDIO-STUB` — no microphone, no Opus audio, no
DTLS-SRTP session. Real media, when wired, is DTLS-SRTP
peer-to-peer, or via TURN relaying ciphertext only (TURN holds no
DTLS keys and cannot decrypt audio). There is no unencrypted
fallback, no group calls, no PSTN.

Tests: `../tests/test_track_c_voice.js`.
