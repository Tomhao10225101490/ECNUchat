# ECNUchat v2 — Voice Calls via WebRTC

> Design document only. See the final section for status.
> Parent plan: `../PLAN.md`. This document does not change the v1 envelope
> format, does not move any private key off a device, and does not claim
> group calls or PSTN connectivity.

## 1. Scope: what "voice" means here

This document covers **live 1-to-1 voice calls** between two online clients.
It is distinct from v1's desktop voice *messages* (recorded audio sent as a
message), which are a different feature and are not redesigned here.

Out of scope for this design:

- Group voice calls (no multi-party call in this design).
- PSTN / phone-number calling (no gateway to the telephone network).
- Video calls (the media path described here is audio-only; adding video
  would be a separate design decision, not a flag flip).
- Call recording, voicemail, and call transcripts (none are provided).

## 2. Architecture: signalling through the relay, media peer-to-peer

Two planes, kept separate:

| Plane | Path | What the relay / network sees |
| --- | --- | --- |
| Signalling | Through the relay, inside already-encrypted v1 1-to-1 double-ratchet envelopes | Ciphertext envelopes, sender/recipient, timing, size — the same metadata v1 already exposes. No SDP, ICE candidate, or call content in plaintext. |
| Media | Direct peer-to-peer WebRTC connection when possible; TURN relay as fallback (§4) | Encrypted media only (DTLS-SRTP). No plaintext audio anywhere on the network. |

Why signalling reuses the ratchet envelope, following the v1 idea of
"putting the call key inside a ratchet envelope":

- The existing 1-to-1 double-ratchet session already authenticates both
  parties and provides forward secrecy for the signalling exchange. No new
  key-exchange protocol is needed for call setup.
- Session descriptions (SDP offers/answers) and ICE candidates are
  signalling data, not audio. Carrying them inside ratchet envelopes means
  the relay cannot read or tamper with them without breaking the envelope
  authentication — a relay that modifies signalling produces envelopes that
  fail authentication and are rejected, rather than silently redirecting
  the call.
- No separate call-signalling server, account, or phone number is required.
  The parties are the same identities as in text chat.

## 3. Call flow: invite / accept / reject / hangup

States on each side: `idle → inviting / ringing → connecting →
in-call → ended`. Only one live call per client at a time in this design.

1. **Invite.** The caller sends a call-invite signalling message inside a
   1-to-1 ratchet envelope. It carries a call id (random, per call), the
   caller's SDP offer, and the caller's first ICE candidates. The caller's
   UI shows "calling…".
2. **Ringing.** The callee's client, on decrypting and authenticating the
   invite, shows an incoming-call UI with accept / reject. Nothing about
   the call is auto-accepted.
3. **Accept.** On accept, the callee sends an SDP answer plus its ICE
   candidates inside a ratchet envelope. Both sides complete ICE
   connectivity checks and DTLS-SRTP negotiation. Audio starts only after
   the peer connection reports a connected media path.
4. **Reject.** On reject, the callee sends a reject signalling message in a
   ratchet envelope. The caller stops ringing and shows "declined". A
   reject is final for that call id; the caller must start a new call id to
   retry.
5. **Hangup.** Either side may hang up at any time (ringing, connecting,
   or in-call). Hangup sends a hangup signalling message in a ratchet
   envelope and closes the peer connection locally. If the hangup envelope
   is lost (e.g. the other side went offline mid-call), the peer connection
   also ends on ICE/DTLS failure detection — hangup must not depend on a
   single envelope arriving.
6. **Missed / unanswered.** See §5 for the invite expiry rule.

### 3.1 Further signalling during a call

- ICE candidates discovered after the initial offer/answer are exchanged
  as additional signalling messages in ratchet envelopes ("trickle ICE"
  through the relay). This keeps all signalling on the same authenticated
  channel even though media may already be flowing.
- Renegotiation (e.g. changing audio parameters mid-call) is not in this
  design. If media parameters must change, the call ends and a new call
  starts.

## 4. Media path: direct first, TURN fallback, encrypted throughout

Connection establishment order:

1. **Direct peer-to-peer** (host candidates, then server-reflexive
   candidates via STUN). This is the preferred path: media never transits
   any third-party server.
2. **TURN relay fallback** when direct connectivity fails (symmetric NATs,
   restrictive firewalls). The client allocates a TURN relay address and
   media flows client → TURN → peer.

TURN security properties, stated precisely:

- Media is encrypted with DTLS-SRTP end to end between the two peers.
  The TURN server relays UDP packets; it does **not** hold the DTLS keys
  and cannot decrypt the audio. It sees ciphertext, packet sizes, timing,
  and both peers' IP addresses — the same class of metadata any relay sees.
- TURN credentials must be short-lived and per-call (or per-session), not
  a single long-lived shared credential baked into the client. How those
  credentials are issued (relay-issued vs a dedicated TURN service) is an
  open question (§8).
- STUN, if used, only reveals a client's public address to that client
  itself for candidate gathering; a STUN server carries no media and no
  signalling.

Audio properties (design targets, not measured):

- Opus audio, the WebRTC default codec, with echo cancellation, noise
  suppression, and automatic gain control provided by the platform WebRTC
  stack — not reimplemented by ECNUchat.
- No ECNUchat-side audio processing, transcription, or storage of call
  audio. Nothing about the call content is written to the message history
  except a local call record (see §6).

## 5. Invite expiry: ~45 seconds, carried over from v1

The v1 1-to-1 voice call design uses an approximately 45-second invite
expiry, and this design carries that over unchanged:

- If the callee has not accepted within ~45 seconds of the invite being
  sent, the invite expires. The caller stops ringing, shows "no answer",
  and the call id becomes invalid.
- A late accept for an expired call id must be rejected by the caller;
  a late SDP answer must not resurrect the call.
- Expiry is enforced by both sides' local timers, not by the relay. The
  relay does not need to understand call state; it only forwards envelopes.
- Consequence, stated honestly: a callee whose device is offline, whose
  push wake arrives late (see `push-wake-only.md`), or whose client is
  slow to fetch the invite envelope may miss the window even though the
  caller is still willing. There is no voicemail fallback in this design,
  and no "call back automatically" behaviour.

## 6. In-call controls and call records

- **Mute:** a local-only control. Muting stops sending local audio; it
  does not send a "muted" signal the other side must trust, and it does not
  mute the remote side. The mute state is shown locally only.
- **Duration:** a local timer starting when media connects (not when the
  invite is sent). Duration is displayed during the call and recorded in
  the local call record.
- **Call record:** each side keeps a local record of the call — peer,
  start/end time, duration, and outcome (accepted, declined, missed, failed).
  This record is local history, like message history; it contains no audio
  and no transcript. Whether it is included in encrypted backup is a
  backup-design question (see `backup-encrypted.md`).
- **Speaker / device selection:** delegated to the platform (browser /
  Tauri audio device handling). No custom audio routing in this design.
- **Background behaviour:** on mobile PWA, an incoming call that arrives
  while the app is backgrounded depends on the push wake path
  (`push-wake-only.md`) and on the platform's background limits. This
  design does not promise that a backgrounded PWA will ring as reliably
  as a native calling app — see §7.

## 7. What is NOT done, and what can go wrong

- **No group calls.** Adding a third party is not a matter of adding a
  peer connection; it requires a conferencing topology (mesh, SFU, or
  MCU), each with its own encryption and trust questions. That is a future
  design, not an extension of this one.
- **No PSTN.** There is no phone-number dialling, no gateway, and no
  interworking with the telephone network.
- **No end-to-end identity verification beyond the ratchet session.**
  Call signalling is authenticated by the same 1-to-1 session as text
  messages, so a call is as trustworthy as a text from that contact — no
  more, no less. Out-of-band fingerprint verification (the same mechanism
  as for adding a contact) is the remedy if a contact's identity is in
  doubt, not a call-specific verification ceremony in this design.
- **Relay metadata remains.** The relay sees that a call was attempted,
  when, between whom, and roughly how long signalling continued. It does
  not hear the call. Users who need to hide the fact of a call need sealed
  sender / metadata protection, which is explicitly out of scope (see the
  plan's "absolutely not" list).
- **NAT / firewall failures are user-visible.** If neither direct nor TURN
  connectivity succeeds, the call fails with a connectivity error, not a
  silent downgrade to unencrypted media. There is no unencrypted fallback
  in any circumstance.
- **No call quality adaptation beyond WebRTC defaults.** Congestion
  control, jitter buffering, and codec adaptation are the platform stack's
  job; ECNUchat does not add its own adaptation layer in this design.

## 8. Open questions

- Who issues short-lived TURN credentials, and how does a client obtain
  them without the relay learning more than it already knows?
- Is TURN self-hosted, a third-party service, or optional (direct-only
  deployments with no TURN at all)? What does the UI say when no TURN is
  configured and direct connection fails?
- Should the ~45-second invite timer start when the caller sends the
  invite, or when the callee's client first decrypts it? The difference
  matters for offline / slow-push callees.
- How does the callee's client handle an invite arriving while already in
  another call (busy signal vs call waiting vs auto-reject)?
- What audio-device and permission UX is required on PWA (browser mic
  permission) vs Tauri desktop, and what happens if permission is denied
  mid-call?
- Should a missed-call entry appear in the text chat thread, or only in a
  separate call history, and does it sync across a user's devices?
- Does the DTLS-SRTP layer need any additional ECNUchat-level key
  confirmation (e.g. comparing a short authentication string), or is
  ratchet-authenticated signalling sufficient for this design's threat
  model?

## Status: DESIGN ONLY -- NOT IMPLEMENTED

No WebRTC call code, signalling message type, TURN configuration, or
in-call UI is implemented by this document. The v1 desktop voice-call
behaviour is the only implemented voice feature; this WebRTC design is a
separate, unimplemented plan. Group calls and PSTN are not implemented and
are not promised by this design.
