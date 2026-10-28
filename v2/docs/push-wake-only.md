# ECNUchat v2 — Wake-Only Push Notifications

> Design document only. See the final section for status.
> Parent plan: `../PLAN.md`. This document does not change the v1 envelope
> format, does not move any private key off a device, and does not promise
> native-app push reliability on iOS.

## 1. The rule: push wakes, push never tells

A push notification in this design contains **no message content**:

- No message text, no preview, no snippet.
- No sender name, no group name, no subject line.
- No message count, no thread identifier that names a conversation.

The push payload is a wake signal only, for example (illustrative, not a
final wire format):

```json
{ "type": "wake", "v": 1 }
```

What the user sees from the push itself is therefore generic — e.g.
"New message — open ECNUchat to read it" — and nothing more specific.
The real content appears only after the user opens the app, the client
fetches the ciphertext envelope from the relay, and the client decrypts
it locally with keys that never left the device.

This is a deliberate UX trade-off: a generic notification is less
informative at a glance than a normal messenger notification, and that is
the price of keeping message content out of the push path entirely.

## 2. Flow: from sender to wake to decrypted message

1. Alice sends a message. The relay stores the ciphertext envelope in Bob's
   mailbox (or forwards it immediately if Bob is online via WebSocket).
2. If Bob has no live connection, the relay asks the push service to
   deliver a wake signal to Bob's registered push subscription.
3. The push service delivers the wake to Bob's device.
4. Bob's client (opened by the user, or its service worker waking briefly)
   connects to the relay, fetches any pending ciphertext envelopes, and
   decrypts them locally.
5. Only then does Bob see who sent what. The push service, at no point,
   held the message, the sender's name, or the decryption key.

Two properties follow from this ordering:

- **Decryption is local-only.** The push service worker does not decrypt.
  In this design the service worker holds no private keys and performs no
  decryption, so a compromised or curious push path cannot yield plaintext
  — it can only trigger a fetch that the app itself then decrypts.
- **Push is best-effort, messages are not.** If a push is lost, delayed,
  or suppressed, the message is not lost: it waits as ciphertext in the
  relay mailbox until the client next connects. Push affects *latency of
  awareness*, never *delivery of the message itself*.

## 3. Android and desktop: background WebSocket / polling vs PWA Web Push

ECNUchat v2's mobile client is a PWA (per the plan), so the push story
differs by platform. On Android:

- **PWA Web Push** is the primary wake mechanism. The PWA registers a push
  subscription (via the browser's push service); the relay stores the
  subscription endpoint and triggers a wake through it when a mailbox
  gains a new envelope. This works even when the PWA is not open, subject
  to the browser's and OS's background policies.
- **Background WebSocket** is *not* relied upon as the primary wake path
  on Android. A backgrounded PWA / browser tab's WebSocket is subject to
  being suspended by the OS (battery optimisation / Doze), so a design
  that assumed "the socket stays open forever" would silently stop waking
  the user. A live WebSocket is used while the app is in the foreground;
  it is a fast path, not the wake guarantee.
- **Polling** is the fallback of last resort: the client periodically
  checks the relay mailbox when it next runs. Polling intervals trade
  battery and data against wake latency, and must be user-configurable
  with a conservative default. Polling does not replace push; it bounds
  the damage when push is unavailable (e.g. push permission denied, or a
  browser without push support).
- **Desktop (Tauri):** the desktop client can hold a WebSocket while
  running and can use OS notification APIs for the local "you have a
  message" alert after it decrypts. Push via a web push service is not
  needed while the desktop app is running; when it is fully closed, no
  wake is delivered in this design (the user sees messages on next launch).

## 4. iOS PWA push limits — stated honestly

iOS is the weakest link in this design, and this document does not hide
that:

- PWA push on iOS requires iOS 16.4 or later, the PWA installed to the
  Home Screen (not merely opened in Safari), and explicit user permission.
  Users on older iOS, or who run ECNUchat only as a Safari tab, get **no**
  push wakes at all — polling on next open is their only path.
- Even when all conditions are met, iOS may delay, coalesce, or throttle
  background push delivery, and a backgrounded PWA cannot hold a live
  WebSocket or run arbitrary background work the way a native app can.
  There is no iOS VoIP-push equivalent for a PWA, so an incoming voice
  call (see `voice-webrtc.md`) that depends on a push wake may arrive
  after the ~45-second invite window has already expired.
- **This design therefore cannot promise native-app reliability on iOS.**
  It promises: wake-only pushes where the platform allows them, messages
  never lost because push failed (they wait in the relay mailbox), and a
  UI that says so plainly instead of implying iOS push "just works".
- A future native iOS app (via APNs) could improve this, but it is a
  separate project — new client, App Store process, APNs key management —
  and is not part of this design or its promises.

## 5. Metadata leakage of push — what the push provider learns

Wake-only push protects *content*, not *metadata*. The following leakage
is inherent to using any third-party push service, and users should
understand it:

| Observer | Sees | Does NOT see |
| --- | --- | --- |
| Push service (browser vendor's push infrastructure) | That a wake was delivered to a particular device subscription, and when; approximate frequency of wakes | Message content, sender identity or name, group, message size beyond the fixed wake size, decryption keys |
| Relay | That a mailbox gained an envelope, for whom, and when the client fetched it; the push subscription endpoint if it triggers the wake | Message plaintext (envelopes are ciphertext), the push payload content (it is a fixed wake) |
| Network observer | Encrypted traffic to the push service and to the relay; timing correlation is possible | Message content |

Mitigations *within* this design, and their limits:

- Fixed, content-free wake payloads mean the push service cannot learn
  anything from payload inspection — but it still learns timing and
  destination, which alone can reveal activity patterns (e.g. "this device
  gets wakes at night").
- No sender information in the wake means the push service cannot tell
  *who* messaged the user — but the relay, which triggers the wake, does
  know the recipient's mailbox, as it must to route anything at all.
- Batching or delaying wakes could reduce timing leakage, but would also
  delay user awareness; this design does not add artificial delay, and
  any future delay policy must be an explicit, user-visible choice.
- Full metadata protection (hiding even the fact of a wake from the push
  provider) would require sealed sender / header encryption and a
  different push architecture. That is explicitly a later protocol upgrade
  in the plan, not something this design provides.

## 6. What is NOT implemented (in this design, as well as in code)

- No rich notifications: no sender name, preview, image, or reply-from-
  notification, because all of those would put content or metadata into
  the push path.
- No background decryption: the service worker never decrypts, and no
  decrypted content is rendered from a push alone.
- No silent data push that wakes the app to decrypt in the background and
  then notify with content. The wake only prompts the user to open the
  app; decryption happens in the app, in the foreground.
- No iOS native push (APNs), no Android native FCM client beyond what the
  PWA Web Push path uses through the browser, and no push for a fully
  closed desktop app.
- No guarantee of push delivery latency, ordering, or at-most-once
  semantics: the client must deduplicate by envelope id on fetch, and
  must treat "no push arrived" as normal (open the app and fetch).
- No push for calls that bypasses the voice-call expiry: a call invite
  delivered via a delayed push is still subject to the ~45-second window
  in `voice-webrtc.md`.

## 7. Open questions

- Should the relay store push subscription endpoints at all, or should a
  separate, minimal push-trigger service hold them so the mailbox relay
  and the push trigger are different components?
- How long should the relay retain a push subscription, and how is a
  stale / revoked subscription pruned (e.g. after repeated delivery
  failures)?
- Should wakes be coalesced (one wake per mailbox-poll rather than one
  per message) to reduce timing leakage and notification spam, and if so,
  with what delay bound?
- What polling interval default (and user-configurable range) balances
  battery against wake latency on Android when Web Push is unavailable?
- What exactly does the generic notification text say, in each supported
  language, so that it never leaks a sender or group by accident (e.g.
  via a per-conversation notification channel)?
- How does the client handle a wake arriving while it already has a live
  WebSocket (ignore, or treat as a fetch prompt) without double-fetching?
- For voice calls, is there any acceptable fallback when a push wake
  arrives after the invite expired — e.g. converting the missed call into
  a local missed-call record on next fetch?

## Status: DESIGN ONLY -- NOT IMPLEMENTED

No push subscription handling, push-trigger service, service worker, or
notification UI is implemented by this document. iOS PWA push reliability
is not promised and is not native-app equivalent. Push in this design is
wake-only: it carries no content, and a lost or delayed push never loses
a message, which waits as ciphertext in the relay mailbox.
