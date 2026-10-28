# ECNUchat v2 — Large Groups via Sender Keys

> Design document only. See the final section for status.
> Parent plan: `../PLAN.md`. This document does not change the v1 envelope
> format, does not move any private key off a device, and does not claim MLS.

## 1. Problem and scope

ECNUchat v1 implements a group message as one double-ratchet envelope per
recipient, capped at 8 members. That is simple and gives each recipient a
pairwise-authenticated, forward-secret channel, but its send cost grows
linearly with group size: a message to N members is N separate encryptions
and N separate relay deliveries.

This design covers groups larger than 8. It does **not** replace v1 for small
groups:

- Groups of 8 or fewer keep the existing v1 per-recipient double-ratchet
  envelopes, unchanged, so old Python clients keep working.
- Groups above 8 use the Sender Keys scheme described here, carried in a new
  group envelope type. A v1-only client that receives a Sender Keys group
  message must report it as unsupported, not silently drop it or decrypt it
  as a v1 message.
- One-to-one chats are unaffected by this document.

## 2. Sender Keys, in one paragraph

Each member of a group maintains **one sending chain for that group**.
When Alice sends a group message, she encrypts it **once** under the next key
derived from her own group sending chain, signs the ciphertext with her
group signing key, and posts a single ciphertext to the relay for the group.
Every other member holds a copy of Alice's current sending chain and signing
public key, so every member can decrypt and verify Alice's messages without
Alice having to encrypt the message N times. Each member's chain is
independent: Bob's messages use Bob's chain, not Alice's.

## 3. Per-member group state

For each group, each member stores, per other member:

| Item | Purpose | Rotated when |
| --- | --- | --- |
| Sender chain key (32-byte secret) | Ratchets forward to derive one message key per message | Every message (ratchet step); fully replaced on rekey (see §5) |
| Sender signing keypair (Ed25519) | Signs each group message so recipients can authenticate the sender | On rekey (see §5) |
| Current chain step counter | Lets recipients derive the right message key and detect gaps / replays | Advances per message |

Plus, per group, each member stores its own sending chain and signing
keypair, the member list, and the admin list (§7).

Message-key derivation (design-level, not a code specification):

1. Message key = KDF(chain key, step counter); the chain key is then
   ratcheted forward with a one-way function before the next message.
2. Plaintext is encrypted with AES-256-GCM under the message key.
3. The ciphertext, step counter, sender identity, and group id are signed
   with the sender's group signing key.
4. Recipients verify the signature first, then derive (or look up) the
   message key for that step and decrypt.

Design consequences:

- A recipient that missed messages must be able to derive or retain skipped
  message keys up to a bounded gap; beyond that bound, the sender's key must
  be re-fetched via a 1-to-1 envelope (see §4). The exact gap bound is an
  open question (§9).
- Out-of-order delivery within the bound is tolerable; replayed step
  counters must be rejected once a step has been decrypted.

## 4. Key distribution: only through 1-to-1 envelopes

Sender keys are **never** posted in the clear, and never posted as a group
broadcast that a not-yet-member could read. They are distributed exclusively
inside the existing v1 1-to-1 double-ratchet envelopes, which are already
authenticated and encrypted between two devices:

- **Join:** when a new member joins, each existing member sends that member
  its current sender chain key and signing public key in a 1-to-1 v1
  envelope. The new member generates its own fresh sending chain and signing
  keypair and sends them to every existing member the same way.
- **Join cost:** O(N) 1-to-1 envelopes per join (one per existing member in
  each direction). This is a one-time, membership-event cost, not a
  per-message cost — that trade-off is the whole point of Sender Keys.
- **New members and old history:** a new member receives current sender
  keys only. It can decrypt messages sent **after** it joined. It does **not**
  retroactively gain old messages, and old sender keys are not re-sent to it.
  (Whether old history is separately shared from a backup is a backup-design
  question, not something this scheme provides on its own.)
- **No trusted dealer:** there is no group key owned by an admin or by the
  relay. The relay stores and forwards ciphertext and 1-to-1 key-distribution
  envelopes; it never holds a sender chain key in plaintext and cannot
  decrypt group messages.

## 5. Rekey on membership change and kick: what rotates, what does not

### 5.1 What happens on leave or kick

When a member leaves voluntarily, or an admin kicks a member:

1. The departing member is removed from the member list (admin action for a
   kick; self-action for a leave).
2. **Every remaining member rotates its own sender keys**: it generates a
   fresh chain key and a fresh signing keypair for the group.
3. Each remaining member distributes its fresh sender key to every other
   **remaining** member via 1-to-1 v1 envelopes. The removed member receives
   nothing in this round.
4. From that point on, messages are encrypted under the new chains, which
   the removed member does not hold.

Rekey cost is O(N) 1-to-1 envelopes per remaining member, i.e. O(N²)
envelopes for the group in the worst case, once per membership change.
That is expensive for very large groups, and is the main scaling limit of
this design (see §6).

### 5.2 What is NOT retroactively protected — stated plainly

- **Old messages stay decryptable by the removed member.** The removed
  member kept the old sender chain keys and old message keys it already
  received. Rotating keys does not, and cannot, erase keys or ciphertexts
  already in that member's possession. Anyone who had access to group
  history before removal keeps that history.
- **Forward secrecy boundary:** the one-way chain ratchet means that a
  chain key at step *t* does not reveal message keys for steps before *t*
  (they were derived and then the chain moved on). But a chain key at step
  *t* **does** allow decrypting that sender's messages from step *t* onward
  until the next rotation. That is why rotation on kick matters: without it,
  a kicked member holding a current chain key could keep decrypting future
  messages from that sender.
- **Compromise boundary:** if a member's device is compromised, the attacker
  learns that member's own sending chain and every other member's sender
  keys stored on that device — i.e. the ability to read that group's traffic
  until the next rekey, and the group's history stored on that device. The
  remedy is the same as for a kick: remove/replace the device and rotate
  (see §7). There is no post-compromise recovery for messages already
  exposed, and no mechanism here that heals a compromised chain without a
  rotation event.
- **No backward secrecy for joins either:** a new member gets current keys
  only, so it cannot read the past — but a member who rejoins after a kick
  is a *new* member, not a continuation; the group must not silently reuse
  the pre-kick keys for them.

### 5.3 What does NOT rotate

- Members' long-term identity keys do not rotate on a group rekey.
- Other groups' sender keys do not rotate.
- 1-to-1 double-ratchet sessions do not rotate just because a group rekeyed.
- The group id does not change, so clients can keep one group thread across
  a rekey; only the sender-key epoch changes.

## 6. Group size targets and fan-out cost

Design targets (targets, not measured results — nothing here is implemented
or benchmarked yet):

| Group size | v1 per-recipient envelopes per message | Sender Keys ciphertexts per message | Sender keys each member stores |
| --- | --- | --- | --- |
| 8 (v1 cap) | 8 | 1 | 8 |
| 20 | 20 | 1 | 20 |
| 50 | 50 | 1 | 50 |
| 100 | 100 | 1 | 100 |

- **Per-message fan-out:** O(1) ciphertext instead of O(N). This is the win.
- **Per-join cost:** O(N) 1-to-1 key-distribution envelopes.
- **Per-kick/leave cost:** O(N²) 1-to-1 envelopes in the worst case (every
  remaining member re-keys to every other remaining member). For a 100-person
  group that is ~10,000 envelopes for one kick, which is why the design
  target below is a soft cap, not an unbounded promise.
- **Design target:** groups up to ~50 members as the comfortable operating
  range; up to ~100 as a soft cap where kicks are expected to be rare. Beyond
  that, membership churn makes rekey cost dominant, and a different protocol
  (see §8) is needed. No group size above 100 is promised by this design.
- **Relay load:** the relay delivers one group ciphertext per message to
  each member (or holds it in each member's mailbox until fetched). Relay
  bandwidth is still O(N) deliveries; what Sender Keys saves is sender-side
  encryption work and envelope count, not relay delivery work.

## 7. Admin and member operations

- **Create:** the creator becomes the first admin and the first member, and
  generates the first sender key. Group creation itself does not encrypt
  anything to anyone.
- **Invite / add:** an admin (or any member, if the group policy allows —
  policy is an open question, §9) invites a user; on acceptance, the §4 join
  exchange runs. Until that exchange completes, the new member must not be
  shown as able to read new messages, and senders must not assume it can.
- **Leave:** a member leaves; the remaining members rekey per §5. A member
  who leaves cannot rejoin silently — rejoining is a fresh join (§4).
- **Kick:** an admin removes a member; the remaining members rekey per §5.
  The kicked member's client must delete the group's current sender keys on
  receipt of the removal notice, but the design does **not** rely on that
  deletion for security — security comes from the rotation, because a
  malicious client could ignore the deletion instruction. Old history on
  the kicked device is out of the group's control (§5.2).
- **Admin transfer / multiple admins:** a group should not become
  unmanageable if the sole admin leaves. The design provides for more than
  one admin and for admin transfer, but the exact quorum/transfer rule is
  an open question (§9). At minimum: an admin leaving must hand off or the
  group must elect/assign a successor before the leave completes, and a
  group with no admin must still allow members to leave.
- **Device handling:** a sender key belongs to a *member* in this design;
  how it maps to a member's multiple devices (one key per member shared
  across their devices, vs one key per device) is an open question (§9) and
  must be settled before implementation, because it changes both the
  distribution cost and the kick semantics.

## 8. Explicitly not MLS

**MLS (Messaging Layer Security) is a future research item. It is NOT
implemented here, and this design must not be described as MLS.**

Differences that matter:

- MLS provides a single group key agreement with efficient, tree-based
  rekeying (logarithmic rather than the O(N²) rekey cost in §5), formal
  forward secrecy and post-compromise security properties, and a standard
  group state machine. Sender Keys provides none of those guarantees in
  full; it is the pragmatic pre-MLS approach the plan names.
- Adopting MLS later would be a new protocol upgrade with its own envelope
  type and migration story, not a drop-in replacement for the sender keys
  in this document.
- No document, UI string, or announcement for this feature may use the
  words "MLS" to describe what is built here. The correct label is
  "Sender Keys groups".

## 9. Open questions

- What is the bounded skipped-message-key gap before a recipient must
  re-fetch a sender key via a 1-to-1 envelope, and how many skipped keys
  may a client retain?
- Is group membership policy admin-only invite, or may any member invite?
  Who approves a join, and how is a forged invite rejected?
- What is the admin transfer / multi-admin rule, especially when the sole
  admin leaves or is removed?
- Does a sender key belong to a member (shared across that member's
  devices) or to each device separately, and how does that interact with
  device revocation?
- Should groups between 9 and some threshold stay on v1 envelopes until a
  size trigger, or switch to Sender Keys immediately on exceeding 8?
- How are group messages acknowledged or marked delivered/read, if at all,
  without leaking read state to the relay beyond what v1 already leaks?
- What is the relay retention policy for undelivered group ciphertexts and
  for 1-to-1 key-distribution envelopes to offline members?
- How does a client recover when its stored sender keys for a group are
  lost or desynchronised (e.g. after a backup restore) without rejoining?

## Status: DESIGN ONLY -- NOT IMPLEMENTED

No Sender Keys code, envelope format, or group-size change is implemented
by this document. The v1 per-recipient cap of 8 remains the implemented
behaviour. MLS is not implemented. Group sizes above 8, rekey behaviour,
and the cost figures in §6 are design targets and reasoning, not measured
results.
