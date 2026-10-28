'use strict';
/*
 * ECNUchat v2 — Track C (b): Large groups via Sender Keys. WORKING CODE.
 *
 * This is NOT MLS. It must never be described as MLS. Label: "Sender Keys
 * groups" (see ../docs/large-groups-sender-keys.md §8). Differences that
 * matter: rekey on kick is O(N^2) 1-to-1 envelopes, there is no tree
 * key agreement, no formal post-compromise security, and old messages
 * stay decryptable by a removed member (it already holds the old keys).
 *
 * Design implemented here (matching the design doc):
 *  - Each member has ONE sending chain per group: a 32-byte chain key
 *    plus an Ed25519 group signing keypair (fresh per epoch).
 *  - Message key derivation mirrors the 1-to-1 ratchet step:
 *      mk     = HMAC-SHA256(chain_key, 0x01)
 *      next   = HMAC-SHA256(chain_key, 0x02)
 *    Plaintext is AES-256-GCM under mk. AAD = group_id || sender ||
 *    epoch || step (big-endian). The ciphertext, step, sender, group
 *    id and epoch are signed with the sender's group signing key;
 *    recipients verify the signature BEFORE decrypting.
 *  - Sender keys are distributed ONLY inside 1-to-1 double-ratchet
 *    envelopes. This module produces/consumes the distribution
 *    payload object; it never sends it in the clear itself. Callers
 *    must pass the JSON of getOwnDistribution() through the 1-to-1
 *    session (pwa/crypto.js sessionEncrypt) — see the test that does
 *    exactly that. Sending a distribution payload over any clear
 *    channel defeats the scheme.
 *  - Skipped message keys: up to MAX_SKIP (40) per sender, mirroring
 *    the 1-to-1 skipped-key cache. Beyond that, decrypt throws and
 *    the caller must re-fetch the sender key via a 1-to-1 envelope.
 *  - Replay: a step already decrypted is rejected. A stale epoch
 *    (pre-kick) envelope is rejected; a future epoch is rejected
 *    until the new sender keys arrive via rekey distributions.
 *  - Kick/leave: every remaining member rotates its own sender key
 *    (fresh chain key + fresh signing keypair), epoch increments,
 *    and the new keys go ONLY to remaining members. A former member
 *    holds only old keys, so it cannot verify (new signing key) or
 *    decrypt (new chain key) post-kick messages. Old history on the
 *    former member's device is NOT erased by this — see §5.2 of the
 *    design doc, stated plainly here too.
 *  - Scope: groups above 8 members. Groups of <= 8 keep v1
 *    per-recipient envelopes; this module does not change that.
 *    Soft cap ~50, hard design cap 100 (rekey cost dominates above).
 *
 * Crypto sources: Ed25519 via tweetnacl (vendored in ../pwa/vendor/,
 * read-only here, never copied into this directory); HMAC/AES-GCM via
 * WebCrypto SubtleCrypto (browser + Node 18+). No private key ever
 * leaves a device through this module except inside a caller-supplied
 * 1-to-1 encrypted envelope, which is the distribution mechanism.
 */
(function (root) {
  var nacl = null;
  if (typeof require === 'function') {
    try { nacl = require('../pwa/vendor/nacl-fast.min.js'); } catch (e) { nacl = null; }
  }
  if (!nacl) nacl = root.nacl || (typeof self !== 'undefined' ? self.nacl : null);
  if (!nacl) throw new Error('tweetnacl (nacl) is not loaded; include ../pwa/vendor/nacl-fast.min.js before sender_keys.js');

  function subtle() {
    var c = (typeof crypto !== 'undefined' ? crypto : null) || root.crypto;
    if (!c || !c.subtle) throw new Error('SubtleCrypto unavailable');
    return c.subtle;
  }
  function enc() { return new TextEncoder(); }
  function dec() { return new TextDecoder(); }
  function concat() {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
    return out;
  }
  function u32be(n) {
    var b = new Uint8Array(4);
    b[0] = (n >>> 24) & 255; b[1] = (n >>> 16) & 255; b[2] = (n >>> 8) & 255; b[3] = n & 255;
    return b;
  }
  function b64(bytes) {
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
    var s = ''; bytes.forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s);
  }
  function unb64(s) {
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'base64'));
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function eq(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function randomBytes(n) {
    var out = new Uint8Array(n);
    var c = (typeof crypto !== 'undefined' ? crypto : null) || root.crypto;
    if (c && c.getRandomValues) { c.getRandomValues(out); return out; }
    if (typeof require === 'function') { out.set(require('crypto').randomBytes(n)); return out; }
    throw new Error('No secure RNG available');
  }
  async function hmac(keyBytes, msgBytes) {
    var s = subtle();
    var key = await s.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await s.sign('HMAC', key, msgBytes));
  }
  async function aesEncrypt(keyBytes, nonce, plaintext, aad) {
    var s = subtle();
    var key = await s.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    return new Uint8Array(await s.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, plaintext));
  }
  async function aesDecrypt(keyBytes, nonce, ciphertext, aad) {
    var s = subtle();
    var key = await s.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    return new Uint8Array(await s.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, ciphertext));
  }

  var MAX_SKIP = 40;
  var MAX_MEMBERS = 100;

  function createSenderKey() {
    var kp = nacl.sign.keyPair();
    return { chainKey: randomBytes(32), signPub: kp.publicKey, signSec: kp.secretKey, step: 0 };
  }

  // Distribution payload: MUST travel inside a 1-to-1 ratchet envelope.
  function distributionFor(groupId, epoch, senderId, senderKey) {
    return {
      type: 'ecnu-sender-key-dist-v1',
      group_id: groupId, epoch: epoch, sender: senderId,
      chain_key: b64(senderKey.chainKey), sign_pub: b64(senderKey.signPub),
      step: senderKey.step
    };
  }
  function parseDistribution(obj) {
    if (!obj || obj.type !== 'ecnu-sender-key-dist-v1') throw new Error('Not a Sender Keys distribution payload');
    if (typeof obj.group_id !== 'string' || !obj.group_id) throw new Error('Distribution missing group_id');
    if (typeof obj.sender !== 'string' || !obj.sender) throw new Error('Distribution missing sender');
    if (typeof obj.epoch !== 'number' || obj.epoch < 0) throw new Error('Distribution epoch invalid');
    var chainKey = unb64(obj.chain_key), signPub = unb64(obj.sign_pub);
    if (chainKey.length !== 32 || signPub.length !== 32) throw new Error('Distribution key length invalid');
    if (typeof obj.step !== 'number' || obj.step < 0) throw new Error('Distribution step invalid');
    return { groupId: obj.group_id, epoch: obj.epoch, sender: obj.sender, chainKey: chainKey, signPub: signPub, step: obj.step };
  }

  function Group(groupId, selfId) {
    if (!groupId || !selfId) throw new Error('Group requires groupId and selfId');
    this.groupId = groupId;
    this.selfId = selfId;
    this.epoch = 0;
    this.members = new Set([selfId]);
    this.own = createSenderKey();
    // senderId -> { chainKey, signPub, step, skipped: Map(step->mk), seen: Set(step) }
    this.senders = new Map();
  }
  Group.prototype.getOwnDistribution = function () {
    return distributionFor(this.groupId, this.epoch, this.selfId, this.own);
  };
  // Apply a distribution received via a 1-to-1 envelope. Sender keys
  // for an older epoch are ignored (stale); a newer epoch replaces
  // the stored key for that sender and moves this group's epoch.
  Group.prototype.applyDistribution = function (distObj) {
    var d = parseDistribution(distObj);
    if (d.groupId !== this.groupId) throw new Error('Distribution group_id mismatch');
    if (d.sender === this.selfId) throw new Error('Distribution for self is not accepted from a peer');
    if (d.epoch < this.epoch) return false; // stale rekey round: ignore
    if (d.epoch > this.epoch) this.epoch = d.epoch;
    this.senders.set(d.sender, {
      chainKey: d.chainKey, signPub: d.signPub, step: d.step,
      skipped: new Map(), seen: new Set()
    });
    this.members.add(d.sender);
    return true;
  };
  Group.prototype.addMember = function (memberId) {
    if (this.members.size >= MAX_MEMBERS) throw new Error('Group member cap (100) reached');
    this.members.add(memberId);
  };
  Group.prototype.hasMember = function (memberId) { return this.members.has(memberId); };

  Group.prototype.encrypt = async function (text) {
    if (typeof text !== 'string') throw new Error('Group text must be a string');
    var step = this.own.step;
    var mk = await hmac(this.own.chainKey, new Uint8Array([0x01]));
    this.own.chainKey = await hmac(this.own.chainKey, new Uint8Array([0x02]));
    this.own.step = step + 1;
    var nonce = randomBytes(12);
    var aad = concat(enc().encode(this.groupId), enc().encode(this.selfId), u32be(this.epoch), u32be(step));
    var ct = await aesEncrypt(mk, nonce, enc().encode(text), aad);
    var signed = concat(enc().encode(this.groupId), enc().encode(this.selfId),
      u32be(this.epoch), u32be(step), nonce, ct);
    var sig = nacl.sign.detached(signed, this.own.signSec);
    return {
      type: 'ecnu-group-msg-v1', group_id: this.groupId, sender: this.selfId,
      epoch: this.epoch, step: step, nonce: b64(nonce), ciphertext: b64(ct),
      signature: b64(sig)
    };
  };

  Group.prototype.decrypt = async function (env) {
    if (!env || env.type !== 'ecnu-group-msg-v1') throw new Error('Not a Sender Keys group message');
    if (env.group_id !== this.groupId) throw new Error('Group message group_id mismatch');
    if (env.sender === this.selfId) throw new Error('Own group messages are not decrypted via the peer path');
    if (!this.members.has(env.sender)) throw new Error('Sender is not a member of this group');
    if (env.epoch < this.epoch) throw new Error('Stale epoch: message predates the latest rekey (former-member keys do not apply)');
    if (env.epoch > this.epoch) throw new Error('Unknown future epoch: re-fetch sender keys via 1-to-1 envelopes first');
    var st = this.senders.get(env.sender);
    if (!st) throw new Error('No sender key for ' + env.sender + '; fetch it via a 1-to-1 envelope first');
    var nonce = unb64(env.nonce), ct = unb64(env.ciphertext), sig = unb64(env.signature);
    var signed = concat(enc().encode(this.groupId), enc().encode(env.sender),
      u32be(env.epoch), u32be(env.step), nonce, ct);
    if (!nacl.sign.detached.verify(signed, sig, st.signPub)) {
      throw new Error('Group message signature verification failed');
    }
    if (st.seen.has(env.step)) throw new Error('Replay rejected: step already decrypted');
    var aad = concat(enc().encode(this.groupId), enc().encode(env.sender), u32be(env.epoch), u32be(env.step));
    var mk;
    if (st.skipped.has(env.step)) {
      mk = st.skipped.get(env.step); st.skipped.delete(env.step);
    } else {
      if (env.step < st.step) throw new Error('Replay rejected: step already passed');
      var gap = env.step - st.step;
      if (st.skipped.size + gap > MAX_SKIP) throw new Error('Skip limit exceeded (40): re-fetch sender key via a 1-to-1 envelope');
      var ck = st.chainKey;
      while (st.step < env.step) {
        var m = await hmac(ck, new Uint8Array([0x01]));
        ck = await hmac(ck, new Uint8Array([0x02]));
        st.skipped.set(st.step, m); st.step += 1;
      }
      mk = await hmac(ck, new Uint8Array([0x01]));
      st.chainKey = await hmac(ck, new Uint8Array([0x02]));
      st.step = env.step + 1;
    }
    var pt;
    try { pt = await aesDecrypt(mk, nonce, ct, aad); }
    catch (e) { throw new Error('Group message decryption failed (GCM authentication)'); }
    st.seen.add(env.step);
    return dec().decode(pt);
  };

  // Kick (admin action) or leave (self action): rotate ONLY this
  // member's own sender key, bump the epoch, and return the fresh
  // distribution to send to every REMAINING member via 1-to-1
  // envelopes. The removed member receives nothing. Callers must
  // remove the member from their member list and call applyRekey
  // with every remaining member's new distribution.
  // Returns { distribution, removed }.
  Group.prototype.rotateForKick = function (removedId) {
    if (!this.members.has(removedId)) throw new Error('Cannot kick a non-member');
    this.members.delete(removedId);
    this.senders.delete(removedId);
    this.own = createSenderKey();
    this.epoch += 1;
    return { distribution: this.getOwnDistribution(), removed: removedId };
  };
  // Apply a full rekey round: replace sender keys for every sender
  // in `distributions` (each via 1-to-1 envelope) and drop the
  // removed member. Distributions at the new epoch win; older ones
  // are ignored by applyDistribution.
  Group.prototype.applyRekey = function (distributions, removedId) {
    if (removedId) { this.members.delete(removedId); this.senders.delete(removedId); }
    var applied = 0;
    for (var i = 0; i < distributions.length; i++) {
      if (this.applyDistribution(distributions[i])) applied += 1;
    }
    return applied;
  };

  var api = {
    MAX_SKIP: MAX_SKIP, MAX_MEMBERS: MAX_MEMBERS,
    createSenderKey: createSenderKey,
    distributionFor: distributionFor, parseDistribution: parseDistribution,
    Group: Group
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ECNUSenderKeys = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
