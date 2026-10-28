'use strict';
/*
 * ECNUchat v2 — real classical crypto core (NOT a demo stand-in).
 *
 * What it implements, matching the original Python v1 design
 * (src/x3dh.py, src/double_ratchet.py, src/protocol.py, as read from
 * https://github.com/Tomhao10225101490/ECNUchat):
 *  - X25519 ECDH and Ed25519 signatures via tweetnacl 1.0.3
 *    (vendored in ./vendor/nacl-fast.min.js, Unlicense — see
 *    ./vendor/LICENSE-tweetnacl). No curve code is hand-rolled here.
 *  - Classical X3DH: DH1 = IK_dh x SPK, DH2 = EK x IK_dh,
 *    DH3 = EK x SPK, optional DH4 = EK x OPK, then
 *    HKDF-SHA256(salt = 32 zero bytes, info = "x3dh-v1", 32 bytes)
 *    to a ratchet root SK. SK is NEVER a message key.
 *  - Double ratchet (classical only): KDF_CK is
 *    MK = HMAC(ck, 0x01), newCK = HMAC(ck, 0x02); KDF_RK is
 *    HKDF(salt = rk, info = "dr-v1", 64 bytes) -> RK || CK;
 *    per-message AES-256-GCM, AAD = sender || receiver ||
 *    n (4-byte BE) || pn (4-byte BE) || dh_pub, skipped-key
 *    cache capped at 40, replay rejection. This mirrors v1's
 *    kdf_ck / kdf_rk / build_aad / encrypt / decrypt semantics.
 *  - Ratchet payload field names match v1's encode_ratchet_payload:
 *    dh_pub, n, pn, nonce, ciphertext, kind, and x3dh =
 *    { ik_dh_pub, ek_pub, opk_pub, signature } on the first
 *    message only. The initial signature covers
 *    ik_dh_pub || ek_pub || (opk_pub or "").
 *  - SPK signature rule, matching v1 (prekeys.py sign_spk):
 *    Ed25519 over spk_pub || username (UTF-8). generateIdentity
 *    therefore takes the username, and parseBundle verifies with
 *    the peer username. Identities generated under the old
 *    spk_pub-only rule are NOT accepted: they must re-register.
 *    This is a strengthening (the key is bound to the name).
 *  - Inner plaintext, matching v1 (client.py _decrypt_envelope):
 *    every ratchet plaintext is the v1 inner JSON
 *    {"v": 1, "text", "group": null, "kind": "chat",
 *     "gstate": null, "thread": null, "thread_title": null,
 *     "privacy": null}, and sessionDecrypt cross-checks kind and
 *    group against the outer payload, exactly as v1 does for
 *    1-to-1 chat. Raw-text plaintexts are rejected, not rendered.
 *  - One-time prekey pool, matching v1 (OPK_POOL_SIZE = 20,
 *    OPK_REFILL_THRESHOLD = 5): an identity holds 20 OPKs, the
 *    relay's bundle-fetch endpoint consumes exactly one per
 *    fetch, and the receiver drops its consumed OPK after the
 *    first message decrypts and refills below 5. A consumed OPK
 *    is never re-served as fresh.
 *  - Fingerprint = SHA-256 of the Ed25519 identity public key,
 *    rendered as 16 groups of 4 uppercase hex chars, as in v1.
 *
 * What it does NOT implement (explicit, not faked):
 *  - ML-KEM-768 / PQXDH / hybrid ratchet: PQ_SUPPORTED = false.
 *    Sessions here are classical x3dh-v1 / dr-v1 only. A v1 peer
 *    that requires a PQ bundle will not accept a classical-only
 *    session as a hybrid one; do not claim otherwise. Endpoint
 *    fixes 1–3 of docs/v1-interop-gap.md §6 (SPK rule, inner JSON,
 *    OPK pool + consumption) ARE implemented here; PQ (step 4),
 *    dual-stack auth (G8) and the WS↔HTTP bridge (step 5) are not,
 *    so end-to-end interop with a real v1 client is still NOT
 *    claimed (see STATUS.md).
 *  - The original v1 bundle store / WebSocket transport: this core
 *    speaks the same crypto and payload fields, but the v2 relay
 *    (HTTP JSON, see ../relay/README.md) is a different transport
 *    from v1's WebSocket server, and the v2 bundle is carried in
 *    the relay's public_keys object. Full client-to-client interop
 *    with the original Python v1 client has NOT been tested and
 *    is NOT claimed (see STATUS.md).
 *
 * Key storage warning: this module only returns key bytes. The
 * PWA stores them in localStorage, which is NOT production-grade
 * secure storage. Production must move keys to an OS keychain /
 * hardware-backed store.
 */
(function (root) {
  var nacl = null;
  if (typeof require === 'function') {
    try { nacl = require('./vendor/nacl-fast.min.js'); } catch (e) { nacl = null; }
  }
  if (!nacl) nacl = root.nacl || (typeof self !== 'undefined' ? self.nacl : null);
  if (!nacl) throw new Error('tweetnacl (nacl) is not loaded; include vendor/nacl-fast.min.js before crypto.js');

  var subtle = null;
  try { subtle = (root.crypto && root.crypto.subtle) || (typeof crypto !== 'undefined' && crypto.subtle) || null; } catch (e) { subtle = null; }
  function needSubtle() {
    if (!subtle) throw new Error('SubtleCrypto unavailable in this context; serve over http://localhost (see pwa/README.md).');
    return subtle;
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
    var s = '';
    bytes.forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s);
  }
  function unb64(s) {
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'base64'));
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function hex(bytes) {
    return Array.from(bytes).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  function eq(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function randomBytes(n) {
    var out = new Uint8Array(n);
    var c = root.crypto || (typeof crypto !== 'undefined' ? crypto : null);
    if (c && c.getRandomValues) c.getRandomValues(out);
    else if (typeof require === 'function') {
      var rb = require('crypto').randomBytes(n);
      out.set(rb);
    } else throw new Error('No secure RNG available');
    return out;
  }
  async function hmacSha256(keyBytes, msgBytes) {
    var s = needSubtle();
    var key = await s.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    var sig = await s.sign('HMAC', key, msgBytes);
    return new Uint8Array(sig);
  }
  async function hkdf(ikm, salt, info, length) {
    var prk;
    if (!salt) salt = new Uint8Array(32);
    prk = await hmacSha256(salt, ikm);
    var out = new Uint8Array(0), t = new Uint8Array(0), counter = 1;
    while (out.length < length) {
      t = await hmacSha256(prk, concat(t, info, new Uint8Array([counter])));
      out = concat(out, t);
      counter++;
    }
    return out.slice(0, length);
  }
  async function sha256(bytes) {
    var s = needSubtle();
    var d = await s.digest('SHA-256', bytes);
    return new Uint8Array(d);
  }
  async function fingerprintOf(ikSignPub) {
    var d = await sha256(ikSignPub);
    var h = hex(d).toUpperCase();
    var groups = [];
    for (var i = 0; i < 64; i += 4) groups.push(h.slice(i, i + 4));
    return groups.join(' ');
  }
  async function aesGcmEncrypt(keyBytes, nonce, plaintext, aad) {
    var s = needSubtle();
    var key = await s.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    var ct = await s.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, plaintext);
    return new Uint8Array(ct);
  }
  async function aesGcmDecrypt(keyBytes, nonce, ciphertext, aad) {
    var s = needSubtle();
    var key = await s.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    var pt = await s.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, ciphertext);
    return new Uint8Array(pt);
  }
  function x25519(priv, pub) {
    if (priv.length !== 32 || pub.length !== 32) throw new Error('X25519 key length must be 32 bytes');
    return nacl.scalarMult(priv, pub);
  }
  function edSign(secretKey64, message) { return nacl.sign.detached(message, secretKey64); }
  function edVerify(message, signature, publicKey) { return nacl.sign.detached.verify(message, signature, publicKey); }

  var OPK_POOL_SIZE = 20;      // v1 OPK_POOL_SIZE
  var OPK_REFILL_THRESHOLD = 5; // v1 OPK_REFILL_THRESHOLD

  function generateIdentity(username) {
    if (typeof username !== 'string' || !username) {
      throw new Error('generateIdentity requires a username: the SPK signature binds spk_pub to the username (v1 sign_spk rule)');
    }
    var ikSign = nacl.sign.keyPair();
    var ikDh = nacl.box.keyPair();
    var spk = nacl.box.keyPair();
    var opks = [];
    var i;
    for (i = 0; i < OPK_POOL_SIZE; i++) opks.push(nacl.box.keyPair());
    // v1 rule (prekeys.py sign_spk): Ed25519 over spk_pub || username.
    var spkSignature = edSign(ikSign.secretKey, concat(spk.publicKey, enc().encode(username)));
    return { username: username, ikSign: ikSign, ikDh: ikDh, spk: spk, spkSignature: spkSignature, opks: opks, opk: opks[0] };
  }
  function opkPubs(id) {
    if (id.opks && id.opks.length) return id.opks.map(function (k) { return k.publicKey; });
    if (id.opk) return [id.opk.publicKey];
    return [];
  }
  function bundleFromIdentity(id) {
    if (!id.username) throw new Error('Identity has no username; re-register with generateIdentity(username) (SPK signature binds the key to the name)');
    var pubs = opkPubs(id);
    return {
      ik_sign_pub: b64(id.ikSign.publicKey),
      ik_dh_pub: b64(id.ikDh.publicKey),
      spk_pub: b64(id.spk.publicKey),
      spk_signature: b64(id.spkSignature),
      spk_created: Math.floor(Date.now() / 1000),
      opk_pub: pubs.length ? b64(pubs[0]) : null,
      opks: pubs.map(function (p) { return b64(p); })
    };
  }
  function parseBundle(obj, username) {
    if (!obj) throw new Error('Missing peer bundle');
    if (typeof username !== 'string' || !username) {
      throw new Error('parseBundle requires the peer username: the SPK signature is verified over spk_pub || username (v1 rule)');
    }
    function f(name, len) {
      var v = obj[name];
      if (typeof v !== 'string') throw new Error('Bundle field missing: ' + name);
      var b = unb64(v);
      if (b.length !== len) throw new Error('Bundle field wrong length: ' + name);
      return b;
    }
    var b = {
      ik_sign_pub: f('ik_sign_pub', 32),
      ik_dh_pub: f('ik_dh_pub', 32),
      spk_pub: f('spk_pub', 32),
      spk_signature: f('spk_signature', 64),
      opk_pub: obj.opk_pub ? f('opk_pub', 32) : null,
      opks: []
    };
    if (Array.isArray(obj.opks)) {
      b.opks = obj.opks.map(function (s) {
        var p = unb64(s);
        if (p.length !== 32) throw new Error('Bundle field wrong length: opks entry');
        return p;
      });
    } else if (b.opk_pub) {
      b.opks = [b.opk_pub];
    }
    // v1 rule: verify over spk_pub || username, NOT spk_pub alone.
    // A bundle signed under the old v2 rule fails here by design.
    if (!edVerify(concat(b.spk_pub, enc().encode(username)), b.spk_signature, b.ik_sign_pub)) {
      throw new Error('Peer signed-prekey signature verification failed (v1 rule: spk_pub || username)');
    }
    return b;
  }
  function serializeIdentity(id) {
    var pubs = opkPubs(id);
    var secs = [];
    if (id.opks && id.opks.length) secs = id.opks.map(function (k) { return k.secretKey; });
    else if (id.opk) secs = [id.opk.secretKey];
    return {
      username: id.username || null,
      ik_sign_pub: b64(id.ikSign.publicKey), ik_sign_sec: b64(id.ikSign.secretKey),
      ik_dh_pub: b64(id.ikDh.publicKey), ik_dh_sec: b64(id.ikDh.secretKey),
      spk_pub: b64(id.spk.publicKey), spk_sec: b64(id.spk.secretKey),
      spk_signature: b64(id.spkSignature),
      opk_pub: pubs.length ? b64(pubs[0]) : null,
      opk_sec: secs.length ? b64(secs[0]) : null,
      opks_pub: pubs.map(function (p) { return b64(p); }),
      opks_sec: secs.map(function (s) { return b64(s); })
    };
  }
  function parseIdentity(obj) {
    function kp(pub, sec) { return { publicKey: unb64(pub), secretKey: unb64(sec) }; }
    var opks = [];
    if (Array.isArray(obj.opks_pub) && Array.isArray(obj.opks_sec)
        && obj.opks_pub.length === obj.opks_sec.length) {
      opks = obj.opks_pub.map(function (p, i) { return kp(p, obj.opks_sec[i]); });
    } else if (obj.opk_pub && obj.opk_sec) {
      opks = [kp(obj.opk_pub, obj.opk_sec)];
    }
    return {
      username: obj.username || null,
      ikSign: kp(obj.ik_sign_pub, obj.ik_sign_sec),
      ikDh: kp(obj.ik_dh_pub, obj.ik_dh_sec),
      spk: kp(obj.spk_pub, obj.spk_sec),
      spkSignature: unb64(obj.spk_signature),
      opks: opks,
      opk: opks.length ? opks[0] : null
    };
  }
  function findOpk(me, pub) {
    if (!pub) return null;
    if (me.opks) {
      for (var i = 0; i < me.opks.length; i++) {
        if (eq(me.opks[i].publicKey, pub)) return me.opks[i];
      }
    }
    if (me.opk && eq(me.opk.publicKey, pub)) return me.opk;
    return null;
  }
  // Drop a consumed OPK from an identity (after first-message GCM
  // success, mirroring v1's delayed OPK deletion). Never re-serves it.
  function dropOpk(me, pub) {
    if (!pub) return;
    if (me.opks) me.opks = me.opks.filter(function (k) { return !eq(k.publicKey, pub); });
    if (me.opk && eq(me.opk.publicKey, pub)) me.opk = me.opks && me.opks.length ? me.opks[0] : null;
  }
  // Refill the pool back to OPK_POOL_SIZE with fresh OPKs. OPKs are
  // unsigned, so refilling does not change the SPK signature.
  function refillOpks(me) {
    if (!me.opks) me.opks = me.opk ? [me.opk] : [];
    while (me.opks.length < OPK_POOL_SIZE) me.opks.push(nacl.box.keyPair());
    me.opk = me.opks[0];
    return me.opks.length;
  }
  async function hkdfSk(dhMaterial) {
    if (!dhMaterial.length || dhMaterial.length % 32 !== 0) throw new Error('DH material length must be a multiple of 32');
    return hkdf(dhMaterial, new Uint8Array(32), enc().encode('x3dh-v1'), 32);
  }
  async function kdfRk(rk, dhOut) {
    var out = await hkdf(dhOut, rk, enc().encode('dr-v1'), 64);
    return { rk: out.slice(0, 32), ck: out.slice(32, 64) };
  }
  async function kdfCk(ck) {
    var mk = await hmacSha256(ck, new Uint8Array([0x01]));
    var newCk = await hmacSha256(ck, new Uint8Array([0x02]));
    return { newCk: newCk, mk: mk };
  }
  function buildAad(sender, receiver, n, pn, dhPub) {
    return concat(enc().encode(sender), enc().encode(receiver), u32be(n), u32be(pn), dhPub);
  }
  async function x3dhInitiatorSecret(me, peerBundle) {
    var ek = nacl.box.keyPair();
    var dh1 = x25519(me.ikDh.secretKey, peerBundle.spk_pub);
    var dh2 = x25519(ek.secretKey, peerBundle.ik_dh_pub);
    var dh3 = x25519(ek.secretKey, peerBundle.spk_pub);
    var material = dh1;
    if (peerBundle.opk_pub) material = concat(material, dh2, dh3, x25519(ek.secretKey, peerBundle.opk_pub));
    else material = concat(material, dh2, dh3);
    var sk = await hkdfSk(material);
    var signed = concat(me.ikDh.publicKey, ek.publicKey, peerBundle.opk_pub || new Uint8Array(0));
    var signature = edSign(me.ikSign.secretKey, signed);
    var initial = {
      ik_dh_pub: b64(me.ikDh.publicKey),
      ek_pub: b64(ek.publicKey),
      opk_pub: peerBundle.opk_pub ? b64(peerBundle.opk_pub) : null,
      signature: b64(signature)
    };
    return { sk: sk, ek: ek, initial: initial };
  }
  async function x3dhResponderSecret(me, initial, peerIkSignPub, peerIkDhPub) {
    var ekPub = unb64(initial.ek_pub);
    var ikDhPub = unb64(initial.ik_dh_pub);
    var opkPub = initial.opk_pub ? unb64(initial.opk_pub) : null;
    var signature = unb64(initial.signature);
    var opk = opkPub ? findOpk(me, opkPub) : null;
    if (opkPub && !opk) throw new Error('Initial message names an OPK this device does not hold');
    var signed = concat(ikDhPub, ekPub, opkPub || new Uint8Array(0));
    if (!edVerify(signed, signature, peerIkSignPub)) throw new Error('Initial message signature verification failed');
    var dh1 = x25519(me.spk.secretKey, ikDhPub);
    var dh2 = x25519(me.ikDh.secretKey, ekPub);
    var dh3 = x25519(me.spk.secretKey, ekPub);
    var material = dh1;
    if (opkPub) material = concat(material, dh2, dh3, x25519(opk.secretKey, ekPub));
    else material = concat(material, dh2, dh3);
    return hkdfSk(material);
  }

  var MAX_SKIP = 40;
  function cloneState(st) {
    function copyBytes(v) { return v ? new Uint8Array(v) : null; }
    return {
      rk: copyBytes(st.rk), dhs_priv: copyBytes(st.dhs_priv), dhs_pub: copyBytes(st.dhs_pub),
      dhr_pub: copyBytes(st.dhr_pub), cks: copyBytes(st.cks), ckr: copyBytes(st.ckr),
      ns: st.ns, nr: st.nr, pns: st.pns,
      skipped: new Map(Array.from(st.skipped.entries()).map(function (e) { return [e[0], new Uint8Array(e[1])]; })),
      seen: new Set(st.seen), retired: new Set(st.retired), _receiverInit: !!st._receiverInit
    };
  }
  function commitState(target, source) {
    var k;
    for (k in source) target[k] = source[k];
  }
  function skippedKey(dhPub, n) { return b64(dhPub) + ':' + n; }

  // ---- v1 inner plaintext (client.py _decrypt_envelope, 1-to-1 chat) ----
  var INNER_KINDS = ['chat', 'group_meta', 'file', 'thread_init', 'call'];
  function wrapInnerText(text, kind) {
    if (typeof text !== 'string') throw new Error('Inner text must be a string');
    return JSON.stringify({
      v: 1, text: text, group: null, kind: kind || 'chat',
      gstate: null, thread: null, thread_title: null, privacy: null
    });
  }
  function parseInnerText(raw, payload) {
    var inner;
    try { inner = JSON.parse(raw); }
    catch (e) { throw new Error('Inner plaintext is not v1 JSON (message semantic metadata mismatch)'); }
    if (!inner || typeof inner !== 'object') throw new Error('Inner plaintext is not a v1 JSON object');
    if (inner.v !== 1) throw new Error('Inner plaintext version is not 1');
    if (typeof inner.text !== 'string') throw new Error('Inner plaintext has no string text');
    var kind = inner.kind || 'chat';
    if (INNER_KINDS.indexOf(kind) === -1) throw new Error('Inner plaintext kind not recognised');
    var outerKind = (payload && payload.kind) || 'chat';
    if (kind !== outerKind) throw new Error('Inner kind does not match outer payload kind');
    var outerGroup = (payload && payload.group) || null;
    var innerGroup = inner.group || null;
    if (outerGroup !== innerGroup) throw new Error('Inner group does not match outer payload group');
    if (innerGroup !== null) throw new Error('Group messages are not supported by this 1-to-1 core (gstate binding not implemented here)');
    if (inner.thread !== null && inner.thread !== undefined
        && !/^[A-Za-z0-9_-]{1,32}$/.test(inner.thread)) throw new Error('Inner thread token invalid');
    // v1 coerces an out-of-set privacy value to null; it does not throw.
    if (inner.privacy !== null && inner.privacy !== 'low' && inner.privacy !== 'high') inner.privacy = null;
    return inner.text;
  }

  async function sessionEncrypt(session, plaintext) {
    var st = session._state;
    if (!st.cks) {
      if (!st.dhr_pub) throw new Error('No peer ratchet public key; cannot build a sending chain');
      st.pns = st.nr;
      var kp = nacl.box.keyPair();
      st.dhs_priv = kp.secretKey; st.dhs_pub = kp.publicKey;
      var dhOut = x25519(st.dhs_priv, st.dhr_pub);
      var r = await kdfRk(st.rk, dhOut);
      st.rk = r.rk; st.cks = r.ck;
      st.ns = 0;
    }
    var ck = await kdfCk(st.cks);
    st.cks = ck.newCk;
    var n = st.ns, pn = st.pns;
    st.ns = n + 1;
    var nonce = randomBytes(12);
    var aad = buildAad(session.localUser, session.remoteUser, n, pn, st.dhs_pub);
    // v1 inner JSON, not raw text: a v1 receiver rejects raw text.
    var ct = await aesGcmEncrypt(ck.mk, nonce, enc().encode(wrapInnerText(plaintext, 'chat')), aad);
    var payload = {
      dh_pub: b64(st.dhs_pub), n: n, pn: pn, nonce: b64(nonce),
      ciphertext: b64(ct), kind: 'chat'
    };
    if (session._pendingInitial && !session._initialSent) {
      payload.x3dh = session._pendingInitial;
      session._initialSent = true;
    }
    return payload;
  }
  async function decryptOn(st, session, payload) {
    var dhPub = unb64(payload.dh_pub);
    var nonce = unb64(payload.nonce);
    var ct = unb64(payload.ciphertext);
    if (dhPub.length !== 32 || nonce.length !== 12) throw new Error('Ratchet header/nonce length invalid');
    if (!(payload.n >= 0 && payload.n <= 0xffffffff && payload.pn >= 0 && payload.pn <= 0xffffffff)) throw new Error('Ratchet sequence out of range');
    if (ct.length < 16) throw new Error('Ciphertext missing GCM tag');
    var key = skippedKey(dhPub, payload.n);
    if (st.seen.has(key)) throw new Error('Replay rejected');
    async function openWith(mk) {
      var aad = buildAad(session.remoteUser, session.localUser, payload.n, payload.pn, dhPub);
      return dec().decode(await aesGcmDecrypt(mk, nonce, ct, aad));
    }
    if (st.skipped.has(key)) {
      var mk0 = st.skipped.get(key);
      st.skipped.delete(key);
      var pt0 = await openWith(mk0);
      st.seen.add(key);
      return pt0;
    }
    if (st.retired.has(b64(dhPub))) throw new Error('Replay rejected (retired ratchet key)');
    if (session._pendingSk !== null && st.ckr === null && st.dhr_pub === null) {
      // First message to a receiver: initialise the receiving chain
      // from the sender's ratchet public key in this header, using
      // the SK stored at session creation (see createReceiverSession).
      // _pendingSk is cleared by sessionDecrypt only on success, so
      // a failed first decrypt does not lose the pending secret.
      if (!session._me) throw new Error('No ratchet state and no pending X3DH secret');
      var dhOut0 = x25519(session._me.spk.secretKey, dhPub);
      var r0 = await kdfRk(session._pendingSk, dhOut0);
      st.rk = r0.rk; st.ckr = r0.ck; st.dhr_pub = dhPub;
      st._receiverInit = true;
    } else if (st.dhr_pub === null || !eq(dhPub, st.dhr_pub)) {
      if (st.ckr !== null && st.dhr_pub !== null) {
        await skipKeys(st, payload.pn, st.dhr_pub);
      }
      if (st.dhs_priv === null) throw new Error('No local sending ratchet key; cannot DH-ratchet');
      if (st.dhr_pub !== null) st.retired.add(b64(st.dhr_pub));
      st.dhr_pub = dhPub;
      var dhRecv = x25519(st.dhs_priv, dhPub);
      var rr = await kdfRk(st.rk, dhRecv);
      st.rk = rr.rk; st.ckr = rr.ck;
      st.nr = 0; st.pns = st.ns;
      var kp2 = nacl.box.keyPair();
      st.dhs_priv = kp2.secretKey; st.dhs_pub = kp2.publicKey;
      var dhSend = x25519(st.dhs_priv, dhPub);
      var rs = await kdfRk(st.rk, dhSend);
      st.rk = rs.rk; st.cks = rs.ck;
      st.ns = 0;
    }
    if (payload.n < st.nr) throw new Error('Replay rejected');
    await skipKeys(st, payload.n, st.dhr_pub);
    if (st.ckr === null) throw new Error('Receiving chain is empty');
    var ck2 = await kdfCk(st.ckr);
    st.ckr = ck2.newCk;
    st.nr = payload.n + 1;
    var pt = await openWith(ck2.mk);
    st.seen.add(key);
    return pt;
  }
  async function skipKeys(st, until, dhPub) {
    if (st.ckr === null || until < st.nr) return;
    var needed = until - st.nr;
    if (needed <= 0) return;
    if (st.skipped.size + needed > MAX_SKIP) throw new Error('Skip limit exceeded (40)');
    while (st.nr < until) {
      var ck = await kdfCk(st.ckr);
      st.ckr = ck.newCk;
      var k = skippedKey(dhPub, st.nr);
      if (st.seen.has(k)) throw new Error('Replay rejected');
      st.skipped.set(k, ck.mk);
      st.nr += 1;
    }
  }
  async function sessionDecrypt(session, payload) {
    var candidate = cloneState(session._state);
    var raw = await decryptOn(candidate, session, payload);
    // Parse + cross-check the v1 inner JSON BEFORE committing ratchet
    // state, so a semantic mismatch does not advance the ratchet
    // (mirroring v1's decrypt-on-copy, commit-only-on-success rule).
    var text = parseInnerText(raw, payload);
    commitState(session._state, candidate);
    if (candidate._receiverInit) {
      session._pendingSk = null;
      // First-message GCM + inner-JSON success: the OPK named in the
      // initial message is now consumed. The caller drops it from
      // the identity and refills (see dropOpk / refillOpks); the
      // core never re-serves it.
      if (session._consumedOpkPub) session._opkConsumed = session._consumedOpkPub;
    }
    return text;
  }
  async function createInitiatorSession(localUser, remoteUser, me, peerBundle) {
    var x = await x3dhInitiatorSecret(me, peerBundle);
    var dhs = nacl.box.keyPair();
    var dhOut = x25519(dhs.secretKey, peerBundle.spk_pub);
    var r = await kdfRk(x.sk, dhOut);
    var session = {
      localUser: localUser, remoteUser: remoteUser, _me: me,
      _state: {
        rk: r.rk, dhs_priv: dhs.secretKey, dhs_pub: dhs.publicKey,
        dhr_pub: null, cks: r.ck, ckr: null, ns: 0, nr: 0, pns: 0,
        skipped: new Map(), seen: new Set(), retired: new Set()
      },
      _pendingInitial: x.initial, _initialSent: false, _pendingSk: null
    };
    return session;
  }
  function createReceiverSession(localUser, remoteUser, me, peerIkSignPub, peerIkDhPub, initial) {
    // Verify the initial message now; the SK is stored pending and
    // the receiving chain is built on the first ratchet message's
    // dh_pub (see decryptOn). This matches v1's init_receiver
    // ordering: SK first, receiving chain from the first header.
    return (async function () {
      var sk = await x3dhResponderSecret(me, initial, peerIkSignPub, peerIkDhPub);
      return {
        localUser: localUser, remoteUser: remoteUser, _me: me,
        _state: {
          rk: sk, dhs_priv: null, dhs_pub: null,
          dhr_pub: null, cks: null, ckr: null, ns: 0, nr: 0, pns: 0,
          skipped: new Map(), seen: new Set(), retired: new Set()
        },
        _pendingInitial: null, _initialSent: false, _pendingSk: sk,
        _consumedOpkPub: initial.opk_pub ? unb64(initial.opk_pub) : null, _opkConsumed: null
      };
    })();
  }
  function sessionToJSON(session) {
    function b(v) { return v ? b64(v) : null; }
    var st = session._state;
    return {
      localUser: session.localUser, remoteUser: session.remoteUser,
      rk: b(st.rk), dhs_priv: b(st.dhs_priv), dhs_pub: b(st.dhs_pub),
      dhr_pub: b(st.dhr_pub), cks: b(st.cks), ckr: b(st.ckr),
      ns: st.ns, nr: st.nr, pns: st.pns,
      skipped: Array.from(st.skipped.entries()).map(function (e) { return [e[0], b(e[1])]; }),
      seen: Array.from(st.seen), retired: Array.from(st.retired),
      pendingSk: session._pendingSk ? b(session._pendingSk) : null,
      initialSent: !!session._initialSent
    };
  }
  function sessionFromJSON(obj, me) {
    function u(v) { return v ? unb64(v) : null; }
    var session = {
      localUser: obj.localUser, remoteUser: obj.remoteUser, _me: me,
      _state: {
        rk: u(obj.rk), dhs_priv: u(obj.dhs_priv), dhs_pub: u(obj.dhs_pub),
        dhr_pub: u(obj.dhr_pub), cks: u(obj.cks), ckr: u(obj.ckr),
        ns: obj.ns || 0, nr: obj.nr || 0, pns: obj.pns || 0,
        skipped: new Map((obj.skipped || []).map(function (e) { return [e[0], unb64(e[1])]; })),
        seen: new Set(obj.seen || []), retired: new Set(obj.retired || [])
      },
      _pendingInitial: null, _initialSent: !!obj.initialSent, _pendingSk: u(obj.pendingSk)
    };
    return session;
  }

  var api = {
    PQ_SUPPORTED: false,
    OPK_POOL_SIZE: OPK_POOL_SIZE, OPK_REFILL_THRESHOLD: OPK_REFILL_THRESHOLD,
    b64: b64, unb64: unb64, hex: hex, randomBytes: randomBytes,
    hmacSha256: hmacSha256, hkdf: hkdf, hkdfSk: hkdfSk, kdfRk: kdfRk, kdfCk: kdfCk,
    aesGcmEncrypt: aesGcmEncrypt, aesGcmDecrypt: aesGcmDecrypt,
    x25519: x25519, edSign: edSign, edVerify: edVerify, fingerprintOf: fingerprintOf,
    generateIdentity: generateIdentity, bundleFromIdentity: bundleFromIdentity,
    parseBundle: parseBundle, serializeIdentity: serializeIdentity, parseIdentity: parseIdentity,
    dropOpk: dropOpk, refillOpks: refillOpks, findOpk: findOpk,
    wrapInnerText: wrapInnerText, parseInnerText: parseInnerText,
    x3dhInitiatorSecret: x3dhInitiatorSecret, x3dhResponderSecret: x3dhResponderSecret,
    createInitiatorSession: createInitiatorSession, createReceiverSession: createReceiverSession,
    sessionEncrypt: sessionEncrypt, sessionDecrypt: sessionDecrypt,
    sessionToJSON: sessionToJSON, sessionFromJSON: sessionFromJSON,
    buildAad: buildAad
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ECNUcrypto = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
