'use strict';
/*
 * ECNUchat v2 — PQ plug-in module (Track B). Does NOT modify crypto.js.
 *
 * What it adds, on top of the classical core in ./crypto.js (which it
 * loads but never patches — ECNUcrypto.PQ_SUPPORTED stays false):
 *  - ML-KEM-768 via the vendored noble bundle in
 *    ./vendor/mlkem/mlkem-bundle.js (pure JS, MIT; see
 *    ./vendor/mlkem/README.md). The KEM passed all 25+25+25 NIST ACVP
 *    ML-KEM-768 vectors (keyGen / encap / decap); see
 *    ../tests/test_pq_acvp.js. No KEM code is hand-rolled here.
 *  - PQXDH, matching the Python v1 (src/x3dh.py, src/prekeys.py):
 *    classical DH material (DH1..DH3, optional DH4) + one ML-KEM-768
 *    encapsulation, SK = HKDF-SHA256(salt = 32 zero bytes,
 *    info = "pqxdh-v1", 32 bytes) over
 *    DH || kem_ss || SHA-256(pq_ek_pub). The encapsulation target is
 *    the peer's one-time PQOPK when one is published, otherwise the
 *    signed long-term PQK — never the other way round, and the two
 *    are never interchangeable (the SHA-256 binding + the initial
 *    signature both cover the exact pq_ek_pub used).
 *  - Hybrid double ratchet, matching v1 (src/double_ratchet.py):
 *    every new sending chain encapsulates fresh to the peer's
 *    long-term PQK, KDF_RK is HKDF(salt = rk, info = "pq-dr-v1",
 *    64 bytes) over dh_out || kem_ss, and the resulting pq_ct rides
 *    on EVERY message of that chain (payload field "pq_ct",
 *    1088 bytes, base64). AAD, inner JSON, skip/replay rules and
 *    the 40-message skip cap are identical to the classical core
 *    (pq_ct is NOT part of the AAD, exactly as in v1).
 *  - Wire fields, matching v1 (src/protocol.py encode_x3dh /
 *    encode_ratchet_payload): the first message's x3dh object gains
 *    "ik_pq_pub" (initiator's long-term PQK pub), "pq_ek" (the exact
 *    encapsulation public key used — note the field name is pq_ek,
 *    not pq_ek_pub) and "pq_ct" (the handshake encapsulation), and
 *    its Ed25519 signature covers
 *    ik_dh_pub || ek_pub || (opk_pub or "") || ik_pq_pub ||
 *    pq_ek || pq_ct. Classical peers see none of this: a classical
 *    session built by crypto.js produces byte-identical payloads to
 *    before, with no pq_* fields, and this module never adds pq
 *    fields to a classical session.
 *
 * Mode flag / anti-downgrade (the whole point of the flag):
 *  - A session is hybrid iff BOTH sides hold a long-term PQK
 *    (decideMode): own PQ + peer PQ pub present. This mirrors v1's
 *    start_session rule, including its asymmetry: a peer PQOPK
 *    alone, without a peer PQK, does NOT trigger a hybrid session.
 *  - A PQ receiver REFUSES a classical initial message
 *    ("downgrade refused"), exactly as v1's _decrypt_envelope does.
 *    A receiver without a PQ key REFUSES a hybrid initial message
 *    (it has no key to decapsulate with). There is no silent
 *    fallback in either direction: decideMode / the responder
 *    throw, they do not quietly pick classical.
 *  - Once a session is hybrid, EVERY ratchet message must carry
 *    pq_ct. A hybrid session that receives a message without
 *    pq_ct throws a downgrade error, and a hybrid message arriving
 *    on a session with no recorded peer PQK throws. This is
 *    stricter than v1 on the very first message (v1's init_receiver
 *    path would classically derive a receiving chain if the first
 *    ratchet payload omitted pq_ct despite a hybrid initial); a
 *    real v1 hybrid sender always attaches pq_ct (init_sender sets
 *    dhs_pq_ct whenever remote_pq_pk is known), so the strictness
 *    rejects only malformed or stripped messages, never a genuine
 *    v1 hybrid message.
 *  - PQ private keys are stored as 64-byte seeds, exactly as v1
 *    does (src/prekeys.py: "priv is 64-byte seed"). The noble
 *    expanded secret key (2400 bytes) is re-derived from the seed
 *    on demand and never stored by this module; a seed given to
 *    noble's keygen produces the same public key as Python
 *    cryptography's MLKEM768PrivateKey.from_seed_bytes(seed)
 *    (verified byte-for-byte; see tests/test_pq_crosscheck.py).
 *
 * PQ identity fields, matching v1 (src/prekeys.py, src/client.py):
 *  - Long-term PQK: Ed25519 (IK_sign) over pq_pub || username.
 *  - One-time PQOPK (pool 8, refill below 2): Ed25519 (IK_sign)
 *    over "pq-opk-v1\x00" || pq_opk_pub || username — a different
 *    signed message from the PQK one, so a PQOPK can never be
 *    substituted into the long-term slot.
 *  - Bundle wire names (for a future relay/app wiring, NOT wired
 *    here): pq_pub, pq_sig, pq_opks: [{pub, sig}] for a bundle,
 *    and bundle fetch returns one pq_opk + pq_opk_sig. This module
 *    only builds/parses those objects; it does not touch the relay
 *    or app.js, so end-to-end interop with a real v1 client is
 *    still NOT claimed (see ../tests/TRACK_B_STATUS.md).
 *
 * Key storage warning: same as crypto.js — this module only returns
 * key bytes (seeds). The PWA stores them in localStorage, which is
 * NOT production-grade secure storage.
 */
(function (root) {
  var C = null;
  if (typeof require === 'function') {
    try { C = require('./crypto.js'); } catch (e) { C = null; }
  }
  if (!C) C = root.ECNUcrypto || (typeof self !== 'undefined' ? self.ECNUcrypto : null);
  if (!C) throw new Error('ECNUcrypto (crypto.js) is not loaded; include crypto.js before crypto-pq.js');

  var MLKEM = null;
  if (typeof require === 'function') {
    try { MLKEM = require('./vendor/mlkem/mlkem-bundle.js'); } catch (e) { MLKEM = null; }
  }
  if (!MLKEM) MLKEM = root.ECNUMLKEM768 || (typeof self !== 'undefined' ? self.ECNUMLKEM768 : null);
  if (!MLKEM || !MLKEM.ml_kem768) throw new Error('ML-KEM bundle (ECNUMLKEM768) is not loaded; include vendor/mlkem/mlkem-bundle.js before crypto-pq.js');

  var nacl = null;
  if (typeof require === 'function') {
    try { nacl = require('./vendor/nacl-fast.min.js'); } catch (e) { nacl = null; }
  }
  if (!nacl) nacl = root.nacl || (typeof self !== 'undefined' ? self.nacl : null);
  if (!nacl) throw new Error('tweetnacl (nacl) is not loaded; include vendor/nacl-fast.min.js before crypto-pq.js');

  var subtle = null;
  try { subtle = (root.crypto && root.crypto.subtle) || (typeof crypto !== 'undefined' && crypto.subtle) || null; } catch (e) { subtle = null; }
  function enc() { return new TextEncoder(); }
  function concat() {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
    return out;
  }
  function eq(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  async function sha256(bytes) {
    if (!subtle) throw new Error('SubtleCrypto unavailable in this context');
    var d = await subtle.digest('SHA-256', bytes);
    return new Uint8Array(d);
  }
  function b64(bytes) { return C.b64(bytes); }
  function unb64(s) { return C.unb64(s); }

  var PQ_PUB_LEN = 1184;  // ML-KEM-768 encapsulation key
  var PQ_CT_LEN = 1088;   // ML-KEM-768 ciphertext
  var PQ_SS_LEN = 32;     // ML-KEM-768 shared secret
  var PQ_DK_LEN = 2400;   // noble expanded secret key (dkPKE||ek||H(ek)||z)
  var PQ_SEED_LEN = 64;   // v1 PQ private-key storage format (d||z)
  var PQ_OPK_POOL_SIZE = 8;        // v1 PQ_OPK_POOL_SIZE
  var PQ_OPK_REFILL_THRESHOLD = 2; // v1 PQ_OPK_REFILL_THRESHOLD
  var PQ_OPK_PREFIX = new Uint8Array([0x70, 0x71, 0x2d, 0x6f, 0x70, 0x6b, 0x2d, 0x76, 0x31, 0x00]); // "pq-opk-v1\x00"
  var MAX_SKIP = 40;

  function kem() { return MLKEM.ml_kem768; }
  function needLen(bytes, len, name) {
    if (!bytes || bytes.length !== len) throw new Error('PQ field wrong length: ' + name);
    return bytes;
  }

  // ---- KEM glue (seed-based, v1-compatible) ----
  function pqKeygen(seed) {
    var s = seed || C.randomBytes(PQ_SEED_LEN);
    needLen(s, PQ_SEED_LEN, 'seed');
    var k = kem().keygen(s);
    needLen(k.publicKey, PQ_PUB_LEN, 'publicKey');
    needLen(k.secretKey, PQ_DK_LEN, 'secretKey');
    return { seed: new Uint8Array(s), pub: new Uint8Array(k.publicKey), dk: new Uint8Array(k.secretKey) };
  }
  function pqPublicKeyFromSeed(seed) {
    return pqKeygen(seed).pub;
  }
  function pqEncapsulate(pub, msg) {
    needLen(pub, PQ_PUB_LEN, 'publicKey');
    var r = msg === undefined || msg === null ? kem().encapsulate(pub) : kem().encapsulate(pub, msg);
    needLen(r.cipherText, PQ_CT_LEN, 'cipherText');
    needLen(r.sharedSecret, PQ_SS_LEN, 'sharedSecret');
    return { ss: new Uint8Array(r.sharedSecret), ct: new Uint8Array(r.cipherText) };
  }
  function pqDecapsulateDk(dk, ct) {
    needLen(dk, PQ_DK_LEN, 'secretKey');
    needLen(ct, PQ_CT_LEN, 'cipherText');
    var ss = kem().decapsulate(ct, dk);
    needLen(ss, PQ_SS_LEN, 'sharedSecret');
    return new Uint8Array(ss);
  }
  function pqDecapsulateSeed(seed, ct) {
    needLen(seed, PQ_SEED_LEN, 'seed');
    return pqDecapsulateDk(pqKeygen(seed).dk, ct);
  }

  // ---- PQ identity: signatures, bundle fields, OPK pool ----
  function signPq(ikSignSec64, pqPub, username) {
    return C.edSign(ikSignSec64, concat(needLen(pqPub, PQ_PUB_LEN, 'pq_pub'), enc().encode(username)));
  }
  function verifyPq(ikSignPub, pqPub, username, sig) {
    return C.edVerify(concat(needLen(pqPub, PQ_PUB_LEN, 'pq_pub'), enc().encode(username)), sig, ikSignPub);
  }
  function signPqOpk(ikSignSec64, pqOpkPub, username) {
    return C.edSign(ikSignSec64, concat(PQ_OPK_PREFIX, needLen(pqOpkPub, PQ_PUB_LEN, 'pq_opk_pub'), enc().encode(username)));
  }
  function verifyPqOpk(ikSignPub, pqOpkPub, username, sig) {
    return C.edVerify(concat(PQ_OPK_PREFIX, needLen(pqOpkPub, PQ_PUB_LEN, 'pq_opk_pub'), enc().encode(username)), sig, ikSignPub);
  }
  // Attach PQ keys to a classical identity object from
  // ECNUcrypto.generateIdentity(username). Returns a standalone PQ
  // object; the classical identity itself is never mutated here —
  // the caller stores both halves (see serializePq / parsePq).
  function generatePqForIdentity(id) {
    if (!id || !id.username || !id.ikSign) throw new Error('generatePqForIdentity requires a classical identity with username + ikSign');
    var pqk = pqKeygen();
    var pq = {
      pqSeed: pqk.seed, pqPub: pqk.pub,
      pqSig: signPq(id.ikSign.secretKey, pqk.pub, id.username),
      pqOpks: []
    };
    refillPqOpks(pq, id.ikSign.secretKey, id.username);
    return pq;
  }
  function pqBundleFrom(pq) {
    if (!pq) return { pq_pub: null, pq_sig: null, pq_opks: [] };
    return {
      pq_pub: b64(pq.pqPub), pq_sig: b64(pq.pqSig),
      pq_opks: (pq.pqOpks || []).map(function (o) { return { pub: b64(o.pub), sig: b64(o.sig) }; })
    };
  }
  // Parse + verify a peer's PQ bundle fields. Returns null when the
  // peer publishes no PQ fields at all (classical peer). Throws on
  // any half-present pair or bad signature — never a silent accept.
  function parsePqBundle(obj, username, ikSignPub) {
    if (!obj) return null;
    var hasPub = obj.pq_pub != null, hasSig = obj.pq_sig != null;
    var hasOpks = Array.isArray(obj.pq_opks) && obj.pq_opks.length > 0;
    var hasSingleOpk = obj.pq_opk != null;
    if (!hasPub && !hasSig && !hasOpks && !hasSingleOpk) return null;
    if (hasPub !== hasSig) throw new Error('Peer PQK public key and signature must be provided together');
    if (hasSingleOpk !== (obj.pq_opk_sig != null)) throw new Error('Peer PQOPK public key and signature must be provided together');
    if (typeof username !== 'string' || !username) throw new Error('parsePqBundle requires the peer username');
    var out = { pqPub: null, pqSig: null, pqOpks: [] };
    if (hasPub) {
      out.pqPub = needLen(unb64(obj.pq_pub), PQ_PUB_LEN, 'pq_pub');
      out.pqSig = needLen(unb64(obj.pq_sig), 64, 'pq_sig');
      if (!verifyPq(ikSignPub, out.pqPub, username, out.pqSig)) throw new Error('Peer PQK signature verification failed (pq_pub || username)');
    }
    var rawOpks = [];
    if (hasOpks) rawOpks = obj.pq_opks;
    else if (hasSingleOpk) rawOpks = [{ pub: obj.pq_opk, sig: obj.pq_opk_sig }];
    rawOpks.forEach(function (o) {
      var pub = needLen(unb64(o.pub), PQ_PUB_LEN, 'pq_opk.pub');
      var sig = needLen(unb64(o.sig), 64, 'pq_opk.sig');
      if (!verifyPqOpk(ikSignPub, pub, username, sig)) throw new Error('Peer PQOPK signature verification failed (pq-opk-v1 prefix)');
      out.pqOpks.push({ pub: pub, sig: sig });
    });
    return out;
  }
  function serializePq(pq) {
    return {
      pq_seed: b64(pq.pqSeed), pq_pub: b64(pq.pqPub), pq_sig: b64(pq.pqSig),
      pq_opks_seed: (pq.pqOpks || []).map(function (o) { return b64(o.seed); }),
      pq_opks_pub: (pq.pqOpks || []).map(function (o) { return b64(o.pub); }),
      pq_opks_sig: (pq.pqOpks || []).map(function (o) { return b64(o.sig); })
    };
  }
  function parsePq(obj) {
    var opks = [];
    if (Array.isArray(obj.pq_opks_seed)) {
      opks = obj.pq_opks_seed.map(function (s, i) {
        return { seed: unb64(s), pub: unb64(obj.pq_opks_pub[i]), sig: unb64(obj.pq_opks_sig[i]) };
      });
    }
    return { pqSeed: unb64(obj.pq_seed), pqPub: unb64(obj.pq_pub), pqSig: unb64(obj.pq_sig), pqOpks: opks };
  }
  function findPqOpk(pq, pub) {
    if (!pq || !pub) return null;
    for (var i = 0; i < (pq.pqOpks || []).length; i++) {
      if (eq(pq.pqOpks[i].pub, pub)) return pq.pqOpks[i];
    }
    return null;
  }
  function dropPqOpk(pq, pub) {
    if (!pq || !pub) return;
    pq.pqOpks = (pq.pqOpks || []).filter(function (o) { return !eq(o.pub, pub); });
  }
  function refillPqOpks(pq, ikSignSec64, username) {
    if (!pq.pqOpks) pq.pqOpks = [];
    while (pq.pqOpks.length < PQ_OPK_POOL_SIZE) {
      var k = pqKeygen();
      pq.pqOpks.push({ seed: k.seed, pub: k.pub, sig: signPqOpk(ikSignSec64, k.pub, username) });
    }
    return pq.pqOpks.length;
  }

  // ---- Mode decision (never silent) ----
  function decideMode(ownPq, peerPq) {
    // v1 start_session: hybrid iff peer PQK present AND own PQK present.
    if (ownPq && ownPq.pqPub && peerPq && peerPq.pqPub) return 'pqxdh';
    return 'classical';
  }
  function isHybridInitial(initial) {
    return !!(initial && initial.pq_ct && initial.ik_pq_pub && initial.pq_ek);
  }
  function assertReceiverMode(localHasPq, initial) {
    var hybrid = isHybridInitial(initial);
    if (localHasPq && !hybrid) throw new Error('Missing PQ handshake, downgrade refused (local PQ key present, classical initial received)');
    if (!localHasPq && hybrid) throw new Error('Hybrid initial received but local identity has no PQ key; cannot decapsulate');
    return hybrid ? 'pqxdh' : 'classical';
  }

  // ---- PQXDH ----
  function dhMaterialInitiator(me, ekSec, peerBundle) {
    var dh1 = C.x25519(me.ikDh.secretKey, peerBundle.spk_pub);
    var dh2 = C.x25519(ekSec, peerBundle.ik_dh_pub);
    var dh3 = C.x25519(ekSec, peerBundle.spk_pub);
    var material = dh1;
    if (peerBundle.opk_pub) material = concat(material, dh2, dh3, C.x25519(ekSec, peerBundle.opk_pub));
    else material = concat(material, dh2, dh3);
    return material;
  }
  function dhMaterialResponder(me, ekPub, ikDhPub, opk) {
    var dh1 = C.x25519(me.spk.secretKey, ikDhPub);
    var dh2 = C.x25519(me.ikDh.secretKey, ekPub);
    var dh3 = C.x25519(me.spk.secretKey, ekPub);
    var material = dh1;
    if (opk) material = concat(material, dh2, dh3, C.x25519(opk.secretKey, ekPub));
    else material = concat(material, dh2, dh3);
    return material;
  }
  async function pqxdhSk(dhMaterial, kemSs, pqEkPub) {
    if (!dhMaterial.length || dhMaterial.length % 32 !== 0) throw new Error('DH material length must be a multiple of 32');
    var binding = await sha256(pqEkPub);
    return C.hkdf(concat(dhMaterial, kemSs, binding), new Uint8Array(32), enc().encode('pqxdh-v1'), 32);
  }
  // me: classical identity; peerBundle: parsed classical bundle
  // (ECNUcrypto.parseBundle output); peerPq: parsed peer PQ bundle
  // (parsePqBundle output, non-null); myPqPub: own long-term PQK pub.
  async function pqxdhInitiatorSecret(me, peerBundle, peerPq, myPqPub) {
    if (!peerPq || !peerPq.pqPub) throw new Error('PQXDH requires the peer long-term PQK; use the classical path when the peer has none');
    needLen(myPqPub, PQ_PUB_LEN, 'ik_pq_pub');
    var pqEkPub, handshakePq;
    if (peerPq.pqOpks && peerPq.pqOpks.length) { pqEkPub = peerPq.pqOpks[0].pub; handshakePq = 'pqopk'; }
    else { pqEkPub = peerPq.pqPub; handshakePq = 'pqk'; }
    var ek = nacl.box.keyPair();
    var material = dhMaterialInitiator(me, ek.secretKey, peerBundle);
    var encap = pqEncapsulate(pqEkPub);
    var sk = await pqxdhSk(material, encap.ss, pqEkPub);
    var signed = concat(me.ikDh.publicKey, ek.publicKey, peerBundle.opk_pub || new Uint8Array(0), myPqPub, pqEkPub, encap.ct);
    var signature = C.edSign(me.ikSign.secretKey, signed);
    var initial = {
      ik_dh_pub: b64(me.ikDh.publicKey),
      ek_pub: b64(ek.publicKey),
      opk_pub: peerBundle.opk_pub ? b64(peerBundle.opk_pub) : null,
      signature: b64(signature),
      ik_pq_pub: b64(myPqPub),
      pq_ek: b64(pqEkPub),
      pq_ct: b64(encap.ct)
    };
    return { sk: sk, ek: ek, initial: initial, pqEkPub: pqEkPub, pqCt: encap.ct, handshakePq: handshakePq, mode: 'pqxdh' };
  }
  // initial: wire object (base64 strings, as produced above / by v1
  // encode_x3dh). mePq: own parsed PQ object (parsePq output).
  async function pqxdhResponderSecret(me, mePq, initial, peerIkSignPub, peerIkDhPub) {
    if (!isHybridInitial(initial)) throw new Error('Missing PQ handshake, downgrade refused (classical initial on a PQ responder)');
    if (!mePq || !mePq.pqPub || !mePq.pqSeed) throw new Error('Hybrid responder requires the local PQK seed');
    var ekPub = unb64(initial.ek_pub);
    var ikDhPub = unb64(initial.ik_dh_pub);
    var opkPub = initial.opk_pub ? unb64(initial.opk_pub) : null;
    var ikPqPub = needLen(unb64(initial.ik_pq_pub), PQ_PUB_LEN, 'ik_pq_pub');
    var pqEkPub = needLen(unb64(initial.pq_ek), PQ_PUB_LEN, 'pq_ek');
    var pqCt = needLen(unb64(initial.pq_ct), PQ_CT_LEN, 'pq_ct');
    var signature = unb64(initial.signature);
    if (!eq(ikDhPub, peerIkDhPub)) throw new Error('Initial IK_dh does not match the pinned peer identity key');
    var signed = concat(ikDhPub, ekPub, opkPub || new Uint8Array(0), ikPqPub, pqEkPub, pqCt);
    if (!C.edVerify(signed, signature, peerIkSignPub)) throw new Error('Hybrid initial message signature verification failed');
    var opk = opkPub ? C.findOpk(me, opkPub) : null;
    if (opkPub && !opk) throw new Error('Initial message names a classical OPK this device does not hold');
    var pqSeed, consumedPqOpkPub = null, handshakePq;
    var match = findPqOpk(mePq, pqEkPub);
    if (match) { pqSeed = match.seed; consumedPqOpkPub = match.pub; handshakePq = 'pqopk'; }
    else if (eq(pqEkPub, mePq.pqPub)) { pqSeed = mePq.pqSeed; handshakePq = 'pqk'; }
    else throw new Error('Local identity holds no PQ key matching the handshake encapsulation key');
    var material = dhMaterialResponder(me, ekPub, ikDhPub, opk);
    var kemSs = pqDecapsulateSeed(pqSeed, pqCt);
    var sk = await pqxdhSk(material, kemSs, pqEkPub);
    return { sk: sk, consumedPqOpkPub: consumedPqOpkPub, handshakePq: handshakePq, mode: 'pqxdh', ikPqPub: ikPqPub };
  }

  // ---- Hybrid ratchet KDF + sessions (state shape mirrors crypto.js) ----
  async function kdfRkPq(rk, dhOut, kemSs) {
    var out = await C.hkdf(concat(dhOut, kemSs), rk, enc().encode('pq-dr-v1'), 64);
    return { rk: out.slice(0, 32), ck: out.slice(32, 64) };
  }
  function cloneHybridState(st) {
    function copyBytes(v) { return v ? new Uint8Array(v) : null; }
    return {
      rk: copyBytes(st.rk), dhs_priv: copyBytes(st.dhs_priv), dhs_pub: copyBytes(st.dhs_pub),
      dhs_pq_ct: copyBytes(st.dhs_pq_ct),
      dhr_pub: copyBytes(st.dhr_pub), cks: copyBytes(st.cks), ckr: copyBytes(st.ckr),
      ns: st.ns, nr: st.nr, pns: st.pns,
      skipped: new Map(Array.from(st.skipped.entries()).map(function (e) { return [e[0], new Uint8Array(e[1])]; })),
      seen: new Set(st.seen), retired: new Set(st.retired), _receiverInit: !!st._receiverInit
    };
  }
  function commitHybridState(target, source) {
    var k;
    for (k in source) target[k] = source[k];
  }
  function skippedKey(dhPub, n) { return b64(dhPub) + ':' + n; }

  async function createHybridInitiatorSession(localUser, remoteUser, me, peerBundle, pqResult, remotePqPub, localPqSeed) {
    needLen(remotePqPub, PQ_PUB_LEN, 'remote_pq_pk');
    var dhs = nacl.box.keyPair();
    var dhOut = C.x25519(dhs.secretKey, peerBundle.spk_pub);
    var encap = pqEncapsulate(remotePqPub);
    var r = await kdfRkPq(pqResult.sk, dhOut, encap.ss);
    return {
      localUser: localUser, remoteUser: remoteUser, mode: 'hybrid',
      remotePqPub: remotePqPub, _me: me, _localPqSeed: localPqSeed,
      _state: {
        rk: r.rk, dhs_priv: dhs.secretKey, dhs_pub: dhs.publicKey, dhs_pq_ct: encap.ct,
        dhr_pub: null, cks: r.ck, ckr: null, ns: 0, nr: 0, pns: 0,
        skipped: new Map(), seen: new Set(), retired: new Set()
      },
      _pendingInitial: pqResult.initial, _initialSent: false, _pendingSk: null,
      _consumedOpkPub: null, _opkConsumed: null,
      _consumedPqOpkPub: null, _pqOpkConsumed: null
    };
  }
  async function createHybridReceiverSession(localUser, remoteUser, me, mePq, peerIkSignPub, peerIkDhPub, initial) {
    var res = await pqxdhResponderSecret(me, mePq, initial, peerIkSignPub, peerIkDhPub);
    return {
      localUser: localUser, remoteUser: remoteUser, mode: 'hybrid',
      remotePqPub: unb64(initial.ik_pq_pub), _me: me, _localPqSeed: mePq.pqSeed,
      _state: {
        rk: res.sk, dhs_priv: null, dhs_pub: null, dhs_pq_ct: null,
        dhr_pub: null, cks: null, ckr: null, ns: 0, nr: 0, pns: 0,
        skipped: new Map(), seen: new Set(), retired: new Set()
      },
      _pendingInitial: null, _initialSent: false, _pendingSk: res.sk,
      _consumedOpkPub: initial.opk_pub ? unb64(initial.opk_pub) : null, _opkConsumed: null,
      _consumedPqOpkPub: res.consumedPqOpkPub, _pqOpkConsumed: null
    };
  }
  async function hybridSessionEncrypt(session, plaintext) {
    if (session.mode !== 'hybrid') throw new Error('hybridSessionEncrypt requires a hybrid session (mode flag)');
    var st = session._state;
    if (!st.cks) {
      if (!st.dhr_pub) throw new Error('No peer ratchet public key; cannot build a sending chain');
      st.pns = st.nr;
      var kp = nacl.box.keyPair();
      st.dhs_priv = kp.secretKey; st.dhs_pub = kp.publicKey;
      var dhOut = C.x25519(st.dhs_priv, st.dhr_pub);
      var encap = pqEncapsulate(session.remotePqPub);
      var r = await kdfRkPq(st.rk, dhOut, encap.ss);
      st.rk = r.rk; st.cks = r.ck; st.dhs_pq_ct = encap.ct;
      st.ns = 0;
    }
    var ck = await C.kdfCk(st.cks);
    st.cks = ck.newCk;
    var n = st.ns, pn = st.pns;
    st.ns = n + 1;
    var nonce = C.randomBytes(12);
    var aad = C.buildAad(session.localUser, session.remoteUser, n, pn, st.dhs_pub);
    var ct = await C.aesGcmEncrypt(ck.mk, nonce, new TextEncoder().encode(C.wrapInnerText(plaintext, 'chat')), aad);
    var payload = {
      dh_pub: b64(st.dhs_pub), n: n, pn: pn, nonce: b64(nonce),
      ciphertext: b64(ct), kind: 'chat',
      pq_ct: st.dhs_pq_ct ? b64(st.dhs_pq_ct) : null
    };
    if (!payload.pq_ct) throw new Error('Hybrid sending chain has no PQ encapsulation; refusing to send a downgraded message');
    if (session._pendingInitial && !session._initialSent) {
      payload.x3dh = session._pendingInitial;
      session._initialSent = true;
    }
    return payload;
  }
  async function hybridDecryptOn(st, session, payload) {
    var dhPub = unb64(payload.dh_pub);
    var nonce = unb64(payload.nonce);
    var ct = unb64(payload.ciphertext);
    if (dhPub.length !== 32 || nonce.length !== 12) throw new Error('Ratchet header/nonce length invalid');
    if (!(payload.n >= 0 && payload.n <= 0xffffffff && payload.pn >= 0 && payload.pn <= 0xffffffff)) throw new Error('Ratchet sequence out of range');
    if (ct.length < 16) throw new Error('Ciphertext missing GCM tag');
    // Anti-downgrade on every message of a hybrid session.
    if (!payload.pq_ct) throw new Error('Missing PQ encapsulation on a hybrid session message; downgrade refused');
    var pqCt = needLen(unb64(payload.pq_ct), PQ_CT_LEN, 'pq_ct');
    if (!session.remotePqPub) throw new Error('Hybrid message received but no peer PQK is recorded for this session');
    if (!session._localPqSeed) throw new Error('Hybrid message received but local identity has no PQ seed to decapsulate with');
    var key = skippedKey(dhPub, payload.n);
    if (st.seen.has(key)) throw new Error('Replay rejected');
    async function openWith(mk) {
      var aad = C.buildAad(session.remoteUser, session.localUser, payload.n, payload.pn, dhPub);
      return new TextDecoder().decode(await C.aesGcmDecrypt(mk, nonce, ct, aad));
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
      // First message to a hybrid receiver: receiving chain from SK
      // + this header's dh_pub + this message's pq_ct (decapsulated
      // with the local PQK seed). _pendingSk clears only on success.
      var dhOut0 = C.x25519(session._me.spk.secretKey, dhPub);
      var ss0 = pqDecapsulateSeed(session._localPqSeed, pqCt);
      var r0 = await kdfRkPq(session._pendingSk, dhOut0, ss0);
      st.rk = r0.rk; st.ckr = r0.ck; st.dhr_pub = dhPub;
      st._receiverInit = true;
    } else if (st.dhr_pub === null || !eq(dhPub, st.dhr_pub)) {
      if (st.ckr !== null && st.dhr_pub !== null) {
        await hybridSkipKeys(st, payload.pn, st.dhr_pub);
      }
      if (st.dhs_priv === null) throw new Error('No local sending ratchet key; cannot DH-ratchet');
      if (st.dhr_pub !== null) st.retired.add(b64(st.dhr_pub));
      st.dhr_pub = dhPub;
      var dhRecv = C.x25519(st.dhs_priv, dhPub);
      var ssRecv = pqDecapsulateSeed(session._localPqSeed, pqCt);
      var rr = await kdfRkPq(st.rk, dhRecv, ssRecv);
      st.rk = rr.rk; st.ckr = rr.ck;
      st.nr = 0; st.pns = st.ns;
      var kp2 = nacl.box.keyPair();
      st.dhs_priv = kp2.secretKey; st.dhs_pub = kp2.publicKey;
      var dhSend = C.x25519(st.dhs_priv, dhPub);
      var encapSend = pqEncapsulate(session.remotePqPub);
      var rs = await kdfRkPq(st.rk, dhSend, encapSend.ss);
      st.rk = rs.rk; st.cks = rs.ck; st.dhs_pq_ct = encapSend.ct;
      st.ns = 0;
    }
    if (payload.n < st.nr) throw new Error('Replay rejected');
    await hybridSkipKeys(st, payload.n, st.dhr_pub);
    if (st.ckr === null) throw new Error('Receiving chain is empty');
    var ck2 = await C.kdfCk(st.ckr);
    st.ckr = ck2.newCk;
    st.nr = payload.n + 1;
    var pt = await openWith(ck2.mk);
    st.seen.add(key);
    return pt;
  }
  async function hybridSkipKeys(st, until, dhPub) {
    if (st.ckr === null || until < st.nr) return;
    var needed = until - st.nr;
    if (needed <= 0) return;
    if (st.skipped.size + needed > MAX_SKIP) throw new Error('Skip limit exceeded (40)');
    while (st.nr < until) {
      var ck = await C.kdfCk(st.ckr);
      st.ckr = ck.newCk;
      var k = skippedKey(dhPub, st.nr);
      if (st.seen.has(k)) throw new Error('Replay rejected');
      st.skipped.set(k, ck.mk);
      st.nr += 1;
    }
  }
  async function hybridSessionDecrypt(session, payload) {
    if (session.mode !== 'hybrid') throw new Error('hybridSessionDecrypt requires a hybrid session (mode flag)');
    var candidate = cloneHybridState(session._state);
    var raw = await hybridDecryptOn(candidate, session, payload);
    var text = C.parseInnerText(raw, payload);
    commitHybridState(session._state, candidate);
    if (candidate._receiverInit) {
      session._pendingSk = null;
      if (session._consumedOpkPub) session._opkConsumed = session._consumedOpkPub;
      if (session._consumedPqOpkPub) session._pqOpkConsumed = session._consumedPqOpkPub;
    }
    return text;
  }
  function hybridSessionToJSON(session) {
    function b(v) { return v ? b64(v) : null; }
    var st = session._state;
    return {
      localUser: session.localUser, remoteUser: session.remoteUser, mode: 'hybrid',
      remotePqPub: b(session.remotePqPub),
      rk: b(st.rk), dhs_priv: b(st.dhs_priv), dhs_pub: b(st.dhs_pub), dhs_pq_ct: b(st.dhs_pq_ct),
      dhr_pub: b(st.dhr_pub), cks: b(st.cks), ckr: b(st.ckr),
      ns: st.ns, nr: st.nr, pns: st.pns,
      skipped: Array.from(st.skipped.entries()).map(function (e) { return [e[0], b(e[1])]; }),
      seen: Array.from(st.seen), retired: Array.from(st.retired),
      pendingSk: session._pendingSk ? b(session._pendingSk) : null,
      initialSent: !!session._initialSent
    };
  }
  function hybridSessionFromJSON(obj, me, localPqSeed) {
    if (obj.mode !== 'hybrid') throw new Error('hybridSessionFromJSON requires a hybrid session record');
    function u(v) { return v ? unb64(v) : null; }
    return {
      localUser: obj.localUser, remoteUser: obj.remoteUser, mode: 'hybrid',
      remotePqPub: u(obj.remotePqPub), _me: me, _localPqSeed: localPqSeed || null,
      _state: {
        rk: u(obj.rk), dhs_priv: u(obj.dhs_priv), dhs_pub: u(obj.dhs_pub), dhs_pq_ct: u(obj.dhs_pq_ct),
        dhr_pub: u(obj.dhr_pub), cks: u(obj.cks), ckr: u(obj.ckr),
        ns: obj.ns || 0, nr: obj.nr || 0, pns: obj.pns || 0,
        skipped: new Map((obj.skipped || []).map(function (e) { return [e[0], unb64(e[1])]; })),
        seen: new Set(obj.seen || []), retired: new Set(obj.retired || [])
      },
      _pendingInitial: null, _initialSent: !!obj.initialSent, _pendingSk: u(obj.pendingSk),
      _consumedOpkPub: null, _opkConsumed: null,
      _consumedPqOpkPub: null, _pqOpkConsumed: null
    };
  }

  var api = {
    PQ_SUPPORTED: true, // plug-in flag ONLY; ECNUcrypto.PQ_SUPPORTED stays false
    PQ_PUB_LEN: PQ_PUB_LEN, PQ_CT_LEN: PQ_CT_LEN, PQ_SS_LEN: PQ_SS_LEN,
    PQ_SEED_LEN: PQ_SEED_LEN, PQ_DK_LEN: PQ_DK_LEN,
    PQ_OPK_POOL_SIZE: PQ_OPK_POOL_SIZE, PQ_OPK_REFILL_THRESHOLD: PQ_OPK_REFILL_THRESHOLD,
    pqKeygen: pqKeygen, pqPublicKeyFromSeed: pqPublicKeyFromSeed,
    pqEncapsulate: pqEncapsulate, pqDecapsulateSeed: pqDecapsulateSeed, pqDecapsulateDk: pqDecapsulateDk,
    signPq: signPq, verifyPq: verifyPq, signPqOpk: signPqOpk, verifyPqOpk: verifyPqOpk,
    generatePqForIdentity: generatePqForIdentity, pqBundleFrom: pqBundleFrom, parsePqBundle: parsePqBundle,
    serializePq: serializePq, parsePq: parsePq,
    findPqOpk: findPqOpk, dropPqOpk: dropPqOpk, refillPqOpks: refillPqOpks,
    decideMode: decideMode, isHybridInitial: isHybridInitial, assertReceiverMode: assertReceiverMode,
    kdfRkPq: kdfRkPq, pqxdhInitiatorSecret: pqxdhInitiatorSecret, pqxdhResponderSecret: pqxdhResponderSecret,
    createHybridInitiatorSession: createHybridInitiatorSession,
    createHybridReceiverSession: createHybridReceiverSession,
    hybridSessionEncrypt: hybridSessionEncrypt, hybridSessionDecrypt: hybridSessionDecrypt,
    hybridSessionToJSON: hybridSessionToJSON, hybridSessionFromJSON: hybridSessionFromJSON
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ECNUcryptoPQ = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
