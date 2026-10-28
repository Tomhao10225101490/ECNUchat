'use strict';
/*
 * ECNUchat v2 PWA — real classical crypto in relay mode, demo only in demo mode.
 *
 * RELAY MODE (real crypto; hybrid when both sides hold PQ keys):
 *  - Identity, X3DH and double ratchet live in crypto.js (tweetnacl +
 *    WebCrypto, matching the original Python v1's x3dh-v1 / dr-v1
 *    labels, HMAC 0x01/0x02 chain step, and AAD construction).
 *  - Post-quantum hybrid lives in crypto-pq.js (ML-KEM-768 via the
 *    vendored noble bundle, PQXDH pqxdh-v1, hybrid ratchet
 *    pq-dr-v1). A session is hybrid iff BOTH sides hold a long-term
 *    PQK (decideMode, v1's rule): a PQ peer is NEVER silently
 *    downgraded to classical, and a no-PQ peer is NEVER upgraded to
 *    hybrid — a PQ receiver refuses a classical initial and a
 *    no-PQ receiver refuses a hybrid initial. If crypto-pq.js is
 *    absent, this app degrades to classical-only (it does not fake
 *    hybrid); old stored profiles gain a PQ identity only when
 *    re-registered (same username reuses device + classical keys
 *    and publishes the new PQ bundle), so a locally generated PQ
 *    key is never ahead of what the relay advertises.
 *  - Relay API is EXACTLY the real relay in ../relay/README.md:
 *    POST /v1/devices/register {username, device, identity_key,
 *      signed_prekey, one_time_prekeys (pool of 20), public_keys
 *      (now also pq_pub / pq_sig / pq_opks, pool of 8)},
 *    POST /v1/bundles/fetch {username, device} — consumes exactly
 *    one classical OPK AND exactly one PQOPK, used ONLY when an
 *    initiator starts a new session; the initiator MUST encapsulate
 *    to the returned pq_opk, never to a key still in the returned
 *    public_keys pool (that pool now holds only the remainder);
 *    POST /v1/envelopes {sender, recipient, ciphertext, ...}
 *    (hybrid envelopes also carry pq_ct, passed through verbatim),
 *    GET /v1/inbox?recipient=username:device (pop-on-fetch, NO ack),
 *    GET /v1/devices?username=<username> (non-consuming listing).
 *    SPK signatures follow the v1 rule (spk_pub || username) and
 *    messages carry the v1 inner JSON; see pwa/crypto.js.
 *    Default relay URL is http://127.0.0.1:8765 (the relay default).
 *    Keys live in localStorage, which is NOT production-grade
 *    secure storage. PQ seeds are NEVER sent to the relay: only
 *    pq_pub / pq_sig / pq_opks (public keys + signatures) leave
 *    the device.
 *
 * DEMO MODE (offline only, never touches a relay):
 *  - Messages use a SHA-256 demo key derivation and are tagged
 *    DEMO-NOT-E2EE-REAL. Anyone knowing the two usernames can
 *    derive that key, so demo traffic is effectively public.
 *    Demo envelopes are NEVER sent to a relay.
 */
var params = new URLSearchParams(location.search);
var NS = params.get('profile') ? '-' + params.get('profile').replace(/[^A-Za-z0-9_-]/g, '') : '';
var STORE_KEY = 'ecnu-chat-v2' + NS;
var BC_NAME = 'ecnu-chat-v2-demo';
var USER_RE = /^[A-Za-z0-9_]{3,20}$/;
var DEMO_TAG = 'DEMO-NOT-E2EE-REAL';
var REAL_TAG = 'E2EE classical (X3DH + ratchet)';
var HYBRID_TAG = 'E2EE hybrid (PQXDH + hybrid ratchet; ML-KEM-768)';

var state = load();
var channel = null;
try { channel = new BroadcastChannel(BC_NAME); } catch (e) { channel = null; }
if (channel) {
  channel.onmessage = function (ev) {
    var env = ev.data && ev.data.envelope;
    if (!env || !env.demo || !state.profile || env.to !== state.profile.username) return;
    if (state.seen && state.seen.indexOf(envId(env)) !== -1) return;
    receiveDemoEnvelope(env);
  };
}

function load() {
  try {
    var raw = localStorage.getItem(STORE_KEY);
    if (raw) {
      var s = JSON.parse(raw);
      s.friends = s.friends || []; s.messages = s.messages || [];
      s.seen = s.seen || []; s.sessions = s.sessions || {};
      return s;
    }
  } catch (e) { /* corrupt store: start fresh, loudly */ }
  return { profile: null, friends: [], messages: [], seen: [], sessions: {}, relayUrl: 'http://127.0.0.1:8765', mode: 'relay' };
}
function save() { try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (e) { setStatus('Store write failed: ' + e.message); } }
function $(id) { return document.getElementById(id); }
function setStatus(t) { $('status').textContent = 'Status: ' + t; }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function b64(bytes) { var s = ''; bytes.forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s); }
function unb64(s) { var bin = atob(s); var out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
function envId(env) { return env.from + '|' + (env.to_device || '') + '|' + env.ts + '|' + String(env.ciphertext).slice(0, 40); }
function randomDeviceId() { var a = new Uint8Array(4); crypto.getRandomValues(a); return 'dev-' + Array.from(a).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
function meAddress() { return state.profile.username + ':' + state.profile.device; }
function myIdentity() { return ECNUcrypto.parseIdentity(state.profile.identity); }
// PQ plug-in, if loaded (index.html loads vendor/mlkem/mlkem-bundle.js,
// crypto.js, then crypto-pq.js, in that order). typeof-guard, not a
// bare reference: without the plug-in this app is classical-only and
// must not throw on every send/fetch. It never fakes hybrid.
function pqModule() { return (typeof ECNUcryptoPQ !== 'undefined') ? ECNUcryptoPQ : null; }
function myPq() {
  var PQ = pqModule();
  if (!PQ || !state.profile || !state.profile.pq) return null;
  try { return PQ.parsePq(state.profile.pq); } catch (e) { return null; }
}
function myPqSeed() { var p = myPq(); return p ? p.pqSeed : null; }
// Generate + store a PQ identity alongside the classical one, but
// ONLY from a path that immediately re-registers the merged bundle
// (register handler, registerDeviceWithRelay). Generating here and
// not publishing would make this device refuse classical initials
// from peers that still see a classical-only bundle for it.
function ensurePq() {
  var PQ = pqModule();
  if (!PQ || !state.profile) return null;
  var existing = myPq();
  if (existing && existing.pqPub) return existing;
  var fresh = PQ.generatePqForIdentity(myIdentity());
  state.profile.pq = PQ.serializePq(fresh);
  save();
  return fresh;
}
function sessionKey(peerAddress) { return peerAddress; }
function loadSession(peerAddress) {
  var j = state.sessions[sessionKey(peerAddress)];
  if (!j) return null;
  if (j.mode === 'hybrid') {
    var PQ = pqModule();
    if (!PQ) throw new Error('Stored session for ' + peerAddress + ' is hybrid, but crypto-pq.js is not loaded; cannot decrypt.');
    var seed = myPqSeed();
    if (!seed) throw new Error('Stored session for ' + peerAddress + ' is hybrid, but this profile has no PQ identity; cannot decrypt.');
    return PQ.hybridSessionFromJSON(j, myIdentity(), seed);
  }
  return ECNUcrypto.sessionFromJSON(j, myIdentity());
}
function storeSession(peerAddress, session) {
  // Hybrid sessions persist through the hybrid serialiser (which
  // records mode + remotePqPub + dhs_pq_ct); a reload must resume
  // the same hybrid session, not silently restart it as classical.
  state.sessions[sessionKey(peerAddress)] = (session.mode === 'hybrid')
    ? pqModule().hybridSessionToJSON(session)
    : ECNUcrypto.sessionToJSON(session);
  save();
}
async function encryptFor(session, text) {
  if (session.mode === 'hybrid') return pqModule().hybridSessionEncrypt(session, text);
  return ECNUcrypto.sessionEncrypt(session, text);
}
async function decryptFor(session, payload) {
  if (session.mode === 'hybrid') return pqModule().hybridSessionDecrypt(session, payload);
  return ECNUcrypto.sessionDecrypt(session, payload);
}

// ---- Demo-only crypto (never sent to a relay) ----
async function demoKey(a, b) {
  var pair = [a, b].sort().join(':') + ':' + DEMO_TAG;
  var digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pair));
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function demoEncrypt(fromUser, toUser, plaintext) {
  var key = await demoKey(fromUser, toUser);
  var iv = new Uint8Array(12); crypto.getRandomValues(iv);
  var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(plaintext));
  return { iv: b64(iv), ciphertext: b64(new Uint8Array(ct)) };
}
async function demoDecrypt(fromUser, toUser, env) {
  var key = await demoKey(fromUser, toUser);
  var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, key, unb64(env.ciphertext));
  return new TextDecoder().decode(pt);
}
async function receiveDemoEnvelope(env) {
  if (!state.profile || state.seen.indexOf(envId(env)) !== -1) return;
  state.seen.push(envId(env));
  var text;
  try { text = await demoDecrypt(env.from, env.to, env); }
  catch (e) { text = '[could not decrypt demo envelope: ' + e.message + ']'; }
  state.messages.push({ peer: env.from, dir: 'in', text: text, ts: env.ts, from_device: env.from_device, to_device: env.to_device, tag: DEMO_TAG });
  save(); renderChat();
  setStatus('Received a DEMO envelope (not real E2EE) from ' + env.from + '.');
}

function renderProfile() {
  var p = state.profile;
  $('relay-url').value = state.relayUrl || '';
  $('mode').value = state.mode || 'relay';
  if (!p) { $('profile').innerHTML = 'No identity yet. Register above.'; return; }
  $('profile').innerHTML =
    '<strong>Identity:</strong> ' + esc(p.username) + ':' + esc(p.device) +
    '<br><strong>Fingerprint (SHA-256 of Ed25519 identity key):</strong> <code>' + esc(p.fingerprint) + '</code>' +
    '<br><strong>Relay:</strong> ' + esc(state.relayUrl) + ' · <strong>Mode:</strong> ' + esc(state.mode) +
    '<br><strong>Post-quantum:</strong> ' + (p.pq ? 'ML-KEM-768 hybrid ready (sessions are hybrid iff the peer also holds a PQ key; otherwise classical)' : 'classical only (no PQ identity — re-register to publish one)') +
    '<br><small>Relay mode uses real X3DH + double ratchet, hybrid (PQXDH + hybrid ratchet) when both sides hold PQ keys. ' +
    'Keys are in this browser\'s localStorage, which is NOT production-grade secure storage. ' +
    'Compare fingerprints out of band; this client does not verify them cryptographically.</small>';
}
function renderFriends() {
  var list = $('friend-list'); var sel = $('chat-friend');
  var cur = sel.value;
  list.innerHTML = ''; sel.innerHTML = '<option value="">— pick a friend —</option>';
  state.friends.forEach(function (f, i) {
    var li = document.createElement('li');
    li.innerHTML = '<strong>' + esc(f.username) + '</strong>' +
      ' · relay: ' + esc(f.relay || '') +
      ' · fingerprint: <code>' + esc(f.fingerprint || '(none)') + '</code>' +
      '<br>Devices: ' + esc((f.devices && f.devices.length ? f.devices.join(', ') : '(none known — fetch from relay in relay mode)'));
    var rm = document.createElement('button'); rm.textContent = 'Remove'; rm.type = 'button';
    rm.onclick = function () { state.friends.splice(i, 1); save(); renderFriends(); renderChat(); };
    li.appendChild(document.createTextNode(' ')); li.appendChild(rm);
    list.appendChild(li);
    var opt = document.createElement('option'); opt.value = f.username; opt.textContent = f.username; sel.appendChild(opt);
  });
  if (cur) sel.value = cur;
}
function currentFriend() { var n = $('chat-friend').value; return state.friends.find(function (f) { return f.username === n; }) || null; }
function renderChat() {
  var f = currentFriend(); var box = $('messages'); var fan = $('fanout');
  if (!f) { box.textContent = 'Pick a friend to see this conversation.'; fan.textContent = ''; return; }
  var devices = (f.devices && f.devices.length) ? f.devices : ['(no device known)'];
  fan.innerHTML = 'Fan-out for <strong>' + esc(f.username) + '</strong>: one envelope per device — ' +
    devices.map(function (d) { return esc(f.username + ':' + d); }).join(', ');
  var msgs = state.messages.filter(function (m) { return m.peer === f.username; });
  box.innerHTML = msgs.length ? '' : 'No messages yet with this friend.';
  msgs.forEach(function (m) {
    var div = document.createElement('div'); div.className = 'msg';
    div.innerHTML = '<span class="meta">' + (m.dir === 'out' ? 'You → ' : esc(m.peer) + ' → you ') +
      esc(m.from_device || '') + ' → ' + esc(m.to_device || '') + ' · ' + new Date(m.ts).toLocaleString() + '</span>' +
      '<br>' + esc(m.text) + '<br><span class="demo-tag">' + esc(m.tag || '') + '</span>';
    box.appendChild(div);
  });
}
function renderAll() { renderProfile(); renderFriends(); renderChat(); }

// ---- Real relay client (see ../relay/README.md) ----
function relayBase() { return (state.relayUrl || '').replace(/\/+$/, ''); }
async function relayJson(path, opts) {
  var res = await fetch(relayBase() + path, opts);
  var data = null;
  try { data = await res.json(); } catch (e) { /* error body may be empty */ }
  if (!res.ok) throw new Error('relay HTTP ' + res.status + (data && data.error ? ' ' + data.error : ''));
  return data;
}
async function registerDeviceWithRelay() {
  var p = state.profile; if (!p) return;
  var id = myIdentity();
  var bundle = ECNUcrypto.bundleFromIdentity(id);
  // Publish the PQ bundle fields alongside the classical bundle, in
  // the same public_keys object the relay stores verbatim. Only
  // public keys + signatures leave the device: pqBundleFrom never
  // includes seeds, and serializePq (which holds pq_seed) is never
  // sent anywhere. ensurePq() here also covers the OPK-refill
  // re-registration path, so a profile that gains PQ locally always
  // publishes it in the same step.
  var PQ = pqModule();
  var publicKeys = bundle;
  var hadPqBefore = !!(state.profile && state.profile.pq);
  if (PQ) {
    var mine = ensurePq();
    if (mine) {
      var pqBundle = PQ.pqBundleFrom(mine);
      publicKeys = Object.assign({}, bundle, pqBundle);
    }
  }
  try {
    await relayJson('/v1/devices/register', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: p.username, device: p.device,
        identity_key: bundle.ik_sign_pub, signed_prekey: bundle.spk_pub,
        one_time_prekeys: bundle.opks, public_keys: publicKeys
      }) });
  } catch (e) {
    // Roll back a PQ identity generated in this call if publishing
    // it failed: a locally held but unpublished PQ key would make
    // this device refuse classical initials from peers that still
    // see a classical-only bundle for it. A pre-existing PQ
    // identity stays (its earlier publication stands; the failure
    // is surfaced by the caller, as the classical refill path does).
    if (!hadPqBefore && state.profile) { delete state.profile.pq; save(); }
    throw e;
  }
  setStatus('Registered device with relay ' + relayBase() + '.');
}
async function listDevices(username) {
  var data = await relayJson('/v1/devices?username=' + encodeURIComponent(username));
  return data.devices || [];
}
async function refreshFriendDevices(f) {
  if (state.mode !== 'relay') return f.devices || [];
  try {
    var devices = await listDevices(f.username);
    f.devices = devices.map(function (d) { return d.device; });
    save(); renderFriends(); renderChat();
    return f.devices;
  } catch (e) { setStatus('Could not list devices for ' + f.username + ' from relay: ' + e.message); return f.devices || []; }
}
async function peerBundleFor(username, device, opts) {
  // Non-consuming by default (device listing). Only an initiator
  // starting a NEW session passes {consume: true}, which fetches
  // through POST /v1/bundles/fetch: the relay consumes exactly one
  // OPK and the returned opk_pub is that consumed key. A receiver
  // verifying a sender's identity must NOT consume the sender's OPK.
  if (opts && opts.consume) {
    var data = await relayJson('/v1/bundles/fetch', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, device: device }) });
    var pk = data.public_keys || {};
    var bundleObj = {
      ik_sign_pub: data.ik_sign_pub || pk.ik_sign_pub,
      ik_dh_pub: data.ik_dh_pub || pk.ik_dh_pub,
      spk_pub: data.spk_pub || pk.spk_pub,
      spk_signature: data.spk_signature || pk.spk_signature,
      opk_pub: data.opk_pub
    };
    var parsed = ECNUcrypto.parseBundle(bundleObj, username);
    // PQ, consuming path: the initiator MUST use the relay's
    // returned pq_opk — the one PQOPK this fetch consumed — as the
    // handshake encapsulation target. data.public_keys.pq_opks now
    // holds only the unconsumed remainder; encapsulating to one of
    // those would let a later fetch re-serve the same key. When the
    // peer has a PQK but no PQOPK left, pq_opk is null and the
    // empty pq_opks list below makes pqxdh fall back to the PQK.
    // When the peer has no PQ fields at all, parsePqBundle returns
    // null and the session stays classical (see sendViaRelay).
    var PQc = pqModule();
    if (PQc) {
      var pqObj = {
        pq_pub: data.pq_pub != null ? data.pq_pub : (pk.pq_pub || null),
        pq_sig: data.pq_sig != null ? data.pq_sig : (pk.pq_sig || null),
        pq_opks: data.pq_opk ? [data.pq_opk] : []
      };
      parsed.pq = PQc.parsePqBundle(pqObj, username, parsed.ik_sign_pub);
    } else {
      parsed.pq = null;
    }
    return parsed;
  }
  var devices = await listDevices(username);
  var d = devices.find(function (x) { return x.device === device; });
  if (!d) throw new Error('Peer device not registered on this relay: ' + username + ':' + device);
  var bundleObj2 = d.public_keys || {
    ik_sign_pub: d.identity_key, ik_dh_pub: null, spk_pub: d.signed_prekey,
    spk_signature: null, opk_pub: (d.one_time_prekeys && d.one_time_prekeys[0]) || null
  };
  var parsed2 = ECNUcrypto.parseBundle(bundleObj2, username);
  // PQ, non-consuming path (receiver verifying a sender): the full
  // published pool is parsed + signature-verified, but nothing is
  // consumed and nothing here starts a session, so no key is burned.
  var PQl = pqModule();
  if (PQl && d.public_keys) {
    parsed2.pq = PQl.parsePqBundle(d.public_keys, username, parsed2.ik_sign_pub);
  } else {
    parsed2.pq = null;
  }
  return parsed2;
}
async function sendViaRelay(f, text) {
  var devices = await refreshFriendDevices(f);
  if (!devices.length) throw new Error('Friend has no registered devices on this relay; ask them to register first.');
  var me = myIdentity();
  for (var i = 0; i < devices.length; i++) {
    var peerAddress = f.username + ':' + devices[i];
    var session = loadSession(peerAddress);
    if (!session) {
      var bundle = await peerBundleFor(f.username, devices[i], { consume: true });
      // Mode decision, never silent: hybrid iff BOTH sides hold a
      // long-term PQK. A PQ peer is not downgraded to classical
      // (its side will refuse a classical initial), and a no-PQ
      // peer is not upgraded to hybrid (it has nothing to
      // decapsulate with). Without the PQ plug-in, mode is
      // classical and a PQ peer will refuse the initial — that
      // refusal is the correct signal, not a bug to work around.
      var PQ = pqModule();
      var ownPq = PQ ? myPq() : null;
      var mode = (PQ && ownPq) ? PQ.decideMode(ownPq, bundle.pq || null) : 'classical';
      if (mode === 'pqxdh') {
        var pqResult = await PQ.pqxdhInitiatorSecret(me, bundle, bundle.pq, ownPq.pqPub);
        session = await PQ.createHybridInitiatorSession(
          state.profile.username, f.username, me, bundle, pqResult,
          bundle.pq.pqPub, ownPq.pqSeed);
      } else {
        session = await ECNUcrypto.createInitiatorSession(state.profile.username, f.username, me, bundle);
      }
    }
    var payload = await encryptFor(session, text);
    storeSession(peerAddress, session);
    await relayJson('/v1/envelopes', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender: meAddress(), recipient: peerAddress,
        ciphertext: payload.ciphertext, protocol_version: 'v1', message_type: 'text',
        dh_pub: payload.dh_pub, n: payload.n, pn: payload.pn, nonce: payload.nonce,
        kind: payload.kind, x3dh: payload.x3dh || null,
        pq_ct: payload.pq_ct || null
      }) });
    state.messages.push({ peer: f.username, dir: 'out', text: text, ts: Date.now(), from_device: state.profile.device, to_device: devices[i], tag: (session.mode === 'hybrid' ? HYBRID_TAG : REAL_TAG) });
  }
  save(); renderChat();
}
async function fetchInbox() {
  if (!state.profile) { alert('Register first.'); return; }
  if (state.mode !== 'relay') { setStatus('Inbox fetch is a relay-mode action; you are in local demo mode. Use Simulate reply / peer tab instead.'); return; }
  try {
    // relayJson() already prepends relayBase(); passing a full URL here
    // used to produce a doubled base (http://...http://.../v1/...) and
    // every inbox fetch failed with "Failed to parse URL". Pass a path.
    var data = await relayJson('/v1/inbox?recipient=' + encodeURIComponent(meAddress()));
    var list = data.envelopes || [];
    for (var i = 0; i < list.length; i++) {
      var env = list[i];
      var senderAddress = env.sender;
      var parts = senderAddress.split(':');
      var senderUser = parts[0], senderDevice = parts.slice(1).join(':');
      var payload = {
        dh_pub: env.dh_pub, n: env.n, pn: env.pn, nonce: env.nonce,
        ciphertext: env.ciphertext, kind: env.kind, x3dh: env.x3dh || null,
        pq_ct: env.pq_ct || null
      };
      try {
        var session = loadSession(senderAddress);
        if (!session) {
          if (!payload.x3dh) throw new Error('No session for ' + senderAddress + ' and no initial (x3dh) message; cannot decrypt.');
          var bundle = await peerBundleFor(senderUser, senderDevice);
          // Anti-downgrade at the receiver, before any session is
          // built: a PQ identity refuses a classical initial, and
          // a no-PQ identity refuses a hybrid initial. Neither
          // direction falls back silently; the refusal surfaces as
          // a decrypt-failed entry below, not a classical session.
          var PQr = pqModule();
          var localPq = PQr ? myPq() : null;
          if (PQr) PQr.assertReceiverMode(!!(localPq && localPq.pqPub), payload.x3dh);
          if (PQr && PQr.isHybridInitial(payload.x3dh)) {
            session = await PQr.createHybridReceiverSession(
              state.profile.username, senderUser, myIdentity(), localPq,
              bundle.ik_sign_pub, bundle.ik_dh_pub, payload.x3dh);
          } else {
            session = await ECNUcrypto.createReceiverSession(
              state.profile.username, senderUser, myIdentity(),
              bundle.ik_sign_pub, bundle.ik_dh_pub, payload.x3dh);
          }
        }
        var text = await decryptFor(session, payload);
        storeSession(senderAddress, session);
        // First-message success consumed one of MY OPKs (the one
        // named in the initial message) and, for a hybrid session,
        // possibly one of MY PQOPKs (the handshake encapsulation
        // target). Drop each, refill below threshold (classical 5,
        // PQ 2), and re-register so the relay serves fresh pools —
        // never re-serve a consumed key as fresh (v1 pool rules).
        if (session._opkConsumed || session._pqOpkConsumed) {
          var myId = myIdentity();
          var needReregister = false;
          if (session._opkConsumed) {
            ECNUcrypto.dropOpk(myId, session._opkConsumed);
            if (myId.opks.length < ECNUcrypto.OPK_REFILL_THRESHOLD) ECNUcrypto.refillOpks(myId);
            state.profile.identity = ECNUcrypto.serializeIdentity(myId);
            session._opkConsumed = null;
            needReregister = true;
          }
          if (session._pqOpkConsumed) {
            var PQd = pqModule();
            var myPqObj = PQd ? myPq() : null;
            if (PQd && myPqObj) {
              PQd.dropPqOpk(myPqObj, session._pqOpkConsumed);
              if (myPqObj.pqOpks.length < PQd.PQ_OPK_REFILL_THRESHOLD) PQd.refillPqOpks(myPqObj, myId.ikSign.secretKey, state.profile.username);
              state.profile.pq = PQd.serializePq(myPqObj);
            }
            session._pqOpkConsumed = null;
            needReregister = true;
          }
          save();
          if (needReregister) {
            try { await registerDeviceWithRelay(); } catch (e) { setStatus('OPK refilled locally, but relay re-registration failed: ' + e.message); }
          }
        }
        state.messages.push({ peer: senderUser, dir: 'in', text: text, ts: Date.now(), from_device: senderDevice, to_device: state.profile.device, tag: (session.mode === 'hybrid' ? HYBRID_TAG : REAL_TAG) });
      } catch (e) {
        state.messages.push({ peer: senderUser, dir: 'in', text: '[could not decrypt relay envelope from ' + senderAddress + ': ' + e.message + ']', ts: Date.now(), from_device: senderDevice, to_device: state.profile.device, tag: 'DECRYPT FAILED' });
      }
    }
    save(); renderChat();
    setStatus('Inbox fetched from relay (pop-on-fetch, no ack): ' + list.length + ' envelope(s).');
  } catch (e) { setStatus('Relay unreachable or inbox failed (' + e.message + ') — no local messages lost.'); }
}

$('register-form').addEventListener('submit', async function (ev) {
  ev.preventDefault();
  var username = $('username').value.trim();
  if (!USER_RE.test(username)) { alert('Username must be 3–20 chars: letters, digits, underscore only (same rule as v1).'); return; }
  state.relayUrl = $('relay-url').value.trim() || state.relayUrl;
  state.mode = $('mode').value;
  try {
    var device = (state.profile && state.profile.username === username) ? state.profile.device : randomDeviceId();
    var id = (state.profile && state.profile.username === username) ? myIdentity() : ECNUcrypto.generateIdentity(username);
    // Same-username re-register keeps the existing PQ identity (and
    // its relay-published bundle); a fresh username gets a fresh PQ
    // identity from registerDeviceWithRelay's ensurePq() step below.
    // Never drop a published PQ identity without re-registering:
    // see ensurePq().
    var keptPq = (state.profile && state.profile.username === username) ? state.profile.pq : null;
    var fingerprint = await ECNUcrypto.fingerprintOf(id.ikSign.publicKey);
    state.profile = { username: username, device: device, identity: ECNUcrypto.serializeIdentity(id), fingerprint: fingerprint, createdAt: Date.now() };
    if (keptPq) state.profile.pq = keptPq;
    save(); renderAll();
    setStatus('Registered ' + username + ':' + device + ' locally (real identity keys generated in this browser).');
    if (state.mode === 'relay') {
      try { await registerDeviceWithRelay(); renderAll(); } catch (e) { setStatus('Local identity ready, but relay registration failed: ' + e.message); }
    }
  } catch (e) { alert('Registration failed: ' + e.message); }
});
$('mode').addEventListener('change', function () { state.mode = $('mode').value; save(); setStatus('Mode: ' + state.mode); });
$('relay-url').addEventListener('change', function () { state.relayUrl = $('relay-url').value.trim(); save(); });

$('add-friend-form').addEventListener('submit', async function (ev) {
  ev.preventDefault();
  var raw = $('invite').value.trim(); var f = null;
  try { var j = JSON.parse(raw); if (j.username) f = { username: j.username, relay: j.relay || '', fingerprint: j.fingerprint || '', device: j.device || '' }; } catch (e) { /* not JSON */ }
  if (!f) {
    var lines = raw.split(/\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (lines.length >= 1 && USER_RE.test(lines[0])) f = { username: lines[0], relay: lines[1] || '', fingerprint: lines[2] || '', device: lines[3] || '' };
  }
  if (!f) { alert('Could not parse invite. Use JSON or lines: username, relay URL, fingerprint, [device].'); return; }
  if (state.friends.some(function (x) { return x.username === f.username; })) { alert('Friend already added.'); return; }
  f.devices = f.device ? [f.device] : [];
  state.friends.push(f); $('invite').value = ''; save(); renderFriends(); renderChat();
  setStatus('Added friend ' + f.username + ' (fingerprint NOT cryptographically verified — compare out of band).');
  if (state.mode === 'relay') await refreshFriendDevices(f);
});

$('chat-friend').addEventListener('change', renderChat);
$('send-form').addEventListener('submit', async function (ev) {
  ev.preventDefault();
  var f = currentFriend(); var text = $('message-text').value;
  if (!state.profile) { alert('Register an identity first.'); return; }
  if (!f) { alert('Pick a friend first.'); return; }
  if (!text.trim()) return;
  try {
    if (state.mode === 'relay') {
      await sendViaRelay(f, text);
      setStatus('Sent via relay ' + relayBase() + ' to ' + (f.devices || []).join(', ') + '.');
    } else {
      var devices = (f.devices && f.devices.length) ? f.devices : ['?'];
      for (var i = 0; i < devices.length; i++) {
        var enc = await demoEncrypt(state.profile.username, f.username, text);
        var env = { v: 'demo-1', alg: 'AES-256-GCM-DEMO-STANDIN', demo: true, demo_tag: DEMO_TAG,
          from: state.profile.username, from_device: state.profile.device,
          to: f.username, to_device: devices[i], ts: Date.now(), iv: enc.iv, ciphertext: enc.ciphertext };
        state.messages.push({ peer: f.username, dir: 'out', text: text, ts: env.ts, from_device: env.from_device, to_device: env.to_device, tag: DEMO_TAG });
        if (channel) channel.postMessage({ envelope: env });
      }
      save(); renderChat();
      setStatus('Sent in local DEMO mode only (NOT real E2EE, never sent to a relay).');
    }
    $('message-text').value = '';
  } catch (e) { alert('Send failed: ' + e.message); }
});
$('simulate-reply').addEventListener('click', async function () {
  var f = currentFriend();
  if (!state.profile || !f) { alert('Register and pick a friend first.'); return; }
  if (state.mode !== 'demo') { alert('Simulated reply is demo-mode only. Switch Mode to Local demo to use it; in relay mode, use a second identity / peer tab through the relay.'); return; }
  var text = '[simulated reply from ' + f.username + '] Hello back — this is a local demo echo, not a real peer message.';
  try {
    var enc = await demoEncrypt(f.username, state.profile.username, text);
    await receiveDemoEnvelope({ v: 'demo-1', alg: 'AES-256-GCM-DEMO-STANDIN', demo: true, demo_tag: DEMO_TAG,
      from: f.username, from_device: (f.devices && f.devices[0]) || '?', to: state.profile.username,
      to_device: state.profile.device, ts: Date.now(), iv: enc.iv, ciphertext: enc.ciphertext });
  } catch (e) { alert('Simulated reply failed: ' + e.message); }
});
$('open-peer-tab').addEventListener('click', function () {
  window.open(location.pathname + '?profile=peer', '_blank');
});
$('copy-invite').addEventListener('click', function () {
  if (!state.profile) { alert('Register first.'); return; }
  var invite = JSON.stringify({ username: state.profile.username, device: state.profile.device, relay: state.relayUrl, fingerprint: state.profile.fingerprint });
  if (navigator.clipboard) navigator.clipboard.writeText(invite).then(function () { setStatus('Invite copied.'); }, function () { prompt('Copy your invite:', invite); });
  else prompt('Copy your invite:', invite);
});
$('clear-demo').addEventListener('click', function () {
  if (!confirm('Clear all data (identity, friends, messages, sessions) in this browser namespace?')) return;
  localStorage.removeItem(STORE_KEY); location.reload();
});
$('fetch-inbox').addEventListener('click', fetchInbox);
setInterval(function () { if (state.mode === 'relay' && state.profile) fetchInbox(); }, 5000);

// PWA: register the app-shell-only service worker when served over http(s); file:// fails silently and is fine.
if ('serviceWorker' in navigator) { navigator.serviceWorker.register('./sw.js').catch(function () {}); }
if (state.profile) $('username').value = state.profile.username;
renderAll();
setStatus(state.profile
  ? 'Ready in ' + state.mode + ' mode as ' + state.profile.username + ':' + state.profile.device + '.' + (crypto.subtle ? '' : ' WARNING: SubtleCrypto unavailable here.')
  : 'Ready — register an identity to start.' + (crypto.subtle ? '' : ' WARNING: SubtleCrypto unavailable here; serve over http://localhost.'));
