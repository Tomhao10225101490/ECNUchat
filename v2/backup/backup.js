'use strict';
/*
 * ECNUchat v2 — Track C (e): Encrypted passphrase backup / restore.
 * WORKING CODE (PBKDF2 + AES-256-GCM, WebCrypto; Node 18+ and browsers).
 *
 * >>> LOST-PHONE-NO-BACKUP LIMITATION — READ FIRST <<<
 * If a phone is lost, stolen, or wiped, and NO encrypted backup
 * bundle exists, the identity, ratchet sessions, group sender keys
 * and history on that device are GONE. The relay cannot restore
 * them: it holds only ciphertext envelopes, never private keys,
 * never the passphrase or any key derived from it. There is NO
 * server-side recovery and NO passphrase reset, by design — any
 * mechanism that let a server restore an identity would also let
 * that server (or anyone compromising it) impersonate the user.
 * A forgotten passphrase with a bundle in hand is equally
 * unrecoverable: the bundle is undecryptable without it. The UI
 * MUST state this prominently at setup, at backup creation, and
 * at restore — not buried in a help page. A backup is a snapshot,
 * not a live mirror: refresh it after significant changes.
 *
 * Format (ecnu-backup-v1), matching docs/backup-encrypted.md §3:
 *  - KDF: PBKDF2-HMAC-SHA256, fresh random 16-byte salt per bundle,
 *    600,000 iterations by default (OWASP target for PBKDF2-HMAC-
 *    SHA256 at implementation time). Iteration count is stored in
 *    the plaintext header (it is not secret); accepted range on
 *    import is 100,000–2,000,000 to refuse absurd/malicious values.
 *  - Encryption: AES-256-GCM, fresh random 12-byte nonce per
 *    bundle; the GCM tag is the integrity check. A wrong passphrase
 *    or a corrupted/swapped bundle fails authentication and the
 *    restore FAILS CLOSED: no partial restore, no decrypted subset,
 *    a generic error only ("passphrase or bundle incorrect") — no
 *    hint about which part was wrong, to avoid aiding guessing.
 *  - Header (plaintext): format, kdf, iterations, salt, nonce,
 *    bundle_id. It reveals only "this is an ECNUchat backup" and
 *    its KDF parameters — no identity, no history, no passphrase
 *    hint. The passphrase itself is NEVER stored in the bundle, in
 *    the header, or anywhere else by this module, and is never sent
 *    to a relay. The bundle is ciphertext in every storage option
 *    (relay blob, local file, QR-assisted fetch of a locator only:
 *    a QR must encode only a bundle locator + one-time fetch token,
 *    never the passphrase, bundle key, or a private key).
 *  - Contents: whatever state object the caller passes — identity
 *    (private key included, that is the point), ratchet states,
 *    group sender keys, message history, contact trust state. This
 *    module does not decide history scope; the caller does, and
 *    must not include any other device's private keys.
 *  - Passphrase policy enforced here: empty passphrases refused;
 *    minimum 8 characters. PBKDF2 slows guessing; it does NOT make
 *    a weak passphrase safe — the UI must warn about that too.
 */
(function (root) {
  var FORMAT = 'ecnu-backup-v1';
  var KDF = 'PBKDF2-HMAC-SHA256';
  var DEFAULT_ITERATIONS = 600000;
  var MIN_ITERATIONS = 100000, MAX_ITERATIONS = 2000000;
  var MIN_PASSPHRASE_LEN = 8;

  function subtle() {
    var c = (typeof crypto !== 'undefined' ? crypto : null) || root.crypto;
    if (!c || !c.subtle) throw new Error('SubtleCrypto unavailable');
    return c.subtle;
  }
  function enc() { return new TextEncoder(); }
  function dec() { return new TextDecoder(); }
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
  function randomBytes(n) {
    var out = new Uint8Array(n);
    var c = (typeof crypto !== 'undefined' ? crypto : null) || root.crypto;
    if (c && c.getRandomValues) { c.getRandomValues(out); return out; }
    if (typeof require === 'function') { out.set(require('crypto').randomBytes(n)); return out; }
    throw new Error('No secure RNG available');
  }
  function checkPassphrase(p) {
    if (typeof p !== 'string' || p.length < MIN_PASSPHRASE_LEN) {
      throw new Error('Passphrase must be at least ' + MIN_PASSPHRASE_LEN + ' characters; empty passphrases are refused');
    }
  }
  async function deriveKey(passphrase, salt, iterations) {
    var s = subtle();
    var base = await s.importKey('raw', enc().encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
    return s.deriveKey({ name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function exportBundle(state, passphrase, opts) {
    opts = opts || {};
    checkPassphrase(passphrase);
    var plaintext;
    try { plaintext = JSON.stringify(state); }
    catch (e) { throw new Error('Backup state is not JSON-serialisable'); }
    if (typeof plaintext !== 'string') throw new Error('Backup state must be a JSON object');
    var iterations = opts.iterations || DEFAULT_ITERATIONS;
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) throw new Error('Iteration count out of accepted range');
    var salt = randomBytes(16), nonce = randomBytes(12);
    var idBytes = randomBytes(16), idHex = '';
    idBytes.forEach(function (b) { idHex += ('0' + b.toString(16)).slice(-2); });
    var key = await deriveKey(passphrase, salt, iterations);
    var ct = new Uint8Array(await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce }, key, enc().encode(plaintext)));
    return {
      header: { format: FORMAT, kdf: KDF, iterations: iterations,
        salt: b64(salt), nonce: b64(nonce), bundle_id: 'ecnu-' + idHex },
      ciphertext: b64(ct)
    };
  }
  async function importBundle(bundle, passphrase) {
    // Fail closed, generic error only: never distinguish wrong
    // passphrase from corrupted bundle in the thrown message.
    var FAIL = 'passphrase or bundle incorrect';
    try {
      checkPassphrase(passphrase);
      if (!bundle || !bundle.header || !bundle.ciphertext) throw new Error(FAIL);
      var h = bundle.header;
      if (h.format !== FORMAT || h.kdf !== KDF) throw new Error(FAIL);
      if (typeof h.iterations !== 'number' || h.iterations < MIN_ITERATIONS || h.iterations > MAX_ITERATIONS) throw new Error(FAIL);
      var salt = unb64(h.salt), nonce = unb64(h.nonce), ct = unb64(bundle.ciphertext);
      if (salt.length < 16 || nonce.length !== 12 || ct.length < 16) throw new Error(FAIL);
      var key = await deriveKey(passphrase, salt, h.iterations);
      var pt = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce }, key, ct));
      var state = JSON.parse(dec().decode(pt));
      if (!state || typeof state !== 'object' || Array.isArray(state)) throw new Error(FAIL);
      return state;
    } catch (e) {
      // Collapse every failure (bad passphrase, tamper, corrupt
      // JSON, bad header) into the single generic message, except
      // a too-short passphrase, which is a caller input error.
      if (e && e.message && e.message.indexOf('at least') !== -1) throw e;
      throw new Error(FAIL);
    }
  }
  // Verify a freshly created bundle decrypts with the passphrase,
  // without exposing plaintext to any other component (the caller
  // discards the returned state). Use before superseding an old
  // bundle, so a failed new backup never destroys the only good copy.
  async function verifyBundle(bundle, passphrase) {
    await importBundle(bundle, passphrase);
    return true;
  }

  var api = {
    FORMAT: FORMAT, KDF: KDF, DEFAULT_ITERATIONS: DEFAULT_ITERATIONS,
    MIN_PASSPHRASE_LEN: MIN_PASSPHRASE_LEN,
    exportBundle: exportBundle, importBundle: importBundle, verifyBundle: verifyBundle,
    LOST_PHONE_WARNING: 'No backup = identity lost. No server-side recovery, by design. If the phone is lost and no encrypted backup bundle exists, the identity cannot be restored by the relay, by support, or by anyone.'
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ECNUBackup = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
