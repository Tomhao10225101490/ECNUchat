'use strict';
/*
 * ECNUchat v2 — Track C (d): Wake-only push. WORKING CODE.
 *
 * The rule, from docs/push-wake-only.md: push wakes, push never
 * tells. A push payload is exactly { type: 'wake', v: 1 } — no
 * message text, no sender name, no group name, no preview, no
 * count, no thread identifier. Anything else is rejected, never
 * rendered as a notification.
 *
 * Two halves, kept separate on purpose:
 *  1. handlePush(payload) — the SERVICE WORKER half. It holds no
 *     private keys, performs NO decryption, and shows only a
 *     generic notification ("New message — open ECNUchat to read
 *     it"). A compromised or curious push path can therefore yield
 *     at most a wake, never plaintext.
 *  2. fetchAndDecrypt(...) — the APP (foreground) half. After the
 *     user opens the app, it fetches ciphertext envelopes from the
 *     relay and decrypts them locally with keys that never left
 *     the device. Decryption never happens in the service worker.
 *     Delivery is by envelope id deduplication: a lost, delayed or
 *     duplicate push never loses or duplicates a message, because
 *     the message waits as ciphertext in the relay mailbox until
 *     fetched, and pop-on-fetch / dedup handles repeats.
 *
 * iOS limits (documented, not hidden — see push/README.md):
 *  - PWA push on iOS needs iOS 16.4+, Home-Screen install (not a
 *    Safari tab), and explicit permission. Older iOS / Safari-tab
 *    users get NO push wakes; polling on next open is their path.
 *  - iOS may delay, coalesce or throttle background push; there is
 *    no iOS VoIP-push equivalent for a PWA, so a voice-call invite
 *    delivered via a late push may already be past its ~45s window.
 *  - This code therefore CANNOT promise native-app reliability on
 *    iOS. It promises wake-only pushes where the platform allows
 *    them, and messages never lost because push failed.
 */
(function (root) {
  var FORBIDDEN_PAYLOAD_KEYS = ['text', 'message', 'body', 'sender',
    'sender_name', 'from', 'group', 'group_name', 'preview', 'snippet',
    'content', 'title', 'subject', 'count', 'thread', 'thread_id',
    'ciphertext', 'key', 'image'];
  var GENERIC_NOTIFICATION = {
    title: 'New message',
    body: 'Open ECNUchat to read it',
    tag: 'ecnu-wake',
    renotify: false
  };

  function isWakeOnly(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
    if (payload.type !== 'wake' || payload.v !== 1) return false;
    var keys = Object.keys(payload);
    for (var i = 0; i < keys.length; i++) {
      if (keys[i] !== 'type' && keys[i] !== 'v') return false;
      if (FORBIDDEN_PAYLOAD_KEYS.indexOf(keys[i]) !== -1) return false;
    }
    return true;
  }
  function forbiddenKeysFound(payload) {
    if (!payload || typeof payload !== 'object') return [];
    return Object.keys(payload).filter(function (k) { return FORBIDDEN_PAYLOAD_KEYS.indexOf(k) !== -1; });
  }
  // Service-worker half: validate, then return the generic
  // notification to show — or an ignore decision. Never decrypts.
  function handlePush(payload) {
    if (!isWakeOnly(payload)) {
      return { action: 'ignore',
        reason: 'Payload is not a wake-only signal (must be exactly {type:"wake",v:1}); content-bearing pushes are never rendered',
        forbidden: forbiddenKeysFound(payload) };
    }
    return { action: 'notify', notification: {
      title: GENERIC_NOTIFICATION.title, body: GENERIC_NOTIFICATION.body,
      tag: GENERIC_NOTIFICATION.tag, renotify: GENERIC_NOTIFICATION.renotify } };
  }
  function notificationClickAction() {
    // No content in the notification, so a click can only open the
    // app; the app then fetches + decrypts. Never a deep link that
    // names a conversation (that would leak metadata via the push).
    return { action: 'open-app', url: './' };
  }
  // App (foreground) half: fetch ciphertext envelopes from the
  // relay, decrypt locally, dedup by envelope_id. `fetchInbox` must
  // return { envelopes: [{ envelope_id, ... }] }; `decrypt` must
  // throw on failure. Failures are reported per-envelope, never
  // rendered as plaintext, and never retried as plaintext.
  async function fetchAndDecrypt(opts) {
    if (!opts || typeof opts.fetchInbox !== 'function' || typeof opts.decrypt !== 'function') {
      throw new Error('fetchAndDecrypt requires fetchInbox and decrypt functions');
    }
    var seen = opts.seenIds || new Set();
    var data = await opts.fetchInbox();
    var envelopes = (data && data.envelopes) || [];
    var messages = [], failed = [];
    for (var i = 0; i < envelopes.length; i++) {
      var env = envelopes[i];
      if (!env.envelope_id) { failed.push({ envelope: env, error: 'Envelope without id ignored' }); continue; }
      if (seen.has(env.envelope_id)) continue; // duplicate wake/fetch: skip
      seen.add(env.envelope_id);
      try {
        var text = await opts.decrypt(env);
        messages.push({ envelope_id: env.envelope_id, sender: env.sender || null, text: text });
      } catch (e) {
        failed.push({ envelope_id: env.envelope_id, error: e && e.message ? e.message : String(e) });
      }
    }
    return { messages: messages, failed: failed, seenIds: seen };
  }

  var api = {
    FORBIDDEN_PAYLOAD_KEYS: FORBIDDEN_PAYLOAD_KEYS,
    GENERIC_NOTIFICATION: GENERIC_NOTIFICATION,
    isWakeOnly: isWakeOnly, forbiddenKeysFound: forbiddenKeysFound,
    handlePush: handlePush, notificationClickAction: notificationClickAction,
    fetchAndDecrypt: fetchAndDecrypt
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ECNUWakePush = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
