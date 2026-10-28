'use strict';
/* ECNUchat v2 — Track C (d): service-worker push handler (WAKE ONLY).
 *
 * Deploy this file as the PWA's push service worker (or merge its
 * two listeners into the existing worker). It holds NO private keys
 * and performs NO decryption: on push it validates that the payload
 * is exactly { type: 'wake', v: 1 } and shows only a generic
 * notification. Any payload carrying content (text, sender, group,
 * preview, ...) is ignored, never rendered. Decryption happens in
 * the app after the user opens it (see wake_push.js fetchAndDecrypt).
 *
 * Logic mirrors wake_push.js (tested in Node); this file is the
 * browser service-worker wiring around the same rule. In a worker
 * that supports importScripts, wake_push.js is loaded if present
 * and its handlePush is used; otherwise the inline fallback below
 * enforces the identical rule, so the worker is safe standalone.
 */
(function () {
  var loaded = false;
  try {
    if (typeof importScripts === 'function') {
      importScripts('./wake_push.js');
      loaded = typeof self !== 'undefined' && !!self.ECNUWakePush;
    }
  } catch (e) { loaded = false; }
  function isWakeOnly(payload) {
    if (loaded) return self.ECNUWakePush.isWakeOnly(payload);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
    if (payload.type !== 'wake' || payload.v !== 1) return false;
    var keys = Object.keys(payload);
    for (var i = 0; i < keys.length; i++) {
      if (keys[i] !== 'type' && keys[i] !== 'v') return false;
    }
    return true;
  }
  function genericNotification() {
    if (loaded) return self.ECNUWakePush.handlePush({ type: 'wake', v: 1 }).notification;
    return { title: 'New message', body: 'Open ECNUchat to read it', tag: 'ecnu-wake' };
  }
  self.addEventListener('push', function (event) {
    var payload = null;
    try { payload = event.data ? event.data.json() : null; } catch (e) { payload = null; }
    if (!isWakeOnly(payload)) return; // content-bearing or malformed push: ignore silently
    var n = genericNotification();
    event.waitUntil(self.registration.showNotification(n.title, { body: n.body, tag: n.tag }));
  });
  self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    // Open the app only — never a conversation deep link (that
    // would leak which conversation woke the user via the push).
    event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (wins) {
      if (wins.length) return wins[0].focus();
      return self.clients.openWindow('./');
    }));
  });
})();
