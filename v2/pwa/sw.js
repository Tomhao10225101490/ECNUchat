'use strict';
/* ECNUchat v2 PWA scaffold service worker — caches the APP SHELL ONLY.
 * Never cached: messages, envelopes, keys, fingerprints, inbox responses, relay traffic.
 * All relay fetches bypass the cache (fetch event only serves the shell list, else network). */
var CACHE = 'ecnu-chat-v2-shell-v2';
var SHELL = ['./', './index.html', './styles.css', './app.js', './crypto.js', './vendor/nacl-fast.min.js', './manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', function (event) {
  event.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }).then(function () { return self.skipWaiting(); }));
});
self.addEventListener('activate', function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});
self.addEventListener('fetch', function (event) {
  var url = new URL(event.request.url);
  // Relay / API traffic and non-GET: network only, never cached, never served from cache.
  if (event.request.method !== 'GET' || url.pathname.indexOf('/v1/') !== -1) return;
  if (url.origin !== location.origin) return;
  event.respondWith(caches.match(event.request, { ignoreSearch: true }).then(function (hit) { return hit || fetch(event.request); }));
});
