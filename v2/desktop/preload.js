'use strict';
/* ECNUchat v2 desktop preload — exposes ONLY the resolved relay URL
 * to the PWA renderer. No Node APIs, no keys, no filesystem access
 * are exposed. The PWA reads window.ECNU_DESKTOP_RELAY_URL (set by
 * main.js after load) or, if present, this bridge value; a relay
 * URL configured here never overrides an explicit user choice in
 * the PWA's own relay-URL field — main.js documents that the PWA
 * field wins when the user has typed one. */
try {
  var contextBridge = require('electron').contextBridge;
  contextBridge.exposeInMainWorld('ECNUDesktop', {
    getRelayUrl: function () { return window.ECNU_DESKTOP_RELAY_URL || null; }
  });
} catch (e) { /* loaded outside Electron (e.g. node --check): no-op */ }
