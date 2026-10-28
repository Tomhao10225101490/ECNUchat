'use strict';
/*
 * ECNUchat v2 — Track C (f): desktop relay-URL configurability.
 *
 * Resolution order (highest first):
 *  1. ECNU_RELAY_URL environment variable (desktop / CLI use).
 *  2. A JSON config file's `relayUrl` field, if the caller supplies
 *     parsed file content (desktop reads it from the path in
 *     ECNU_DESKTOP_CONFIG, or from its bundled default config).
 *  3. The PWA's stored relay URL, passed in by the caller (the PWA
 *     keeps it in localStorage; the desktop preload bridge may
 *     forward it). In this scaffold the preload does not read the
 *     PWA's storage automatically — the main process passes the
 *     resolved URL into the window as ECNU_DESKTOP_RELAY_URL.
 *  4. Default: http://127.0.0.1:8765 (the local dev relay).
 *
 * Production rule: a production relay URL MUST be https://. An
 * http:// URL that is not loopback is rejected here, so a desktop
 * build can never silently talk to a production relay in the clear.
 * The local relay itself does no TLS; production TLS is terminated
 * by the deployment (see ../relay-prod/README.md).
 */
var DEFAULT_RELAY_URL = 'http://127.0.0.1:8765';

function normalize(url) {
  if (typeof url !== 'string') return null;
  var u = url.trim().replace(/\/+$/, '');
  if (!u) return null;
  return u;
}
function isLoopback(url) {
  try {
    var host = new URL(url).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost');
  } catch (e) { return false; }
}
function resolveRelayUrl(opts) {
  opts = opts || {};
  var env = normalize(opts.envRelayUrl);
  var file = opts.fileConfig && normalize(opts.fileConfig.relayUrl);
  var stored = normalize(opts.storedRelayUrl);
  var chosen = env || file || stored || DEFAULT_RELAY_URL;
  var proto = null;
  try { proto = new URL(chosen).protocol; } catch (e) { throw new Error('Invalid relay URL: ' + chosen); }
  if (proto !== 'https:' && proto !== 'http:') throw new Error('Relay URL must be http(s): ' + chosen);
  if (proto === 'http:' && !isLoopback(chosen)) {
    throw new Error('Refusing non-loopback http relay URL (production relays must be https): ' + chosen);
  }
  return chosen;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DEFAULT_RELAY_URL: DEFAULT_RELAY_URL, resolveRelayUrl: resolveRelayUrl, isLoopback: isLoopback };
}
