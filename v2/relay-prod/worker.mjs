// ECNUchat v2 — Track C (f): production relay for Cloudflare Workers + D1.
//
// DEPLOYMENT STATUS: CODE WRITTEN, NOT DEPLOYED, NOT RUN ON
// WORKERS. Blocker, stated exactly: no Cloudflare account, token,
// or wrangler installation is available to Track C, and Track C
// must not touch the user's accounts. `wrangler.toml` + `schema.sql`
// are provided so deployment is a documented, single-command step
// on a machine/account that has them (see README.md). What IS
// tested (tests/test_track_c_relay_prod.js, Node): the routing,
// validation, OPK consumption, forbidden-field rejection, and rate
// limiting, against the InMemoryStore below — the same handler
// code the Worker entry point calls. What is NOT tested: the D1
// store SQL against a real D1 database, and the Worker runtime
// itself (no wrangler here). Do not claim this relay is live.
//
// What this is: the same HTTP JSON mailbox API as relay/relay.py
// (register, device list, consuming bundle fetch, envelopes,
// inbox pop, inbox count, revoke), with:
//  - TLS termination by Cloudflare: the deployed URL is https://
//    automatically (workers.dev subdomain or a custom domain with
//    Cloudflare proxying). This worker never serves plain HTTP in
//    production and must never be deployed behind a plain-http URL.
//    The dev relay's plain-HTTP warning does not carry over: the
//    deployment, not the code, provides TLS.
//  - WSS: NOT implemented. Like the dev relay, this is HTTP JSON,
//    not WebSocket. Clients poll GET /v1/inbox (pop-on-fetch).
//    Workers DO support WebSocket upgrades, but no WS endpoint is
//    provided here and none should be claimed.
//  - Rate limiting: per-client-IP fixed window (default 120
//    requests/minute, 60/minute for envelope/register writes),
//    stored in D1 in production (createD1RateStore) so it survives
//    across isolates; the in-memory fallback is per-isolate only
//    and is a test/dev aid, not a production limit. Exceeding it
//    returns 429 with retry_after_seconds. This is abuse friction,
//    not authentication: like the dev relay, this worker does NOT
//    authenticate anyone (no password/token/signature check) —
//    that remains a known production gap, stated here, not hidden.
//  - No long-poll: GET /v1/inbox returns immediately (Workers CPU
//    limits make the dev relay's 30s long-poll unsuitable). Clients
//    must poll, or use push wakes (see ../push/) to learn when to
//    fetch. The dev relay's wait_seconds parameter is accepted and
//    ignored (documented difference, not silent behaviour change
//    in the response shape — responses carry no wait field).
//  - Opacity: envelopes are opaque base64; the worker never parses
//    ciphertext, never holds a private key, never stores a password,
//    and never logs ciphertext or plaintext.

const USERNAME_RE = /^[A-Za-z0-9_.\-]{3,20}$/;
const DEVICE_RE = /^[A-Za-z0-9_.\-]{1,64}$/;
const FORBIDDEN_FIELDS = new Set(['private_key', 'privatekey', 'secret_key',
  'password', 'passphrase', 'seed', 'mnemonic']);
const MAX_CIPHERTEXT_CHARS = 1048576;

export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
function parseAddress(value) {
  if (!value || typeof value !== 'string' || value.split(':').length !== 2) return null;
  const [u, d] = value.split(':');
  if (!USERNAME_RE.test(u) || !DEVICE_RE.test(d)) return null;
  return [u, d];
}
function checkForbidden(obj) {
  if (obj && typeof obj === 'object') {
    if (Array.isArray(obj)) { for (const v of obj) { const f = checkForbidden(v); if (f) return f; } }
    else for (const k of Object.keys(obj)) {
      if (FORBIDDEN_FIELDS.has(k)) return k;
      const f = checkForbidden(obj[k]); if (f) return f;
    }
  }
  return null;
}
function isB64(s) {
  if (typeof s !== 'string' || !s) return false;
  try {
    if (typeof Buffer !== 'undefined') Buffer.from(s, 'base64');
    else atob(s);
    return /^[A-Za-z0-9+/=]+$/.test(s);
  } catch { return false; }
}

// --- In-memory store (tests + reference; production uses D1Store) ---
export class InMemoryStore {
  constructor() { this.devices = new Map(); this.queues = new Map(); this.revoked = new Set(); }
  key(u, d) { return u + ':' + d; }
  register(device) {
    const k = this.key(device.username, device.device);
    this.revoked.delete(k);
    const old = this.devices.get(k);
    if (old) device.registered_at = old.registered_at;
    this.devices.set(k, device);
    if (!this.queues.has(k)) this.queues.set(k, []);
    return device;
  }
  list(username) { return [...this.devices.values()].filter((d) => d.username === username); }
  get(u, d) { return this.devices.get(this.key(u, d)) || null; }
  revoke(u, d) {
    const k = this.key(u, d);
    const existed = this.devices.has(k);
    this.devices.delete(k); this.queues.delete(k); this.revoked.add(k);
    return existed;
  }
  isRevoked(u, d) { return this.revoked.has(this.key(u, d)); }
  enqueue(env) {
    const k = this.key(env.recipient_username, env.recipient_device);
    if (!this.queues.has(k)) this.queues.set(k, []);
    this.queues.get(k).push(env);
  }
  popAll(u, d) { const k = this.key(u, d); const q = this.queues.get(k) || []; this.queues.set(k, []); return q; }
  count(u, d) { return (this.queues.get(this.key(u, d)) || []).length; }
  // Consuming bundle fetch: exactly one OPK removed from every pool
  // field, never re-served. Mirrors relay/relay.py fetch_bundle.
  fetchBundle(u, d) {
    if (this.isRevoked(u, d)) throw new ApiError(410, 'DEVICE_REVOKED', 'device is revoked; it receives no new messages');
    const rec = this.get(u, d);
    if (!rec) throw new ApiError(404, 'DEVICE_NOT_FOUND', 'recipient device is not registered');
    const record = JSON.parse(JSON.stringify(rec));
    let consumed = null, remaining = 0;
    if (Array.isArray(record.one_time_prekeys) && record.one_time_prekeys.length) {
      consumed = record.one_time_prekeys.shift();
      remaining = record.one_time_prekeys.length;
    }
    if (record.public_keys && typeof record.public_keys === 'object') {
      const pk = record.public_keys;
      if (Array.isArray(pk.opks) && pk.opks.length) {
        if (consumed === null) consumed = pk.opks.shift(); else pk.opks.shift();
        remaining = pk.opks.length;
        pk.opk_pub = pk.opks[0] || null;
      } else if (pk.opk_pub != null) {
        if (consumed === null) consumed = pk.opk_pub;
        pk.opk_pub = null;
      }
    }
    this.register(record);
    return { record, consumed, remaining };
  }
}

// --- D1 store (production; SQL reviewed, NOT integration-tested) ---
// Tables: see schema.sql. Devices stored as one JSON row; envelopes
// as one row each; revoked as one row each.
export function createD1Store(db) {
  const q = (sql, ...args) => db.prepare(sql).bind(...args);
  return {
    async register(device) {
      const k = device.username + ':' + device.device;
      const old = await q('SELECT data FROM devices WHERE username=? AND device=?', device.username, device.device).first();
      if (old) device.registered_at = JSON.parse(old.data).registered_at;
      await q('INSERT OR REPLACE INTO devices VALUES (?,?,?)', device.username, device.device, JSON.stringify(device)).run();
      await q('DELETE FROM revoked WHERE username=? AND device=?', device.username, device.device).run();
      return device;
    },
    async list(username) {
      const r = await q('SELECT data FROM devices WHERE username=? ORDER BY device', username).all();
      return (r.results || []).map((row) => JSON.parse(row.data));
    },
    async get(u, d) {
      const row = await q('SELECT data FROM devices WHERE username=? AND device=?', u, d).first();
      return row ? JSON.parse(row.data) : null;
    },
    async revoke(u, d) {
      const row = await q('SELECT 1 AS x FROM devices WHERE username=? AND device=?', u, d).first();
      await q('DELETE FROM devices WHERE username=? AND device=?', u, d).run();
      await q('DELETE FROM envelopes WHERE username=? AND device=?', u, d).run();
      await q('INSERT OR REPLACE INTO revoked VALUES (?,?,?)', u, d, new Date().toISOString()).run();
      return !!row;
    },
    async isRevoked(u, d) {
      return !!(await q('SELECT 1 AS x FROM revoked WHERE username=? AND device=?', u, d).first());
    },
    async enqueue(env) {
      await q('INSERT INTO envelopes VALUES (?,?,?,?,?)', env.envelope_id, env.recipient_username, env.recipient_device, JSON.stringify(env), Date.now() / 1000).run();
    },
    async popAll(u, d) {
      const r = await q('SELECT data FROM envelopes WHERE username=? AND device=? ORDER BY created_at', u, d).all();
      await q('DELETE FROM envelopes WHERE username=? AND device=?', u, d).run();
      return (r.results || []).map((row) => JSON.parse(row.data));
    },
    async count(u, d) {
      const row = await q('SELECT COUNT(*) AS n FROM envelopes WHERE username=? AND device=?', u, d).first();
      return row ? Number(row.n) : 0;
    },
    async fetchBundle(u, d) {
      // Same consumption semantics as InMemoryStore.fetchBundle,
      // implemented by loading, mutating, and re-registering.
      const mem = new InMemoryStore();
      const rec = await this.get(u, d);
      if (await this.isRevoked(u, d)) throw new ApiError(410, 'DEVICE_REVOKED', 'device is revoked; it receives no new messages');
      if (!rec) throw new ApiError(404, 'DEVICE_NOT_FOUND', 'recipient device is not registered');
      mem.register(JSON.parse(JSON.stringify(rec)));
      const out = mem.fetchBundle(u, d);
      await this.register(out.record);
      return out;
    }
  };
}

// --- Rate limiting: fixed window, storage interface {get,set} ---
// Production backend: createD1RateStore(db) (D1 table rate_limits).
// Test/dev backend: a plain Map wrapped as {get,set}. A Map backend
// is per-isolate only — in production always use the D1 backend.
export class RateLimiter {
  constructor(store, opts = {}) {
    this.store = store;
    this.windowMs = opts.windowMs || 60000;
    this.nowMs = opts.nowMs || (() => Date.now());
  }
  check(key, limit) {
    const now = this.nowMs();
    const cur = this.store.get(key);
    if (!cur || now - cur.windowStart >= this.windowMs) {
      this.store.set(key, { count: 1, windowStart: now });
      return { allowed: true, retryAfter: 0 };
    }
    if (cur.count >= limit) {
      return { allowed: false, retryAfter: Math.ceil((this.windowMs - (now - cur.windowStart)) / 1000) };
    }
    cur.count += 1;
    this.store.set(key, cur);
    return { allowed: true, retryAfter: 0 };
  }
}
export function createD1RateStore(db) {
  return {
    _cache: new Map(),
    async get(key) { return this._cache.get(key) || null; },
    async set(key, val) {
      this._cache.set(key, val);
      await db.prepare('INSERT OR REPLACE INTO rate_limits VALUES (?,?,?)').bind(key, val.count, val.windowStart).run();
    }
  };
}
function mapRateStore() {
  const m = new Map();
  return { get: (k) => m.get(k) || null, set: (k, v) => m.set(k, v) };
}

// --- Handler: transport-independent, works with any store ---
export function createHandler(opts = {}) {
  const store = opts.store || new InMemoryStore();
  const limiter = new RateLimiter(opts.rateStore || mapRateStore(), { nowMs: opts.nowMs });
  const GENERAL_LIMIT = opts.generalLimit || 120;
  const WRITE_LIMIT = opts.writeLimit || 60;

  async function requireRecipient(u, d) {
    if (await store.isRevoked(u, d)) throw new ApiError(410, 'DEVICE_REVOKED', 'device is revoked; it receives no new messages');
    if (!(await store.get(u, d))) throw new ApiError(404, 'DEVICE_NOT_FOUND', 'recipient device is not registered');
  }
  function ok(status, body) { return { status, body }; }
  function err(e) {
    if (e instanceof ApiError) return { status: e.status, body: { error: e.code, message: e.message } };
    return { status: 500, body: { error: 'INTERNAL_ERROR', message: 'internal error' } };
  }

  async function handle(req) {
    try {
      const url = new URL(req.url, 'https://relay.invalid');
      const path = url.pathname.replace(/\/+$/, '') || '/';
      const method = (req.method || 'GET').toUpperCase();
      const ip = (req.headers && (req.headers.get('cf-connecting-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim())) || 'unknown';
      const isWrite = method === 'POST' || method === 'DELETE';
      const limit = isWrite ? WRITE_LIMIT : GENERAL_LIMIT;
      const rl = limiter.check('ip:' + ip, limit);
      if (!rl.allowed) return { status: 429, body: { error: 'RATE_LIMITED', message: 'rate limit exceeded', retry_after_seconds: rl.retryAfter } };
      const body = req.json ? await req.json().catch(() => ({})) : (req.body || {});
      const parts = path.split('/').filter(Boolean);

      if (method === 'GET' && (path === '/' || path === '/health')) {
        return ok(200, { status: 'ok', service: 'ecnu-chat-v2-relay', transport: 'http-json-workers (NOT WebSocket)', protocol_version: 'v1', tls: 'terminated-by-cloudflare' });
      }
      if (method === 'POST' && path === '/v1/devices/register') {
        const forbidden = checkForbidden(body);
        if (forbidden) throw new ApiError(400, 'PRIVATE_DATA_REJECTED', `field '${forbidden}' must never be sent to a relay`);
        if (!USERNAME_RE.test(body.username || '')) throw new ApiError(400, 'INVALID_USERNAME', 'username must be 3-20 chars: letters, digits, _ . -');
        if (!DEVICE_RE.test(body.device || '')) throw new ApiError(400, 'INVALID_DEVICE', 'device must be 1-64 chars: letters, digits, _ . -');
        const now = new Date().toISOString();
        const record = { username: body.username, device: body.device, address: body.username + ':' + body.device,
          identity_key: body.identity_key || null, signed_prekey: body.signed_prekey || null,
          one_time_prekeys: body.one_time_prekeys || null, public_keys: body.public_keys || null,
          registered_at: now, updated_at: now };
        for (const k of Object.keys(body)) if (!(k in record)) record[k] = body[k];
        const saved = await store.register(record);
        return ok(200, saved);
      }
      if (method === 'GET' && path === '/v1/devices') {
        const username = url.searchParams.get('username');
        if (!username) throw new ApiError(400, 'MISSING_USERNAME', 'query parameter username is required');
        if (!USERNAME_RE.test(username)) throw new ApiError(400, 'INVALID_USERNAME', 'username must be 3-20 chars: letters, digits, _ . -');
        return ok(200, { username, devices: await store.list(username) });
      }
      if (method === 'POST' && path === '/v1/bundles/fetch') {
        const addr = parseAddress(body.recipient || body.address) ||
          (body.username && body.device ? parseAddress(body.username + ':' + body.device) : null);
        if (!addr) throw new ApiError(400, 'INVALID_ADDRESS', "give username + device (or recipient='username:device')");
        const out = await store.fetchBundle(addr[0], addr[1]);
        const pk = out.record.public_keys || {};
        return ok(200, { username: addr[0], device: addr[1], address: addr.join(':'),
          identity_key: out.record.identity_key, signed_prekey: out.record.signed_prekey,
          public_keys: pk, opk_pub: out.consumed, opks_remaining: out.remaining,
          ik_sign_pub: pk.ik_sign_pub, ik_dh_pub: pk.ik_dh_pub, spk_pub: pk.spk_pub, spk_signature: pk.spk_signature });
      }
      if (method === 'POST' && path === '/v1/envelopes') {
        const forbidden = checkForbidden(body);
        if (forbidden) throw new ApiError(400, 'PRIVATE_DATA_REJECTED', `field '${forbidden}' must never be sent to a relay`);
        const sender = parseAddress(body.sender), recipient = parseAddress(body.recipient);
        if (!sender) throw new ApiError(400, 'INVALID_SENDER', "sender must be 'username:device'");
        if (!recipient) throw new ApiError(400, 'INVALID_RECIPIENT', "recipient must be 'username:device'");
        if (typeof body.ciphertext !== 'string' || !body.ciphertext) throw new ApiError(400, 'MISSING_CIPHERTEXT', 'ciphertext (base64) is required');
        if (body.ciphertext.length > MAX_CIPHERTEXT_CHARS) throw new ApiError(400, 'ENVELOPE_TOO_LARGE', 'ciphertext exceeds 1048576 chars');
        if (!isB64(body.ciphertext)) throw new ApiError(400, 'INVALID_CIPHERTEXT', 'ciphertext must be valid base64');
        await requireRecipient(recipient[0], recipient[1]);
        const env = { envelope_id: body.envelope_id || ('env-' + Math.random().toString(36).slice(2) + Date.now().toString(36)),
          sender: body.sender, sender_username: sender[0], sender_device: sender[1],
          recipient: body.recipient, recipient_username: recipient[0], recipient_device: recipient[1],
          ciphertext: body.ciphertext, ciphertext_encoding: 'base64', protocol_version: body.protocol_version || 'v1',
          timestamp: new Date().toISOString() };
        for (const k of Object.keys(body)) if (!(k in env)) env[k] = body[k];
        await store.enqueue(env);
        return ok(201, { envelope_id: env.envelope_id, sender: env.sender, recipient: env.recipient, timestamp: env.timestamp, queued: true });
      }
      if (method === 'GET' && path === '/v1/inbox') {
        const addr = parseAddress(url.searchParams.get('recipient'));
        if (!addr) throw new ApiError(400, 'INVALID_ADDRESS', "give recipient='username:device'");
        await requireRecipient(addr[0], addr[1]);
        const envelopes = await store.popAll(addr[0], addr[1]);
        return ok(200, { recipient: addr.join(':'), envelopes, delivered_count: envelopes.length });
      }
      if (method === 'GET' && path === '/v1/inbox/count') {
        const addr = parseAddress(url.searchParams.get('recipient'));
        if (!addr) throw new ApiError(400, 'INVALID_ADDRESS', "give recipient='username:device'");
        await requireRecipient(addr[0], addr[1]);
        return ok(200, { recipient: addr.join(':'), queued: await store.count(addr[0], addr[1]) });
      }
      if ((method === 'POST' || method === 'DELETE') && parts.length === 5 && parts[0] === 'v1' && parts[1] === 'devices' && parts[4] === 'revoke') {
        const existed = await store.revoke(parts[2], parts[3]);
        return ok(200, { username: parts[2], device: parts[3], address: parts[2] + ':' + parts[3], revoked: true, was_registered: existed, queued_envelopes_dropped: true });
      }
      throw new ApiError(404, 'NOT_FOUND', 'unknown route');
    } catch (e) { return err(e); }
  }
  return { handle, store, limiter };
}

// Cloudflare Workers entry point (module format). In production,
// env.DB is the D1 binding from wrangler.toml; without it the
// handler falls back to a per-isolate in-memory store (dev only).
export default {
  async fetch(request, env) {
    const store = env && env.DB ? createD1Store(env.DB) : new InMemoryStore();
    const rateStore = env && env.DB ? createD1RateStore(env.DB) : mapRateStore();
    const { handle } = createHandler({ store, rateStore });
    const res = await handle({ method: request.method, url: request.url,
      headers: request.headers, json: async () => { try { return await request.json(); } catch { return {}; } } });
    return new Response(JSON.stringify(res.body), { status: res.status,
      headers: { 'Content-Type': 'application/json' } });
  }
};
