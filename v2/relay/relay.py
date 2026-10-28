#!/usr/bin/env python3
"""
ECNUchat v2 relay — local development relay (HTTP JSON, NOT WebSocket).

Single-file, Python standard library only. No pip install required.

What this is
------------
A dumb mailbox, per ~/workspace/ecnu-chat-v2/PLAN.md:

* public-key directory: register/update a device's public keys
  (``username:device``), list devices for a username;
* offline ciphertext-envelope store: store opaque envelopes for
  offline recipients, deliver on request, delete after delivery;
* online forwarding (HTTP dev substitute): if the recipient device
  currently has a long-poll request pending, the envelope wakes that
  request immediately; otherwise it is queued for a later fetch;
* device revocation: a revoked device stops receiving new messages
  and its queued envelopes are dropped.

What this is NOT (see README.md for the full list)
--------------------------------------------------
* It does NOT decrypt anything. Envelopes are opaque base64.
  The relay never parses ciphertext, never holds a private key,
  never stores a password, and never logs ciphertext or plaintext.
  Logs contain only sender, recipient, envelope size and timestamp.
* It does NOT speak WebSocket. This local relay uses HTTP JSON as a
  development substitute with the same envelope fields. A WebSocket
  production variant is a TODO (see README.md). Do not claim this
  file is a WebSocket server.
* It does NOT do TLS/WSS. It runs plain HTTP for local development
  only (default 127.0.0.1:8765, matching v1). In production, TLS
  must be terminated by the deployment (reverse proxy / Cloudflare);
  never expose this plain-HTTP server to the internet.
* It does NOT authenticate anyone. There is no password, token or
  signature check in this dev relay: anyone who knows a
  ``username:device`` can register it or send to it. That is
  acceptable for local development only and is a known gap for
  production, not a feature.

Run
---
    python3 relay.py
    python3 relay.py --host 127.0.0.1 --port 8765
    python3 relay.py --db relay.db          # SQLite file backend
    ECNU_RELAY_HOST=127.0.0.1 ECNU_RELAY_PORT=8765 python3 relay.py

Storage backends
----------------
* Default: in-memory (data is lost when the process stops).
* ``--db <path>``: SQLite file backend (same API, data persists
  across restarts). Queued envelopes and the device directory are
  stored; pending long-polls are always in-memory by nature.

Envelope format
---------------
The v1 envelope format is frozen (PLAN.md principle 1). This relay
treats the envelope payload as opaque: it requires only the routing
fields (``sender``, ``recipient``, ``ciphertext``) and stores every
other field verbatim, returning it unchanged on delivery. It does
not interpret, validate or re-encode any crypto field beyond
checking that ``ciphertext`` is well-formed base64 and under the
size limit. See README.md for the full field list.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
PROTOCOL_VERSION = "v1"
MAX_CIPHERTEXT_CHARS = 1_048_576  # 1 MiB of base64 text
MAX_WAIT_SECONDS = 30.0
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,20}$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

# Top-level (or nested public_keys) field names this relay refuses to
# accept. A private key must never leave a device, so a client that
# tries to upload one gets a hard rejection, not silent storage.
FORBIDDEN_FIELDS = {
    "private_key", "privatekey", "secret_key", "password",
    "passphrase", "seed", "mnemonic",
}

log = logging.getLogger("ecnu-relay")


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_address(value: str | None) -> tuple[str, str] | None:
    """Parse 'username:device' into (username, device), or None."""
    if not value or not isinstance(value, str):
        return None
    if value.count(":") != 1:
        return None
    username, device = value.split(":", 1)
    if not USERNAME_RE.match(username) or not DEVICE_RE.match(device):
        return None
    return username, device


def check_no_forbidden(obj: object) -> str | None:
    """Return the first forbidden field name found, or None.

    Exact matches against FORBIDDEN_FIELDS, plus any field ending
    in ``_seed``: a PQ seed (``pq_seed``) is private-key material
    exactly like a classical seed, and an exact-match list alone
    would have let ``pq_seed`` through (found by the PQ wiring
    test). No legitimate relay field ends in ``_seed``.
    """
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in FORBIDDEN_FIELDS or key.endswith("_seed"):
                return key
            found = check_no_forbidden(val)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = check_no_forbidden(item)
            if found:
                return found
    return None


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


# ---------------------------------------------------------------- stores

class MemoryStore:
    """In-memory device directory + envelope queues + revocation set."""

    def __init__(self) -> None:
        self.devices: dict[tuple[str, str], dict] = {}
        self.queues: dict[tuple[str, str], list[dict]] = {}
        self.revoked: dict[tuple[str, str], dict] = {}

    def register(self, device: dict) -> dict:
        key = (device["username"], device["device"])
        self.revoked.pop(key, None)  # explicit re-register = new device
        existing = self.devices.get(key)
        if existing:
            device["registered_at"] = existing["registered_at"]
        self.devices[key] = device
        self.queues.setdefault(key, [])
        return device

    def list_devices(self, username: str) -> list[dict]:
        return [d for (u, _), d in self.devices.items() if u == username]

    def get_device(self, username: str, device: str) -> dict | None:
        return self.devices.get((username, device))

    def revoke(self, username: str, device: str) -> bool:
        key = (username, device)
        existed = key in self.devices
        self.devices.pop(key, None)
        self.queues.pop(key, None)  # queued envelopes are dropped
        self.revoked[key] = {"username": username, "device": device,
                             "revoked_at": now_iso()}
        return existed

    def is_revoked(self, username: str, device: str) -> bool:
        return (username, device) in self.revoked

    def enqueue(self, envelope: dict) -> None:
        key = (envelope["recipient_username"], envelope["recipient_device"])
        self.queues.setdefault(key, []).append(envelope)

    def pop_all(self, username: str, device: str) -> list[dict]:
        return self.queues.pop((username, device), [])

    def count(self, username: str, device: str) -> int:
        return len(self.queues.get((username, device), []))


class SQLiteStore:
    """SQLite backend with the same interface as MemoryStore."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    username TEXT NOT NULL, device TEXT NOT NULL,
                    data TEXT NOT NULL,
                    PRIMARY KEY (username, device)
                );
                CREATE TABLE IF NOT EXISTS envelopes (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL,
                    device TEXT NOT NULL, data TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked (
                    username TEXT NOT NULL, device TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    PRIMARY KEY (username, device)
                );
                """
            )
            self.conn.commit()

    def register(self, device: dict) -> dict:
        key = (device["username"], device["device"])
        with self._lock:
            old = self.conn.execute(
                "SELECT data FROM devices WHERE username=? AND device=?",
                key).fetchone()
            if old:
                device["registered_at"] = json.loads(old["data"])["registered_at"]
            self.conn.execute(
                "INSERT OR REPLACE INTO devices VALUES (?,?,?)",
                (key[0], key[1], json.dumps(device)))
            self.conn.execute(
                "DELETE FROM revoked WHERE username=? AND device=?", key)
            self.conn.commit()
        return device

    def list_devices(self, username: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT data FROM devices WHERE username=? ORDER BY device",
                (username,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def get_device(self, username: str, device: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT data FROM devices WHERE username=? AND device=?",
                (username, device)).fetchone()
        return json.loads(row["data"]) if row else None

    def revoke(self, username: str, device: str) -> bool:
        with self._lock:
            existed = self.conn.execute(
                "SELECT 1 FROM devices WHERE username=? AND device=?",
                (username, device)).fetchone() is not None
            self.conn.execute(
                "DELETE FROM devices WHERE username=? AND device=?",
                (username, device))
            self.conn.execute(
                "DELETE FROM envelopes WHERE username=? AND device=?",
                (username, device))
            self.conn.execute(
                "INSERT OR REPLACE INTO revoked VALUES (?,?,?)",
                (username, device, now_iso()))
            self.conn.commit()
        return existed

    def is_revoked(self, username: str, device: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM revoked WHERE username=? AND device=?",
                (username, device)).fetchone()
        return row is not None

    def enqueue(self, envelope: dict) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO envelopes VALUES (?,?,?,?,?)",
                (envelope["envelope_id"],
                 envelope["recipient_username"],
                 envelope["recipient_device"],
                 json.dumps(envelope),
                 time.time()))
            self.conn.commit()

    def pop_all(self, username: str, device: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT data FROM envelopes WHERE username=? AND device=? "
                "ORDER BY created_at",
                (username, device)).fetchall()
            self.conn.execute(
                "DELETE FROM envelopes WHERE username=? AND device=?",
                (username, device))
            self.conn.commit()
        return [json.loads(r["data"]) for r in rows]

    def count(self, username: str, device: str) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM envelopes "
                "WHERE username=? AND device=?",
                (username, device)).fetchone()
        return int(row["n"])


# ---------------------------------------------------------------- relay

class Relay:
    """Business logic; transport-independent except for long-polling."""

    def __init__(self, store) -> None:
        self.store = store
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        # Recipients with at least one long-poll request currently waiting.
        self.waiters: dict[tuple[str, str], int] = {}

    # -- devices ------------------------------------------------------
    def register_device(self, body: dict) -> dict:
        forbidden = check_no_forbidden(body)
        if forbidden:
            raise ApiError(400, "PRIVATE_DATA_REJECTED",
                           f"field '{forbidden}' must never be sent to a relay")
        username = body.get("username")
        device = body.get("device")
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise ApiError(400, "INVALID_USERNAME",
                           "username must be 3-20 chars: letters, digits, _ . -")
        if not isinstance(device, str) or not DEVICE_RE.match(device):
            raise ApiError(400, "INVALID_DEVICE",
                           "device must be 1-64 chars: letters, digits, _ . -")
        now = now_iso()
        record = {
            "username": username,
            "device": device,
            "address": f"{username}:{device}",
            # Canonical public-key fields. Clients may also (or instead)
            # pass a "public_keys" object; both are stored verbatim.
            "identity_key": body.get("identity_key"),
            "signed_prekey": body.get("signed_prekey"),
            "one_time_prekeys": body.get("one_time_prekeys"),
            "public_keys": body.get("public_keys"),
            "registered_at": now,
            "updated_at": now,
        }
        # Preserve any extra public fields the client sent, except the
        # ones already handled, so future key types are not dropped.
        for key, val in body.items():
            if key not in record and key not in ("username", "device"):
                record[key] = val
        with self.lock:
            saved = self.store.register(record)
            saved = dict(saved)
            saved["online"] = self.waiters.get((username, device), 0) > 0
        log.info("register username=%s device=%s", username, device)
        return saved

    def list_devices(self, username: str) -> dict:
        if not USERNAME_RE.match(username):
            raise ApiError(400, "INVALID_USERNAME",
                           "username must be 3-20 chars: letters, digits, _ . -")
        with self.lock:
            devices = [dict(d) for d in self.store.list_devices(username)]
            for d in devices:
                d["online"] = self.waiters.get(
                    (d["username"], d["device"]), 0) > 0
        return {"username": username, "devices": devices}

    def fetch_bundle(self, username: str, device: str) -> dict:
        """Return one device's bundle, consuming exactly one OPK.

        Mirrors v1's fetch_bundle (store.py deletes one classical OPK
        row per fetch): the returned bundle's ``opk_pub`` is the
        consumed key, and it is removed from every pool field in the
        stored record before returning, so it is never re-served as
        fresh. Device listing (list_devices) does NOT consume; only
        this endpoint does, and only an initiator fetching a bundle
        to start a session should call it (a receiver verifying a
        sender's identity must use the non-consuming listing).
        If the pool is empty, opk_pub is None (v1 allows an initial
        message without DH4); the caller must not invent an OPK.

        PQ analogue (same rule, separate pool): when the stored
        bundle carries PQ fields (``pq_pub`` / ``pq_sig`` /
        ``pq_opks`` inside ``public_keys``), exactly one PQOPK is
        consumed per fetch and returned as ``pq_opk`` (an object
        ``{pub, sig}``) with ``pq_opk_pub`` / ``pq_opk_sig``
        conveniences and ``pq_opks_remaining``. The consumed PQOPK
        is removed from the stored pool before returning, so it is
        never re-served as fresh; classical OPK consumption is
        unchanged and independent. If the peer publishes a PQK but
        no PQOPK, ``pq_opk`` is None and ``pq_opks_remaining`` is 0
        (the initiator then falls back to encapsulating to the
        long-term PQK, per v1). If the peer publishes no PQ fields
        at all, ``pq_opk`` is None and ``pq_opks_remaining`` is
        None. PQOPK entries are public keys + signatures only; a
        PQ seed is a forbidden field and is rejected at register.
        """
        if not USERNAME_RE.match(username) or not DEVICE_RE.match(device):
            raise ApiError(400, "INVALID_ADDRESS",
                           "username:device is not well-formed")
        with self.lock:
            self._require_recipient(username, device)
            record = dict(self.store.get_device(username, device))
            # Top-level pool field.
            pool = record.get("one_time_prekeys")
            consumed = None
            remaining_top = None
            if isinstance(pool, list) and pool:
                consumed = pool.pop(0)
                remaining_top = list(pool)
                record["one_time_prekeys"] = remaining_top
            # public_keys object: pool list, then single-opk fallback.
            pk = record.get("public_keys")
            remaining_pk = None
            if isinstance(pk, dict):
                pk = dict(pk)
                opks = pk.get("opks")
                if isinstance(opks, list) and opks:
                    if consumed is None:
                        consumed = opks.pop(0)
                    else:
                        opks.pop(0)
                    remaining_pk = list(opks)
                    pk["opks"] = remaining_pk
                    pk["opk_pub"] = remaining_pk[0] if remaining_pk else None
                elif pk.get("opk_pub") is not None:
                    if consumed is None:
                        consumed = pk["opk_pub"]
                    pk["opk_pub"] = None
                record["public_keys"] = pk
            # PQ pool (inside public_keys only): consume exactly one
            # PQOPK, mirroring the classical rule above. The caller
            # MUST encapsulate to the returned pq_opk, never to a
            # key still sitting in the returned public_keys pool:
            # after this pop, public_keys.pq_opks holds only the
            # unconsumed remainder. A single-object pq_opk /
            # pq_opk_sig fallback is consumed the same way.
            consumed_pq = None
            remaining_pq = None
            pq_present = False
            if isinstance(pk, dict):
                pq_present = any(k in pk for k in
                                 ("pq_pub", "pq_sig", "pq_opks", "pq_opk"))
                pq_pool = pk.get("pq_opks")
                if isinstance(pq_pool, list):
                    pq_pool = list(pq_pool)
                    if pq_pool:
                        consumed_pq = pq_pool.pop(0)
                    remaining_pq = len(pq_pool)
                    pk["pq_opks"] = pq_pool
                elif pk.get("pq_opk") is not None:
                    consumed_pq = {"pub": pk.get("pq_opk"),
                                   "sig": pk.get("pq_opk_sig")}
                    pk["pq_opk"] = None
                    pk["pq_opk_sig"] = None
                    remaining_pq = 0
                elif pq_present:
                    remaining_pq = 0
                record["public_keys"] = pk
            # Persist the consumed state (register preserves
            # registered_at and queued envelopes; the device is
            # registered, not revoked, so revocation is untouched).
            self.store.register(record)
            remaining = 0
            if remaining_top is not None:
                remaining = len(remaining_top)
            elif remaining_pk is not None:
                remaining = len(remaining_pk)
            bundle = {
                "identity_key": record.get("identity_key"),
                "signed_prekey": record.get("signed_prekey"),
                "spk_created": (pk or {}).get("spk_created"),
                "public_keys": pk,
                "opk_pub": consumed,
                "opks_remaining": remaining,
                "pq_pub": (pk or {}).get("pq_pub"),
                "pq_sig": (pk or {}).get("pq_sig"),
                "pq_opk": consumed_pq,
                "pq_opk_pub": consumed_pq.get("pub") if isinstance(consumed_pq, dict) else None,
                "pq_opk_sig": consumed_pq.get("sig") if isinstance(consumed_pq, dict) else None,
                "pq_opks_remaining": remaining_pq,
            }
            if isinstance(pk, dict):
                bundle["ik_sign_pub"] = pk.get("ik_sign_pub")
                bundle["ik_dh_pub"] = pk.get("ik_dh_pub")
                bundle["spk_pub"] = pk.get("spk_pub")
                bundle["spk_signature"] = pk.get("spk_signature")
        log.info("bundle fetch username=%s device=%s opk_consumed=%s "
                 "opks_remaining=%d pq_opk_consumed=%s "
                 "pq_opks_remaining=%s",
                 username, device, consumed is not None, remaining,
                 consumed_pq is not None, remaining_pq)
        return {"username": username, "device": device,
                "address": f"{username}:{device}", **bundle}

    def revoke_device(self, username: str, device: str) -> dict:
        if not USERNAME_RE.match(username) or not DEVICE_RE.match(device):
            raise ApiError(400, "INVALID_ADDRESS",
                           "username:device is not well-formed")
        with self.lock:
            existed = self.store.revoke(username, device)
        log.info("revoke username=%s device=%s existed=%s",
                 username, device, existed)
        # Revoking a never-registered device still records the
        # revocation so later sends to it get 410, not a misleading 404.
        return {"username": username, "device": device,
                "address": f"{username}:{device}",
                "revoked": True, "was_registered": existed,
                "queued_envelopes_dropped": True,
                "revoked_at": now_iso()}

    def _require_recipient(self, username: str, device: str) -> None:
        if self.store.is_revoked(username, device):
            raise ApiError(410, "DEVICE_REVOKED",
                           "device is revoked; it receives no new messages")
        if self.store.get_device(username, device) is None:
            raise ApiError(404, "DEVICE_NOT_FOUND",
                           "recipient device is not registered")

    # -- envelopes ----------------------------------------------------
    def send_envelope(self, body: dict) -> dict:
        forbidden = check_no_forbidden(body)
        if forbidden:
            raise ApiError(400, "PRIVATE_DATA_REJECTED",
                           f"field '{forbidden}' must never be sent to a relay")
        sender = parse_address(body.get("sender"))
        recipient = parse_address(body.get("recipient"))
        if sender is None:
            raise ApiError(400, "INVALID_SENDER",
                           "sender must be 'username:device'")
        if recipient is None:
            raise ApiError(400, "INVALID_RECIPIENT",
                           "recipient must be 'username:device'")
        ciphertext = body.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext:
            raise ApiError(400, "MISSING_CIPHERTEXT",
                           "ciphertext (base64) is required")
        if len(ciphertext) > MAX_CIPHERTEXT_CHARS:
            raise ApiError(400, "ENVELOPE_TOO_LARGE",
                           f"ciphertext exceeds {MAX_CIPHERTEXT_CHARS} chars")
        try:
            base64.b64decode(ciphertext, validate=True)
        except (binascii.Error, ValueError):
            raise ApiError(400, "INVALID_CIPHERTEXT",
                           "ciphertext must be valid base64")
        envelope = {"envelope_id": body.get("envelope_id") or str(uuid.uuid4()),
                    "sender": body["sender"],
                    "sender_username": sender[0],
                    "sender_device": sender[1],
                    "recipient": body["recipient"],
                    "recipient_username": recipient[0],
                    "recipient_device": recipient[1],
                    "ciphertext": ciphertext,
                    "ciphertext_encoding": "base64",
                    "protocol_version": body.get("protocol_version",
                                                PROTOCOL_VERSION),
                    "timestamp": now_iso()}
        # Opaque passthrough: every other client field is stored and
        # returned verbatim. The relay never interprets it.
        reserved = set(envelope)
        for key, val in body.items():
            if key not in reserved:
                envelope[key] = val
        with self.cond:
            self._require_recipient(recipient[0], recipient[1])
            delivered_online = self.waiters.get(recipient, 0) > 0
            self.store.enqueue(envelope)
            self.cond.notify_all()
        # Log metadata only: never ciphertext, never extra payload fields.
        log.info("envelope id=%s sender=%s recipient=%s size=%d "
                 "delivered_online=%s",
                 envelope["envelope_id"], envelope["sender"],
                 envelope["recipient"], len(ciphertext), delivered_online)
        return {"envelope_id": envelope["envelope_id"],
                "sender": envelope["sender"],
                "recipient": envelope["recipient"],
                "timestamp": envelope["timestamp"],
                "delivered_online": delivered_online,
                "queued": not delivered_online}

    def fetch_inbox(self, username: str, device: str,
                    wait_seconds: float = 0.0) -> dict:
        if not USERNAME_RE.match(username) or not DEVICE_RE.match(device):
            raise ApiError(400, "INVALID_ADDRESS",
                           "recipient must be 'username:device'")
        wait_seconds = max(0.0, min(float(wait_seconds), MAX_WAIT_SECONDS))
        key = (username, device)
        deadline = time.monotonic() + wait_seconds
        with self.cond:
            self._require_recipient(username, device)
            envelopes = self.store.pop_all(username, device)
            if not envelopes and wait_seconds > 0:
                self.waiters[key] = self.waiters.get(key, 0) + 1
                try:
                    while not envelopes:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        self.cond.wait(timeout=remaining)
                        # A new send may have been for someone else;
                        # re-check, and re-check revocation on wake.
                        self._require_recipient(username, device)
                        envelopes = self.store.pop_all(username, device)
                finally:
                    self.waiters[key] -= 1
                    if self.waiters[key] <= 0:
                        self.waiters.pop(key, None)
        # Delivery deletes: pop_all already removed them from the store.
        log.info("deliver recipient=%s:%s count=%d",
                 username, device, len(envelopes))
        return {"recipient": f"{username}:{device}",
                "envelopes": envelopes,
                "delivered_count": len(envelopes)}

    def inbox_count(self, username: str, device: str) -> dict:
        if not USERNAME_RE.match(username) or not DEVICE_RE.match(device):
            raise ApiError(400, "INVALID_ADDRESS",
                           "recipient must be 'username:device'")
        with self.lock:
            self._require_recipient(username, device)
            count = self.store.count(username, device)
        return {"recipient": f"{username}:{device}", "queued": count}


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    relay: Relay  # set by main()
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep stdout clean; use logging
        log.debug(fmt, *args)

    # -- helpers ------------------------------------------------------
    def _send_json(self, status: int, obj: dict) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        # CORS (Track D finding): a real browser PWA served from a
        # different origin/port cannot fetch this relay at all without
        # these headers, and its preflight needs do_OPTIONS below.
        # This relay is a dumb public mailbox: it never sees plaintext,
        # so an open CORS policy does not expose message content.
        # A production deployment may restrict the origin instead.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        # Preflight: no body, no routing, just CORS headers.
        try:
            self._drain_body()
        except Exception:
            pass
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _drain_body(self) -> None:
        # Routes that take no body (revoke) must still consume it,
        # otherwise a client sending "{}" on a keep-alive connection
        # desyncs the next request (observed as "Unsupported method
        # ('{}GET')"). This does not parse or validate the body.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(length)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "INVALID_JSON", "request body is not valid JSON")
        if not isinstance(obj, dict):
            raise ApiError(400, "INVALID_JSON", "request body must be a JSON object")
        return obj

    def _path_parts(self) -> list[str]:
        return [unquote(p) for p in urlparse(self.path).path.split("/") if p]

    def _query(self) -> dict[str, list[str]]:
        return parse_qs(urlparse(self.path).query)

    def _recipient_from_query(self, query) -> tuple[str, str]:
        raw = (query.get("recipient") or [None])[0]
        if raw:
            addr = parse_address(raw)
            if addr:
                return addr
        user = (query.get("recipient_username") or [None])[0]
        dev = (query.get("recipient_device") or [None])[0]
        if user and dev:
            addr = parse_address(f"{user}:{dev}")
            if addr:
                return addr
        raise ApiError(400, "INVALID_ADDRESS",
                       "give recipient='username:device' (or "
                       "recipient_username + recipient_device)")

    # -- routing ------------------------------------------------------
    def do_GET(self):
        try:
            self._route("GET")
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.code,
                                         "message": exc.message})
        except BrokenPipeError:
            pass
        except Exception as exc:  # never leak internals / payloads
            log.exception("internal error")
            self._send_json(500, {"error": "INTERNAL_ERROR",
                                  "message": "internal error"})

    def do_POST(self):
        try:
            self._route("POST")
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.code,
                                         "message": exc.message})
        except BrokenPipeError:
            pass
        except Exception:
            log.exception("internal error")
            self._send_json(500, {"error": "INTERNAL_ERROR",
                                  "message": "internal error"})

    def do_DELETE(self):
        try:
            self._route("DELETE")
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.code,
                                         "message": exc.message})
        except BrokenPipeError:
            pass
        except Exception:
            log.exception("internal error")
            self._send_json(500, {"error": "INTERNAL_ERROR",
                                  "message": "internal error"})

    def _route(self, method: str) -> None:
        parts = self._path_parts()
        query = self._query()
        relay = self.relay

        if method == "GET" and parts in ([], ["health"]):
            # GET / and GET /health: service info (no user data).
            self._send_json(200, {
                "status": "ok", "service": "ecnu-chat-v2-relay",
                "transport": "http-json-dev (NOT WebSocket)",
                "protocol_version": PROTOCOL_VERSION,
                "tls": "none-local-dev-only; "
                       "production must terminate TLS at the deployment",
            })
            return

        if method == "GET" and parts == ["v1", "devices"]:
            username = (query.get("username") or [None])[0]
            if not username:
                raise ApiError(400, "MISSING_USERNAME",
                               "query parameter username is required")
            self._send_json(200, relay.list_devices(username))
            return

        if method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "devices"]:
            self._send_json(200, relay.list_devices(parts[2]))
            return

        if method == "POST" and parts == ["v1", "devices", "register"]:
            self._send_json(200, relay.register_device(self._read_json()))
            return

        if method == "POST" and parts == ["v1", "bundles", "fetch"]:
            body = self._read_json()
            raw = body.get("recipient") or body.get("address")
            addr = parse_address(raw) if raw else None
            if addr is None and body.get("username") and body.get("device"):
                addr = parse_address(f"{body['username']}:{body['device']}")
            if addr is None:
                raise ApiError(400, "INVALID_ADDRESS",
                               "give username + device (or recipient='username:device')")
            self._send_json(200, relay.fetch_bundle(addr[0], addr[1]))
            return

        if method == "POST" and len(parts) == 5 and parts[:2] == ["v1", "devices"] \
                and parts[4] == "revoke":
            # POST /v1/devices/<username>/<device>/revoke
            self._drain_body()
            self._send_json(200, relay.revoke_device(parts[2], parts[3]))
            return

        if method == "DELETE" and len(parts) == 4 and parts[:2] == ["v1", "devices"]:
            self._drain_body()
            self._send_json(200, relay.revoke_device(parts[2], parts[3]))
            return

        if method == "POST" and parts == ["v1", "envelopes"]:
            self._send_json(201, relay.send_envelope(self._read_json()))
            return

        if method == "GET" and parts == ["v1", "inbox"]:
            username, device = self._recipient_from_query(query)
            wait = 0.0
            raw_wait = (query.get("wait_seconds") or query.get("wait") or [None])[0]
            if raw_wait is not None:
                try:
                    wait = float(raw_wait)
                except ValueError:
                    raise ApiError(400, "INVALID_WAIT",
                                   "wait_seconds must be a number 0-30")
            self._send_json(200, relay.fetch_inbox(username, device, wait))
            return

        if method == "POST" and parts == ["v1", "inbox", "fetch"]:
            body = self._read_json()
            raw = body.get("recipient")
            addr = parse_address(raw) if raw else None
            if addr is None and body.get("recipient_username") \
                    and body.get("recipient_device"):
                addr = parse_address(
                    f"{body['recipient_username']}:{body['recipient_device']}")
            if addr is None:
                raise ApiError(400, "INVALID_ADDRESS",
                               "give recipient='username:device'")
            wait = body.get("wait_seconds", 0.0)
            try:
                wait = float(wait)
            except (TypeError, ValueError):
                raise ApiError(400, "INVALID_WAIT",
                               "wait_seconds must be a number 0-30")
            self._send_json(200, relay.fetch_inbox(addr[0], addr[1], wait))
            return

        if method == "GET" and parts == ["v1", "inbox", "count"]:
            username, device = self._recipient_from_query(query)
            self._send_json(200, relay.inbox_count(username, device))
            return

        raise ApiError(404, "NOT_FOUND", "unknown route")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ECNUchat v2 local relay (HTTP JSON dev substitute, "
                    "stdlib only). Plain HTTP for local development only.")
    parser.add_argument("--host", default=os.environ.get(
        "ECNU_RELAY_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get(
        "ECNU_RELAY_PORT", str(DEFAULT_PORT))))
    parser.add_argument("--db", default=os.environ.get("ECNU_RELAY_DB", ""),
                        help="optional SQLite file backend (default: in-memory)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    store = SQLiteStore(args.db) if args.db else MemoryStore()
    relay = Relay(store)
    Handler.relay = relay
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    backend = f"sqlite:{args.db}" if args.db else "in-memory"
    print(f"ECNUchat v2 relay listening on http://{args.host}:{args.port} "
          f"(backend={backend})", flush=True)
    print("WARNING: plain HTTP for LOCAL DEVELOPMENT ONLY. "
          "Production requires TLS/WSS terminated by the deployment; "
          "never expose this server to the internet.", flush=True)
    print("This relay does NOT decrypt, does NOT store passwords, "
          "and logs only sender/recipient/size/timestamp metadata.",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
