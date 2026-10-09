"""SQLite 存储：服务器存公钥与离线信封；客户端用口令封装私钥和棘轮状态。"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.double_ratchet import RatchetState
from src.prekeys import IdentityKeys, OneTimePrekey, SignedPrekey
from src.protocol import b64d, b64e

PBKDF2_ITERS = 600_000
SALT_LEN = 16
KEY_LEN = 32
NONCE_LEN = 12


def derive_vault_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    ).derive(password.encode("utf-8"))


def encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], None)


def _identity_to_json(identity: IdentityKeys) -> bytes:
    obj = {
        "username": identity.username,
        "ik_sign_priv": b64e(identity.ik_sign_priv),
        "ik_sign_pub": b64e(identity.ik_sign_pub),
        "ik_dh_priv": b64e(identity.ik_dh_priv),
        "ik_dh_pub": b64e(identity.ik_dh_pub),
        "spk": {
            "priv": b64e(identity.spk.priv),
            "pub": b64e(identity.spk.pub),
            "signature": b64e(identity.spk.signature),
            "created": identity.spk.created,
        },
        "opks": [{"priv": b64e(o.priv), "pub": b64e(o.pub)} for o in identity.opks],
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _identity_from_json(raw: bytes) -> IdentityKeys:
    obj = json.loads(raw.decode("utf-8"))
    spk = obj["spk"]
    return IdentityKeys(
        username=obj["username"],
        ik_sign_priv=b64d(obj["ik_sign_priv"]) or b"",
        ik_sign_pub=b64d(obj["ik_sign_pub"]) or b"",
        ik_dh_priv=b64d(obj["ik_dh_priv"]) or b"",
        ik_dh_pub=b64d(obj["ik_dh_pub"]) or b"",
        spk=SignedPrekey(
            priv=b64d(spk["priv"]) or b"",
            pub=b64d(spk["pub"]) or b"",
            signature=b64d(spk["signature"]) or b"",
            created=float(spk["created"]),
        ),
        opks=[
            OneTimePrekey(priv=b64d(o["priv"]) or b"", pub=b64d(o["pub"]) or b"")
            for o in obj.get("opks") or []
        ],
    )


def _state_to_json(state: RatchetState) -> bytes:
    rec = state.to_record()
    obj = {
        "rk": b64e(rec["rk"]),
        "local_user": rec["local_user"],
        "remote_user": rec["remote_user"],
        "dhs_priv": b64e(rec["dhs_priv"]),
        "dhs_pub": b64e(rec["dhs_pub"]),
        "dhr_pub": b64e(rec["dhr_pub"]),
        "cks": b64e(rec["cks"]),
        "ckr": b64e(rec["ckr"]),
        "ns": rec["ns"],
        "nr": rec["nr"],
        "pns": rec["pns"],
        "skipped": [[b64e(k), b64e(v)] for k, v in rec["skipped"].items()],
        "seen": [b64e(k) for k in rec["seen"]],
        "dh_ratchet_count": rec["dh_ratchet_count"],
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _state_from_json(raw: bytes) -> RatchetState:
    obj = json.loads(raw.decode("utf-8"))
    skipped = {b64d(k) or b"": b64d(v) or b"" for k, v in obj.get("skipped") or []}
    seen = {b64d(k) or b"" for k in obj.get("seen") or []}
    return RatchetState.from_record(
        {
            "rk": b64d(obj["rk"]) or b"",
            "local_user": obj["local_user"],
            "remote_user": obj["remote_user"],
            "dhs_priv": b64d(obj.get("dhs_priv")),
            "dhs_pub": b64d(obj.get("dhs_pub")),
            "dhr_pub": b64d(obj.get("dhr_pub")),
            "cks": b64d(obj.get("cks")),
            "ckr": b64d(obj.get("ckr")),
            "ns": obj.get("ns", 0),
            "nr": obj.get("nr", 0),
            "pns": obj.get("pns", 0),
            "skipped": skipped,
            "seen": seen,
            "dh_ratchet_count": obj.get("dh_ratchet_count", 0),
        }
    )


class ClientStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key: bytes | None = None
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault (
                name TEXT PRIMARY KEY,
                blob BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                peer TEXT PRIMARY KEY,
                blob BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conv TEXT NOT NULL,
                sender TEXT NOT NULL,
                body TEXT NOT NULL,
                ts REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                name TEXT PRIMARY KEY,
                members TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peers (
                username TEXT PRIMARY KEY,
                ik_sign_pub BLOB NOT NULL,
                ik_dh_pub BLOB NOT NULL
            );
            """
        )
        self.conn.commit()

    def exists(self) -> bool:
        row = self.conn.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
        return row is not None

    def create(self, password: str, identity: IdentityKeys) -> None:
        salt = os.urandom(SALT_LEN)
        self._key = derive_vault_key(password, salt)
        self.conn.execute("INSERT INTO meta(k, v) VALUES('salt', ?)", (salt,))
        self.conn.commit()
        self.save_identity(identity)

    def unlock(self, password: str) -> IdentityKeys:
        row = self.conn.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
        if not row:
            raise RuntimeError("本地还没有身份，请先注册")
        self._key = derive_vault_key(password, row[0])
        return self.load_identity()

    def _require_key(self) -> bytes:
        if self._key is None:
            raise RuntimeError("保险库未解锁")
        return self._key

    def save_identity(self, identity: IdentityKeys) -> None:
        blob = encrypt_blob(self._require_key(), _identity_to_json(identity))
        self.conn.execute(
            "INSERT OR REPLACE INTO vault(name, blob) VALUES('identity', ?)",
            (blob,),
        )
        self.conn.commit()

    def load_identity(self) -> IdentityKeys:
        row = self.conn.execute("SELECT blob FROM vault WHERE name='identity'").fetchone()
        if not row:
            raise RuntimeError("身份密文缺失")
        return _identity_from_json(decrypt_blob(self._require_key(), row[0]))

    def save_session(self, peer: str, state: RatchetState) -> None:
        blob = encrypt_blob(self._require_key(), _state_to_json(state))
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions(peer, blob) VALUES(?, ?)",
            (peer, blob),
        )
        self.conn.commit()

    def load_session(self, peer: str) -> RatchetState | None:
        row = self.conn.execute(
            "SELECT blob FROM sessions WHERE peer=?", (peer,)
        ).fetchone()
        if not row:
            return None
        return _state_from_json(decrypt_blob(self._require_key(), row[0]))

    def list_sessions(self) -> list[str]:
        rows = self.conn.execute("SELECT peer FROM sessions").fetchall()
        return [r[0] for r in rows]

    def add_history(self, conv: str, sender: str, body: str) -> None:
        self.conn.execute(
            "INSERT INTO history(conv, sender, body, ts) VALUES(?,?,?,?)",
            (conv, sender, body, time.time()),
        )
        self.conn.commit()

    def get_history(self, conv: str, limit: int = 80) -> list[tuple[str, str, float]]:
        rows = self.conn.execute(
            "SELECT sender, body, ts FROM history WHERE conv=? ORDER BY id DESC LIMIT ?",
            (conv, limit),
        ).fetchall()
        return [(r[0], r[1], float(r[2])) for r in reversed(rows)]

    def recent_messages(self) -> list[tuple[str, str, str, float]]:
        rows = self.conn.execute(
            """
            SELECT h.conv, h.sender, h.body, h.ts
            FROM history h
            INNER JOIN (
                SELECT conv, MAX(id) AS id FROM history GROUP BY conv
            ) t ON h.id = t.id
            ORDER BY h.id DESC
            """
        ).fetchall()
        return [(r[0], r[1], r[2], float(r[3])) for r in rows]

    def save_group(self, name: str, members: list[str]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO groups(name, members) VALUES(?, ?)",
            (name, json.dumps(members, ensure_ascii=False)),
        )
        self.conn.commit()

    def load_groups(self) -> dict[str, list[str]]:
        rows = self.conn.execute("SELECT name, members FROM groups").fetchall()
        return {n: json.loads(m) for n, m in rows}

    def save_peer(self, username: str, ik_sign_pub: bytes, ik_dh_pub: bytes) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO peers(username, ik_sign_pub, ik_dh_pub) VALUES(?,?,?)",
            (username, ik_sign_pub, ik_dh_pub),
        )
        self.conn.commit()

    def load_peer(self, username: str) -> tuple[bytes, bytes] | None:
        row = self.conn.execute(
            "SELECT ik_sign_pub, ik_dh_pub FROM peers WHERE username=?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return row[0], row[1]

    def close(self) -> None:
        self.conn.close()


class ServerStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                ik_sign_pub BLOB NOT NULL,
                ik_dh_pub BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS signed_prekeys (
                username TEXT PRIMARY KEY,
                spk_pub BLOB NOT NULL,
                spk_sig BLOB NOT NULL,
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                opk_pub BLOB NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS offline_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                payload TEXT NOT NULL,
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                name TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_name TEXT NOT NULL,
                username TEXT NOT NULL,
                PRIMARY KEY (group_name, username)
            );
            """
        )
        self.conn.commit()

    def user_exists(self, username: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        return row is not None

    def create_user(
        self,
        username: str,
        ik_sign_pub: bytes,
        ik_dh_pub: bytes,
        spk_pub: bytes,
        spk_sig: bytes,
        spk_created: float,
        opks: list[bytes],
    ) -> None:
        self.conn.execute(
            "INSERT INTO users(username, ik_sign_pub, ik_dh_pub) VALUES(?,?,?)",
            (username, ik_sign_pub, ik_dh_pub),
        )
        self.conn.execute(
            "INSERT INTO signed_prekeys(username, spk_pub, spk_sig, created) VALUES(?,?,?,?)",
            (username, spk_pub, spk_sig, spk_created),
        )
        for pub in opks:
            self.conn.execute(
                "INSERT INTO one_time_prekeys(username, opk_pub) VALUES(?,?)",
                (username, pub),
            )
        self.conn.commit()

    def get_user(self, username: str) -> tuple[bytes, bytes] | None:
        row = self.conn.execute(
            "SELECT ik_sign_pub, ik_dh_pub FROM users WHERE username=?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return row[0], row[1]

    def list_users(self) -> list[str]:
        rows = self.conn.execute("SELECT username FROM users ORDER BY username").fetchall()
        return [r[0] for r in rows]

    def upload_prekeys(
        self,
        username: str,
        opks: list[bytes],
        spk: tuple[bytes, bytes, float] | None = None,
    ) -> None:
        if spk:
            self.conn.execute(
                "INSERT OR REPLACE INTO signed_prekeys(username, spk_pub, spk_sig, created) VALUES(?,?,?,?)",
                (username, spk[0], spk[1], spk[2]),
            )
        for pub in opks:
            try:
                self.conn.execute(
                    "INSERT INTO one_time_prekeys(username, opk_pub) VALUES(?,?)",
                    (username, pub),
                )
            except sqlite3.IntegrityError:
                continue
        self.conn.commit()

    def fetch_bundle(self, username: str) -> dict[str, Any] | None:
        user = self.get_user(username)
        if not user:
            return None
        ik_sign_pub, ik_dh_pub = user
        spk = self.conn.execute(
            "SELECT spk_pub, spk_sig, created FROM signed_prekeys WHERE username=?",
            (username,),
        ).fetchone()
        if not spk:
            return None
        opk_row = self.conn.execute(
            "SELECT id, opk_pub FROM one_time_prekeys WHERE username=? ORDER BY id LIMIT 1",
            (username,),
        ).fetchone()
        opk_pub = None
        if opk_row:
            self.conn.execute("DELETE FROM one_time_prekeys WHERE id=?", (opk_row[0],))
            self.conn.commit()
            opk_pub = opk_row[1]
        else:
            self.conn.commit()
        return {
            "ik_sign_pub": ik_sign_pub,
            "ik_dh_pub": ik_dh_pub,
            "spk_pub": spk[0],
            "spk_sig": spk[1],
            "spk_created": spk[2],
            "opk_pub": opk_pub,
        }

    def enqueue_offline(self, recipient: str, payload: str) -> None:
        self.conn.execute(
            "INSERT INTO offline_queue(recipient, payload, created) VALUES(?,?,?)",
            (recipient, payload, time.time()),
        )
        self.conn.commit()

    def drain_offline(self, recipient: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT id, payload FROM offline_queue WHERE recipient=? ORDER BY id",
            (recipient,),
        ).fetchall()
        if rows:
            ids = [r[0] for r in rows]
            self.conn.executemany(
                "DELETE FROM offline_queue WHERE id=?", [(i,) for i in ids]
            )
            self.conn.commit()
        return [r[1] for r in rows]

    def create_group(self, name: str, members: list[str]) -> None:
        self.conn.execute("INSERT INTO groups(name) VALUES(?)", (name,))
        for u in members:
            self.conn.execute(
                "INSERT INTO group_members(group_name, username) VALUES(?,?)",
                (name, u),
            )
        self.conn.commit()

    def group_exists(self, name: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM groups WHERE name=?", (name,)).fetchone()
        return row is not None

    def group_members(self, name: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT username FROM group_members WHERE group_name=? ORDER BY username",
            (name,),
        ).fetchall()
        return [r[0] for r in rows]

    def add_group_member(self, name: str, username: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO group_members(group_name, username) VALUES(?,?)",
            (name, username),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
