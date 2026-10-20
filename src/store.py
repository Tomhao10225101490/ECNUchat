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
from src.prekeys import IdentityKeys, OneTimePrekey, PqOneTimePrekey, SignedPrekey
from src.protocol import b64d, b64e, decode_group_state, encode_group_state

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
        "pq_priv": b64e(identity.pq_priv),
        "pq_pub": b64e(identity.pq_pub),
        "pq_sig": b64e(identity.pq_sig),
        "spk": {
            "priv": b64e(identity.spk.priv),
            "pub": b64e(identity.spk.pub),
            "signature": b64e(identity.spk.signature),
            "created": identity.spk.created,
        },
        "opks": [{"priv": b64e(o.priv), "pub": b64e(o.pub)} for o in identity.opks],
        "pq_opks": [
            {"priv": b64e(o.priv), "pub": b64e(o.pub), "sig": b64e(o.signature)}
            for o in identity.pq_opks
        ],
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
        pq_priv=b64d(obj.get("pq_priv")),
        pq_pub=b64d(obj.get("pq_pub")),
        pq_sig=b64d(obj.get("pq_sig")),
        opks=[
            OneTimePrekey(priv=b64d(o["priv"]) or b"", pub=b64d(o["pub"]) or b"")
            for o in obj.get("opks") or []
        ],
        pq_opks=[
            PqOneTimePrekey(
                priv=b64d(o["priv"]) or b"",
                pub=b64d(o["pub"]) or b"",
                signature=b64d(o["sig"]) or b"",
            )
            for o in obj.get("pq_opks") or []
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
        "dhs_pq_ct": b64e(rec["dhs_pq_ct"]),
        "dhr_pub": b64e(rec["dhr_pub"]),
        "remote_pq_pk": b64e(rec["remote_pq_pk"]),
        "cks": b64e(rec["cks"]),
        "ckr": b64e(rec["ckr"]),
        "ns": rec["ns"],
        "nr": rec["nr"],
        "pns": rec["pns"],
        "skipped": [[b64e(k), b64e(v)] for k, v in rec["skipped"].items()],
        "seen": [b64e(k) for k in rec["seen"]],
        "retired_dh": [b64e(k) for k in rec["retired_dh"]],
        "dh_ratchet_count": rec["dh_ratchet_count"],
        "handshake_pq": rec.get("handshake_pq"),
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _state_from_json(raw: bytes) -> RatchetState:
    obj = json.loads(raw.decode("utf-8"))
    skipped = {b64d(k) or b"": b64d(v) or b"" for k, v in obj.get("skipped") or []}
    seen = {b64d(k) or b"" for k in obj.get("seen") or []}
    retired_dh = {b64d(k) or b"" for k in obj.get("retired_dh") or []}
    return RatchetState.from_record(
        {
            "rk": b64d(obj["rk"]) or b"",
            "local_user": obj["local_user"],
            "remote_user": obj["remote_user"],
            "dhs_priv": b64d(obj.get("dhs_priv")),
            "dhs_pub": b64d(obj.get("dhs_pub")),
            "dhs_pq_ct": b64d(obj.get("dhs_pq_ct")),
            "dhr_pub": b64d(obj.get("dhr_pub")),
            "remote_pq_pk": b64d(obj.get("remote_pq_pk")),
            "cks": b64d(obj.get("cks")),
            "ckr": b64d(obj.get("ckr")),
            "ns": obj.get("ns", 0),
            "nr": obj.get("nr", 0),
            "pns": obj.get("pns", 0),
            "skipped": skipped,
            "seen": seen,
            "retired_dh": retired_dh,
            "dh_ratchet_count": obj.get("dh_ratchet_count", 0),
            "handshake_pq": obj.get("handshake_pq"),
        }
    )


class ClientStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key: bytes | None = None
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
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
            CREATE TABLE IF NOT EXISTS outbox (
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
                ik_dh_pub BLOB NOT NULL,
                ik_pq_pub BLOB
            );
            CREATE TABLE IF NOT EXISTS group_chain (
                name TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (name, epoch)
            );
            CREATE TABLE IF NOT EXISTS ui_state (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS message_status (
                local_id TEXT PRIMARY KEY,
                conv TEXT NOT NULL,
                body TEXT NOT NULL,
                state TEXT NOT NULL,
                ts REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_jobs (
                local_id TEXT PRIMARY KEY,
                blob BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incoming_files (
                blob_id TEXT PRIMARY KEY,
                blob BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dropbox (
                id TEXT PRIMARY KEY,
                peer TEXT NOT NULL,
                name TEXT NOT NULL,
                direction TEXT NOT NULL,
                size INTEGER NOT NULL,
                path TEXT NOT NULL,
                created REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_history_conv_id ON history(conv, id);
            CREATE INDEX IF NOT EXISTS idx_history_body ON history(body);
            """
        )
        peers_cols = {
            row[1] for row in self.conn.execute("PRAGMA table_info(peers)")
        }
        if "ik_pq_pub" not in peers_cols:
            self.conn.execute("ALTER TABLE peers ADD COLUMN ik_pq_pub BLOB")
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

    def save_pending_prekeys(self, pubs: list[bytes]) -> None:
        raw = json.dumps([b64e(pub) for pub in pubs], separators=(",", ":")).encode()
        blob = encrypt_blob(self._require_key(), raw)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO vault(name, blob) VALUES('pending_prekeys', ?)",
                (blob,),
            )

    def load_pending_prekeys(self) -> list[bytes]:
        row = self.conn.execute(
            "SELECT blob FROM vault WHERE name='pending_prekeys'"
        ).fetchone()
        if not row:
            return []
        raw = decrypt_blob(self._require_key(), row[0])
        return [b64d(item) or b"" for item in json.loads(raw.decode())]

    def clear_pending_prekeys(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM vault WHERE name='pending_prekeys'")

    def save_pending_pq_opks(self, items: list[tuple[bytes, bytes]]) -> None:
        raw = json.dumps(
            [{"pub": b64e(pub), "sig": b64e(sig)} for pub, sig in items],
            separators=(",", ":"),
        ).encode()
        blob = encrypt_blob(self._require_key(), raw)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO vault(name, blob) VALUES('pending_pq_opks', ?)",
                (blob,),
            )

    def load_pending_pq_opks(self) -> list[tuple[bytes, bytes]]:
        row = self.conn.execute(
            "SELECT blob FROM vault WHERE name='pending_pq_opks'"
        ).fetchone()
        if not row:
            return []
        raw = decrypt_blob(self._require_key(), row[0])
        loaded = json.loads(raw.decode())
        return [(b64d(item["pub"]) or b"", b64d(item["sig"]) or b"") for item in loaded]

    def clear_pending_pq_opks(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM vault WHERE name='pending_pq_opks'")

    def save_session(self, peer: str, state: RatchetState) -> None:
        blob = encrypt_blob(self._require_key(), _state_to_json(state))
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions(peer, blob) VALUES(?, ?)",
            (peer, blob),
        )
        self.conn.commit()

    def save_session_with_outbox(
        self,
        peer: str,
        state: RatchetState,
        payload: dict[str, Any],
        file_job: tuple[str, dict[str, Any]] | None = None,
    ) -> None:
        state_blob = encrypt_blob(self._require_key(), _state_to_json(state))
        payload_blob = encrypt_blob(
            self._require_key(),
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
        job_blob = None
        job_id = None
        if file_job is not None:
            job_id, record = file_job
            job_blob = self._seal_json(record)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions(peer, blob) VALUES(?, ?)",
                (peer, state_blob),
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO outbox(peer, blob) VALUES(?, ?)",
                (peer, payload_blob),
            )
            if job_id is not None:
                self.conn.execute(
                    "INSERT OR REPLACE INTO file_jobs(local_id, blob) VALUES(?, ?)",
                    (job_id, job_blob),
                )

    def _seal_json(self, record: dict[str, Any]) -> bytes:
        raw = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return encrypt_blob(self._require_key(), raw)

    def _open_json(self, blob: bytes) -> dict[str, Any]:
        value = json.loads(decrypt_blob(self._require_key(), blob).decode("utf-8"))
        if not isinstance(value, dict):
            raise RuntimeError("附件任务格式无效")
        return value

    def save_file_job(self, local_id: str, record: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO file_jobs(local_id, blob) VALUES(?, ?)",
                (local_id, self._seal_json(record)),
            )

    def load_file_job(self, local_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT blob FROM file_jobs WHERE local_id=?", (local_id,)
        ).fetchone()
        if not row:
            return None
        return self._open_json(row[0])

    def list_file_jobs(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT blob FROM file_jobs").fetchall()
        return [self._open_json(row[0]) for row in rows]

    def save_incoming_file(self, blob_id: str, record: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO incoming_files(blob_id, blob) VALUES(?, ?)",
                (blob_id, self._seal_json(record)),
            )

    def delete_incoming_file(self, blob_id: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM incoming_files WHERE blob_id=?", (blob_id,))

    def list_incoming_files(self) -> list[tuple[str, dict[str, Any]]]:
        rows = self.conn.execute(
            "SELECT blob_id, blob FROM incoming_files ORDER BY blob_id"
        ).fetchall()
        return [(str(row[0]), self._open_json(row[1])) for row in rows]

    def load_outbox(self, peer: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT blob FROM outbox WHERE peer=?", (peer,)
        ).fetchone()
        if not row:
            return None
        raw = decrypt_blob(self._require_key(), row[0])
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise RuntimeError("待发信封格式无效")
        return value

    def delete_outbox(self, peer: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM outbox WHERE peer=?", (peer,))

    def list_outbox_peers(self) -> list[str]:
        rows = self.conn.execute("SELECT peer FROM outbox ORDER BY peer").fetchall()
        return [str(row[0]) for row in rows]

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

    def search_history(
        self, query: str, conv: str | None = None, limit: int = 50
    ) -> list[tuple[int, str, str, str, float]]:
        query = query.strip()
        if not query:
            return []
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        if conv:
            rows = self.conn.execute(
                """
                SELECT id, conv, sender, body, ts FROM history
                WHERE conv=? AND body LIKE ? ESCAPE '\\'
                ORDER BY id DESC LIMIT ?
                """,
                (conv, pattern, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT id, conv, sender, body, ts FROM history
                WHERE body LIKE ? ESCAPE '\\'
                ORDER BY id DESC LIMIT ?
                """,
                (pattern, limit),
            ).fetchall()
        return [
            (int(row[0]), row[1], row[2], row[3], float(row[4])) for row in rows
        ]

    def save_message_status(
        self, local_id: str, conv: str, body: str, state: str
    ) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO message_status(local_id, conv, body, state, ts)
                VALUES(?,?,?,?,?)
                ON CONFLICT(local_id) DO UPDATE SET
                    conv=excluded.conv,
                    body=excluded.body,
                    state=excluded.state
                """,
                (local_id, conv, body, state, time.time()),
            )

    def update_message_status(self, local_id: str, state: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE message_status SET state=? WHERE local_id=?",
                (state, local_id),
            )

    def pending_message_statuses(
        self,
    ) -> list[tuple[str, str, str, str, float]]:
        rows = self.conn.execute(
            """
            SELECT local_id, conv, body, state, ts FROM message_status
            WHERE state IN ('sending', 'failed')
            ORDER BY ts
            """
        ).fetchall()
        return [(r[0], r[1], r[2], r[3], float(r[4])) for r in rows]

    def save_group(self, name: str, members: list[str]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO groups(name, members) VALUES(?, ?)",
            (name, json.dumps(members, ensure_ascii=False)),
        )
        self.conn.commit()

    def load_groups(self) -> dict[str, list[str]]:
        rows = self.conn.execute("SELECT name, members FROM groups").fetchall()
        return {n: json.loads(m) for n, m in rows}

    def save_group_state(self, state) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO group_chain(name, epoch, state) VALUES(?,?,?)",
            (
                state.name,
                state.epoch,
                json.dumps(
                    encode_group_state(state), ensure_ascii=False, separators=(",", ":")
                ),
            ),
        )
        self.conn.commit()

    def load_group_chain(self, name: str):
        rows = self.conn.execute(
            "SELECT state FROM group_chain WHERE name=? ORDER BY epoch", (name,)
        ).fetchall()
        try:
            return [decode_group_state(json.loads(row[0])) for row in rows]
        except Exception:
            return []

    def latest_group_state(self, name: str):
        chain = self.load_group_chain(name)
        return chain[-1] if chain else None

    def save_peer(
        self,
        username: str,
        ik_sign_pub: bytes,
        ik_dh_pub: bytes,
        ik_pq_pub: bytes | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO peers(username, ik_sign_pub, ik_dh_pub, ik_pq_pub) VALUES(?,?,?,?)",
            (username, ik_sign_pub, ik_dh_pub, ik_pq_pub),
        )
        self.conn.commit()

    def load_peer(self, username: str) -> tuple[bytes, bytes, bytes | None] | None:
        row = self.conn.execute(
            "SELECT ik_sign_pub, ik_dh_pub, ik_pq_pub FROM peers WHERE username=?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return row[0], row[1], row[2]

    def save_unread(self, unread: dict[str, int]) -> None:
        clean = {key: min(999, max(0, int(value))) for key, value in unread.items()}
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO ui_state(k, v) VALUES('unread', ?)",
                (json.dumps(clean, ensure_ascii=False),),
            )

    def load_unread(self) -> dict[str, int]:
        row = self.conn.execute(
            "SELECT v FROM ui_state WHERE k='unread'"
        ).fetchone()
        if not row:
            return {}
        value = json.loads(row[0])
        if not isinstance(value, dict):
            return {}
        return {str(key): int(count) for key, count in value.items()}

    def save_ui_value(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO ui_state(k, v) VALUES(?, ?)",
                (key, value),
            )

    def load_ui_value(self, key: str, default: str = "") -> str:
        row = self.conn.execute(
            "SELECT v FROM ui_state WHERE k=?", (key,)
        ).fetchone()
        return str(row[0]) if row else default


    def add_dropbox(
        self,
        item_id: str,
        peer: str,
        name: str,
        direction: str,
        size: int,
        path: str,
    ) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO dropbox(id, peer, name, direction, size, path, created)
               VALUES(?,?,?,?,?,?,?)""",
            (item_id, peer, name, direction, size, path, time.time()),
        )
        self.conn.commit()

    def list_dropbox(self, limit: int = 40) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT id, peer, name, direction, size, path, created
               FROM dropbox ORDER BY created DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "id": row[0],
                "peer": row[1],
                "name": row[2],
                "direction": row[3],
                "size": row[4],
                "path": row[5],
                "created": row[6],
            }
            for row in rows
        ]

    def close(self) -> None:
        self.conn.close()


class ServerStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-65536")
        self._init()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                ik_sign_pub BLOB NOT NULL,
                ik_dh_pub BLOB NOT NULL,
                pq_pub BLOB,
                pq_sig BLOB
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
            CREATE TABLE IF NOT EXISTS pq_one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                pq_opk_pub BLOB NOT NULL UNIQUE,
                pq_opk_sig BLOB NOT NULL
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
            CREATE TABLE IF NOT EXISTS blobs (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                size INTEGER NOT NULL,
                chunks INTEGER NOT NULL,
                recipients TEXT NOT NULL,
                complete INTEGER NOT NULL DEFAULT 0,
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blob_chunks (
                blob_id TEXT NOT NULL,
                idx INTEGER NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (blob_id, idx)
            );
            CREATE TABLE IF NOT EXISTS blob_downloads (
                blob_id TEXT NOT NULL,
                username TEXT NOT NULL,
                PRIMARY KEY (blob_id, username)
            );
            CREATE TABLE IF NOT EXISTS group_states (
                group_name TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                signer TEXT NOT NULL,
                state_json TEXT NOT NULL,
                PRIMARY KEY (group_name, epoch)
            );
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                bio TEXT NOT NULL,
                avatar TEXT NOT NULL,
                updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS privacy (
                username TEXT PRIMARY KEY,
                require_approval INTEGER NOT NULL,
                moments_visibility TEXT NOT NULL,
                show_online INTEGER NOT NULL,
                searchable INTEGER NOT NULL,
                updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS friendships (
                user_lo TEXT NOT NULL,
                user_hi TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                greeting TEXT NOT NULL,
                updated REAL NOT NULL,
                PRIMARY KEY (user_lo, user_hi)
            );
            CREATE TABLE IF NOT EXISTS moments (
                id TEXT PRIMARY KEY,
                author TEXT NOT NULL,
                body TEXT NOT NULL,
                image TEXT NOT NULL,
                visibility TEXT NOT NULL,
                created REAL NOT NULL,
                deleted INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS moment_likes (
                moment_id TEXT NOT NULL,
                username TEXT NOT NULL,
                created REAL NOT NULL,
                PRIMARY KEY (moment_id, username)
            );
            CREATE TABLE IF NOT EXISTS moment_comments (
                id TEXT PRIMARY KEY,
                moment_id TEXT NOT NULL,
                author TEXT NOT NULL,
                body TEXT NOT NULL,
                created REAL NOT NULL
            );
            """
        )
        user_cols = {
            row[1] for row in self.conn.execute("PRAGMA table_info(users)")
        }
        if "pq_pub" not in user_cols:
            self.conn.execute("ALTER TABLE users ADD COLUMN pq_pub BLOB")
        if "pq_sig" not in user_cols:
            self.conn.execute("ALTER TABLE users ADD COLUMN pq_sig BLOB")
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
        pq_pub: bytes | None,
        pq_sig: bytes | None,
        opks: list[bytes],
        pq_opks: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO users(username, ik_sign_pub, ik_dh_pub, pq_pub, pq_sig) VALUES(?,?,?,?,?)",
                (username, ik_sign_pub, ik_dh_pub, pq_pub, pq_sig),
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
            self._insert_pq_opks(username, pq_opks or [])

            now = time.time()
            self.conn.execute(
                """INSERT INTO profiles(username, display_name, bio, avatar, updated)
                   VALUES(?,?,?,?,?)""",
                (username, username, "", "", now),
            )
            self.conn.execute(
                """INSERT INTO privacy(
                       username, require_approval, moments_visibility,
                       show_online, searchable, updated
                   ) VALUES(?,?,?,?,?,?)""",
                (username, 1, "friends", 1, 1, now),
            )

    def get_user(self, username: str) -> tuple[bytes, bytes, bytes | None, bytes | None] | None:
        row = self.conn.execute(
            "SELECT ik_sign_pub, ik_dh_pub, pq_pub, pq_sig FROM users WHERE username=?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return row[0], row[1], row[2], row[3]

    def list_users(self) -> list[str]:
        rows = self.conn.execute("SELECT username FROM users ORDER BY username").fetchall()
        return [r[0] for r in rows]

    def _insert_pq_opks(self, username: str, items: list[tuple[bytes, bytes]]) -> None:
        for pub, sig in items:
            try:
                self.conn.execute(
                    "INSERT INTO pq_one_time_prekeys(username, pq_opk_pub, pq_opk_sig) VALUES(?,?,?)",
                    (username, pub, sig),
                )
            except sqlite3.IntegrityError:
                continue

    def upload_prekeys(
        self,
        username: str,
        opks: list[bytes],
        spk: tuple[bytes, bytes, float] | None = None,
        pq_opks: list[tuple[bytes, bytes]] | None = None,
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
        self._insert_pq_opks(username, pq_opks or [])
        self.conn.commit()

    def count_pq_opks(self, username: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM pq_one_time_prekeys WHERE username=?",
            (username,),
        ).fetchone()
        return int(row[0]) if row else 0

    def fetch_bundle(
        self, username: str, *, consume_pq_opk: bool = False
    ) -> dict[str, Any] | None:
        user = self.get_user(username)
        if not user:
            return None
        ik_sign_pub, ik_dh_pub, pq_pub, pq_sig = user
        spk = self.conn.execute(
            "SELECT spk_pub, spk_sig, created FROM signed_prekeys WHERE username=?",
            (username,),
        ).fetchone()
        if not spk:
            return None
        with self.conn:
            opk_row = self.conn.execute(
                "SELECT id, opk_pub FROM one_time_prekeys WHERE username=? ORDER BY id LIMIT 1",
                (username,),
            ).fetchone()
            opk_pub = None
            if opk_row:
                self.conn.execute(
                    "DELETE FROM one_time_prekeys WHERE id=?", (opk_row[0],)
                )
                opk_pub = opk_row[1]
            pq_opk_pub = None
            pq_opk_sig = None
            if consume_pq_opk:
                pq_row = self.conn.execute(
                    "SELECT id, pq_opk_pub, pq_opk_sig FROM pq_one_time_prekeys "
                    "WHERE username=? ORDER BY id LIMIT 1",
                    (username,),
                ).fetchone()
                if pq_row:
                    self.conn.execute(
                        "DELETE FROM pq_one_time_prekeys WHERE id=?", (pq_row[0],)
                    )
                    pq_opk_pub = pq_row[1]
                    pq_opk_sig = pq_row[2]
        return {
            "ik_sign_pub": ik_sign_pub,
            "ik_dh_pub": ik_dh_pub,
            "pq_pub": pq_pub,
            "pq_sig": pq_sig,
            "spk_pub": spk[0],
            "spk_sig": spk[1],
            "spk_created": spk[2],
            "opk_pub": opk_pub,
            "pq_opk_pub": pq_opk_pub,
            "pq_opk_sig": pq_opk_sig,
        }

    def enqueue_offline(self, recipient: str, payload: str) -> None:
        self.conn.execute(
            "INSERT INTO offline_queue(recipient, payload, created) VALUES(?,?,?)",
            (recipient, payload, time.time()),
        )
        self.conn.commit()

    def list_offline(self, recipient: str) -> list[tuple[int, str]]:
        rows = self.conn.execute(
            "SELECT id, payload FROM offline_queue WHERE recipient=? ORDER BY id",
            (recipient,),
        ).fetchall()
        return [(int(row[0]), str(row[1])) for row in rows]

    def delete_offline(self, envelope_id: int) -> None:
        with self.conn:
            self.conn.execute(
                "DELETE FROM offline_queue WHERE id=?", (envelope_id,)
            )

    def drain_offline(self, recipient: str) -> list[str]:
        """测试/维护接口；运行时推送使用 list + 逐条成功后删除。"""
        rows = self.list_offline(recipient)
        with self.conn:
            self.conn.executemany(
                "DELETE FROM offline_queue WHERE id=?", [(row[0],) for row in rows]
            )
        return [row[1] for row in rows]

    def create_group(self, name: str, members: list[str]) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO groups(name) VALUES(?)", (name,))
            for u in members:
                self.conn.execute(
                    "INSERT INTO group_members(group_name, username) VALUES(?,?)",
                    (name, u),
                )

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

    def blob_get(self, blob_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT owner, size, chunks, recipients, complete FROM blobs WHERE id=?",
            (blob_id,),
        ).fetchone()
        if not row:
            return None
        recipients = json.loads(row[3])
        return {
            "owner": row[0],
            "size": int(row[1]),
            "chunks": int(row[2]),
            "recipients": list(recipients),
            "complete": bool(row[4]),
        }

    def blob_begin(
        self,
        blob_id: str,
        owner: str,
        size: int,
        chunks: int,
        recipients: list[str],
    ) -> None:
        encoded = json.dumps(recipients, ensure_ascii=False, separators=(",", ":"))
        with self.conn:
            current = self.blob_get(blob_id)
            if current is not None:
                return
            self.conn.execute(
                """
                INSERT INTO blobs(id, owner, size, chunks, recipients, complete, created)
                VALUES(?,?,?,?,?,0,?)
                """,
                (blob_id, owner, size, chunks, encoded, time.time()),
            )

    def blob_put_chunk(self, blob_id: str, index: int, data: bytes) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO blob_chunks(blob_id, idx, data) VALUES(?,?,?)
                ON CONFLICT(blob_id, idx) DO UPDATE SET data=excluded.data
                """,
                (blob_id, index, data),
            )

    def blob_chunk(self, blob_id: str, index: int) -> bytes | None:
        row = self.conn.execute(
            "SELECT data FROM blob_chunks WHERE blob_id=? AND idx=?",
            (blob_id, index),
        ).fetchone()
        if not row:
            return None
        return bytes(row[0])

    def blob_chunk_count(self, blob_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM blob_chunks WHERE blob_id=?",
            (blob_id,),
        ).fetchone()
        return int(row[0] if row else 0)

    def blob_mark_complete(self, blob_id: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE blobs SET complete=1 WHERE id=?",
                (blob_id,),
            )

    def blob_mark_download(self, blob_id: str, username: str) -> bool:
        """记录收件人已取完。所有声明过的收件人都取完后删掉密文。"""
        with self.conn:
            info = self.blob_get(blob_id)
            if info is None:
                return False
            self.conn.execute(
                "INSERT OR IGNORE INTO blob_downloads(blob_id, username) VALUES(?,?)",
                (blob_id, username),
            )
            rows = self.conn.execute(
                "SELECT username FROM blob_downloads WHERE blob_id=?",
                (blob_id,),
            ).fetchall()
            got = {row[0] for row in rows}
            if set(info["recipients"]) <= got:
                self.conn.execute("DELETE FROM blob_chunks WHERE blob_id=?", (blob_id,))
                self.conn.execute("DELETE FROM blob_downloads WHERE blob_id=?", (blob_id,))
                self.conn.execute("DELETE FROM blobs WHERE id=?", (blob_id,))
                return True
            return False

    def save_group_state(self, state) -> None:
        """追加一条已验证的群状态。服务器只存签名后的完整状态，不存私钥。"""
        self.conn.execute(
            "INSERT OR REPLACE INTO group_states(group_name, epoch, signer, state_json) VALUES(?,?,?,?)",
            (
                state.name,
                state.epoch,
                state.signer,
                json.dumps(
                    encode_group_state(state), ensure_ascii=False, separators=(",", ":")
                ),
            ),
        )
        self.conn.commit()

    def load_group_states(self, name: str) -> list:
        rows = self.conn.execute(
            "SELECT state_json FROM group_states WHERE group_name=? ORDER BY epoch",
            (name,),
        ).fetchall()
        try:
            return [decode_group_state(json.loads(row[0])) for row in rows]
        except Exception:
            return []

    def latest_group_state(self, name: str):
        states = self.load_group_states(name)
        return states[-1] if states else None

    def get_profile(self, username: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT display_name, bio, avatar, updated FROM profiles WHERE username=?",
            (username,),
        ).fetchone()
        if row is None:
            return {
                "username": username,
                "display_name": username,
                "bio": "",
                "avatar": "",
                "updated": 0,
            }
        return {
            "username": username,
            "display_name": row[0],
            "bio": row[1],
            "avatar": row[2],
            "updated": row[3],
        }

    def set_profile(self, username: str, display_name: str, bio: str, avatar: str) -> dict[str, Any]:
        now = time.time()
        self.conn.execute(
            """INSERT INTO profiles(username, display_name, bio, avatar, updated)
               VALUES(?,?,?,?,?)
               ON CONFLICT(username) DO UPDATE SET
                 display_name=excluded.display_name,
                 bio=excluded.bio,
                 avatar=excluded.avatar,
                 updated=excluded.updated""",
            (username, display_name, bio, avatar, now),
        )
        self.conn.commit()
        return self.get_profile(username)

    def get_privacy(self, username: str) -> dict[str, Any]:
        row = self.conn.execute(
            """SELECT require_approval, moments_visibility, show_online, searchable
               FROM privacy WHERE username=?""",
            (username,),
        ).fetchone()
        if row is None:
            return {
                "require_approval": True,
                "moments_visibility": "friends",
                "show_online": True,
                "searchable": True,
            }
        return {
            "require_approval": bool(row[0]),
            "moments_visibility": row[1],
            "show_online": bool(row[2]),
            "searchable": bool(row[3]),
        }

    def set_privacy(
        self,
        username: str,
        *,
        require_approval: bool,
        moments_visibility: str,
        show_online: bool,
        searchable: bool,
    ) -> dict[str, Any]:
        now = time.time()
        self.conn.execute(
            """INSERT INTO privacy(
                   username, require_approval, moments_visibility,
                   show_online, searchable, updated
               ) VALUES(?,?,?,?,?,?)
               ON CONFLICT(username) DO UPDATE SET
                 require_approval=excluded.require_approval,
                 moments_visibility=excluded.moments_visibility,
                 show_online=excluded.show_online,
                 searchable=excluded.searchable,
                 updated=excluded.updated""",
            (
                username,
                1 if require_approval else 0,
                moments_visibility,
                1 if show_online else 0,
                1 if searchable else 0,
                now,
            ),
        )
        self.conn.commit()
        return self.get_privacy(username)

    def hidden_online_users(self) -> set[str]:
        rows = self.conn.execute(
            "SELECT username FROM privacy WHERE show_online=0"
        ).fetchall()
        return {row[0] for row in rows}

    def relation(self, left: str, right: str) -> dict[str, Any] | None:
        from src.social import pair_key

        user_lo, user_hi = pair_key(left, right)
        row = self.conn.execute(
            """SELECT status, requested_by, greeting, updated
               FROM friendships WHERE user_lo=? AND user_hi=?""",
            (user_lo, user_hi),
        ).fetchone()
        if row is None:
            return None
        return {
            "user_lo": user_lo,
            "user_hi": user_hi,
            "status": row[0],
            "requested_by": row[1],
            "greeting": row[2],
            "updated": row[3],
        }

    def save_relation(
        self,
        left: str,
        right: str,
        *,
        status: str,
        requested_by: str,
        greeting: str,
    ) -> None:
        from src.social import pair_key

        user_lo, user_hi = pair_key(left, right)
        self.conn.execute(
            """INSERT INTO friendships(user_lo, user_hi, status, requested_by, greeting, updated)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(user_lo, user_hi) DO UPDATE SET
                 status=excluded.status,
                 requested_by=excluded.requested_by,
                 greeting=excluded.greeting,
                 updated=excluded.updated""",
            (user_lo, user_hi, status, requested_by, greeting, time.time()),
        )
        self.conn.commit()

    def delete_relation(self, left: str, right: str) -> None:
        from src.social import pair_key

        user_lo, user_hi = pair_key(left, right)
        self.conn.execute(
            "DELETE FROM friendships WHERE user_lo=? AND user_hi=?",
            (user_lo, user_hi),
        )
        self.conn.commit()

    def relations_of(self, username: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT user_lo, user_hi, status, requested_by, greeting, updated
               FROM friendships WHERE user_lo=? OR user_hi=?
               ORDER BY updated DESC""",
            (username, username),
        ).fetchall()
        found = []
        for user_lo, user_hi, status, requested_by, greeting, updated in rows:
            other = user_hi if username == user_lo else user_lo
            found.append(
                {
                    "username": other,
                    "status": status,
                    "requested_by": requested_by,
                    "greeting": greeting,
                    "updated": updated,
                }
            )
        return found

    def are_friends(self, left: str, right: str) -> bool:
        if left == right:
            return False
        rel = self.relation(left, right)
        return rel is not None and rel["status"] == "accepted"

    def friend_names(self, username: str) -> list[str]:
        return sorted(
            row["username"]
            for row in self.relations_of(username)
            if row["status"] == "accepted"
        )

    def directory_for(self, viewer: str, query: str = "") -> list[str]:
        needle = query.strip().lower()
        friends = set(self.friend_names(viewer))
        names = []
        for username in self.list_users():
            if username == viewer:
                continue
            privacy = self.get_privacy(username)
            visible = privacy["searchable"] or username in friends
            if not visible:
                continue
            profile = self.get_profile(username)
            haystack = f"{username} {profile['display_name']}".lower()
            if needle and needle not in haystack:
                continue
            names.append(username)
        return names

    def insert_moment(
        self,
        moment_id: str,
        author: str,
        body: str,
        image: str,
        visibility: str,
    ) -> None:
        self.conn.execute(
            """INSERT INTO moments(id, author, body, image, visibility, created, deleted)
               VALUES(?,?,?,?,?,?,0)""",
            (moment_id, author, body, image, visibility, time.time()),
        )
        self.conn.commit()

    def get_moment_row(self, moment_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            """SELECT id, author, body, image, visibility, created, deleted
               FROM moments WHERE id=?""",
            (moment_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "author": row[1],
            "body": row[2],
            "image": row[3],
            "visibility": row[4],
            "created": row[5],
            "deleted": bool(row[6]),
        }

    def mark_moment_deleted(self, moment_id: str) -> None:
        self.conn.execute("UPDATE moments SET deleted=1 WHERE id=?", (moment_id,))
        self.conn.commit()

    def toggle_like(self, moment_id: str, username: str) -> bool:
        existing = self.conn.execute(
            "SELECT 1 FROM moment_likes WHERE moment_id=? AND username=?",
            (moment_id, username),
        ).fetchone()
        if existing:
            self.conn.execute(
                "DELETE FROM moment_likes WHERE moment_id=? AND username=?",
                (moment_id, username),
            )
            liked = False
        else:
            self.conn.execute(
                "INSERT INTO moment_likes(moment_id, username, created) VALUES(?,?,?)",
                (moment_id, username, time.time()),
            )
            liked = True
        self.conn.commit()
        return liked

    def add_comment(self, comment_id: str, moment_id: str, author: str, body: str) -> None:
        self.conn.execute(
            """INSERT INTO moment_comments(id, moment_id, author, body, created)
               VALUES(?,?,?,?,?)""",
            (comment_id, moment_id, author, body, time.time()),
        )
        self.conn.commit()

    def moment_likes(self, moment_id: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT username FROM moment_likes WHERE moment_id=? ORDER BY created",
            (moment_id,),
        ).fetchall()
        return [row[0] for row in rows]

    def moment_comments(self, moment_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT id, author, body, created FROM moment_comments
               WHERE moment_id=? ORDER BY created""",
            (moment_id,),
        ).fetchall()
        return [
            {"id": row[0], "author": row[1], "body": row[2], "created": row[3]}
            for row in rows
        ]

    def recent_moments(self, limit: int = 40) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT id, author, body, image, visibility, created, deleted
               FROM moments WHERE deleted=0 ORDER BY created DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "id": row[0],
                "author": row[1],
                "body": row[2],
                "image": row[3],
                "visibility": row[4],
                "created": row[5],
                "deleted": bool(row[6]),
            }
            for row in rows
        ]


    def close(self) -> None:
        self.conn.close()
