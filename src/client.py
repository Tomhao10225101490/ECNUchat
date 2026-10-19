"""Rich 终端客户端：注册/登录、单聊、最多 8 人的逐人棘轮群聊。"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import websockets
from cryptography.exceptions import InvalidSignature
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src import PROJECT_ABSTRACT, PROJECT_NAME
from src.attachments import (
    MAX_FILE_BYTES,
    AttachmentError,
    attachment_root,
    attachment_view,
    display_text,
    history_body,
    meta_from_dict,
    meta_to_dict,
    open_bytes,
    plaintext_len,
    seal_bytes,
)
from src.double_ratchet import (
    GCMError,
    RatchetError,
    RatchetState,
    ReplayError,
    decrypt,
    encrypt,
    init_receiver,
    init_sender,
)
from src.prekeys import generate_identity, generate_x25519, sign_bytes, verify_spk
from src.protocol import (
    ProtocolError,
    b64d,
    b64e,
    check_size,
    decode_ratchet_payload,
    dumps,
    encode_ratchet_payload,
    fingerprint,
    fingerprint_short,
    loads,
    validate_username,
)
from src.store import ClientStore
from src.x3dh import (
    X3DHError,
    build_initial_message,
    initiator_secret,
    responder_secret,
    verify_initial,
)

console = Console()


@dataclass
class Incoming:
    sender: str
    text: str
    group: str | None
    kind: str
    error: str | None = None
    attachment: dict[str, Any] | None = None


@dataclass
class CommandResult:
    notice: str | None = None
    overlay: str | None = None


@dataclass
class ChatEngine:
    username: str
    password: str
    store: ClientStore
    identity: Any
    sessions: dict[str, RatchetState] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    peer_keys: dict[str, tuple[bytes, bytes]] = field(default_factory=dict)
    current_peer: str | None = None
    current_group: str | None = None
    last_error: str | None = None
    inbox: asyncio.Queue[Incoming] = field(default_factory=asyncio.Queue)
    pending_x3dh: dict[str, Any] = field(default_factory=dict)
    online_users: set[str] = field(default_factory=set)
    directory: list[str] = field(default_factory=list)
    connected: bool = False
    ui_theme: str = "telegram"
    ws: Any = None
    _waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    _incoming_raw: asyncio.Queue = field(default_factory=asyncio.Queue)
    _tasks: list[asyncio.Task] = field(default_factory=list)
    _peer_locks: dict[str, asyncio.Lock] = field(default_factory=dict)
    _incoming_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _incoming_done: set[str] = field(default_factory=set)
    on_file_progress: Any = None

    @classmethod
    def open(cls, username: str, password: str, db_path: str) -> ChatEngine:
        validate_username(username)
        store = ClientStore(db_path)
        if store.exists():
            identity = store.unlock(password)
            if identity.username != username:
                raise RuntimeError("本地身份与 --user 不一致")
        else:
            identity = generate_identity(username)
            store.create(password, identity)
        engine = cls(
            username=username,
            password=password,
            store=store,
            identity=identity,
        )
        engine.groups = store.load_groups()
        for peer in store.list_sessions():
            state = store.load_session(peer)
            if state:
                engine.sessions[peer] = state
        return engine

    def persist(self) -> None:
        self.store.save_identity(self.identity)
        for peer, state in self.sessions.items():
            self.store.save_session(peer, state)
        for name, members in self.groups.items():
            self.store.save_group(name, members)

    def status_line(self) -> str:
        if self.current_group:
            members = ",".join(self.groups.get(self.current_group, []))
            gens = []
            for m in self.groups.get(self.current_group, []):
                if m != self.username and m in self.sessions:
                    gens.append(f"{m}:{self.sessions[m].dh_ratchet_count}")
            return (
                f"用户 {self.username} | 群 {self.current_group} [{members}] "
                f"| 棘轮代数 {','.join(gens) or '-'} | {self.last_error or '就绪'}"
            )
        if self.current_peer:
            fp = "-"
            keys = self.peer_keys.get(self.current_peer)
            if keys:
                fp = fingerprint_short(keys[0])
            gen = self.sessions[self.current_peer].dh_ratchet_count if self.current_peer in self.sessions else 0
            return (
                f"用户 {self.username} | 对端 {self.current_peer} | 指纹 {fp} "
                f"| 棘轮代数 {gen} | {self.last_error or '就绪'}"
            )
        return f"用户 {self.username} | 未选择会话 | {self.last_error or '就绪'}"

    async def send_json(self, obj: dict[str, Any]) -> None:
        raw = dumps(obj)
        check_size(raw)
        await self.ws.send(raw)

    def _arm(self, request_id: str) -> asyncio.Future:
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._waiters[request_id] = fut
        return fut

    def _disarm(self, request_id: str) -> None:
        self._waiters.pop(request_id, None)

    async def request(self, obj: dict[str, Any], *expect: str) -> dict[str, Any]:
        if not self.connected and obj.get("type") not in {"register", "login"}:
            raise ProtocolError("连接已断开")
        request_id = uuid.uuid4().hex
        request_obj = dict(obj)
        request_obj["request_id"] = request_id
        fut = self._arm(request_id)
        try:
            await self.send_json(request_obj)
            result = await asyncio.wait_for(fut, timeout=15)
        finally:
            self._disarm(request_id)
        if result.get("type") == "error":
            raise ProtocolError(result.get("message") or "服务器错误")
        if expect and result.get("type") not in expect:
            raise ProtocolError(f"响应类型错误：{result.get('type')}")
        return result

    async def connect(self, uri: str) -> None:
        self.ws = await websockets.connect(uri, max_size=64 * 1024)
        self.connected = True
        self._tasks.append(asyncio.create_task(self._reader()))
        self._tasks.append(asyncio.create_task(self._processor()))
        registered = self.store.load_peer("__registered__")
        if registered:
            await self._login()
        else:
            try:
                await self._register()
            except ProtocolError as exc:
                if "已存在" in str(exc):
                    await self._login()
                else:
                    raise
            self.store.save_peer(
                "__registered__", self.identity.ik_sign_pub, self.identity.ik_dh_pub
            )
        await self._retry_outboxes()
        try:
            await self._retry_incoming_files()
        except Exception:
            self.last_error = "文件下载将在下次连接重试"
        try:
            await self._retry_pending_prekeys()
        except Exception:
            self.last_error = "预密钥补充将在下次登录重试"

    async def _retry_outboxes(self) -> None:
        """重连后重发原始加密信封，不再次推进双棘轮。"""
        for peer in self.store.list_outbox_peers():
            lock = self._peer_locks.setdefault(peer, asyncio.Lock())
            try:
                async with lock:
                    await self._flush_outbox(peer)
            except Exception:
                self.last_error = "待发加密信封将在下次重连重试"

    async def _flush_outbox(self, peer: str) -> None:
        pending_payload = self.store.load_outbox(peer)
        if pending_payload is None:
            return
        await self.request(
            {
                "type": "envelope",
                "from": self.username,
                "to": peer,
                "payload": pending_payload,
            },
            "envelope_ok",
        )
        self.store.delete_outbox(peer)
        if pending_payload.get("x3dh") is not None:
            self.pending_x3dh.pop(peer, None)

    def _progress(self, local_id: str, done: int, total: int) -> None:
        callback = self.on_file_progress
        if callback is not None:
            callback(local_id, done, total)

    async def _retry_pending_prekeys(self) -> None:
        pending = self.store.load_pending_prekeys()
        if not pending:
            return
        await self.request(
            {"type": "upload_prekeys", "opks": [b64e(pub) for pub in pending]},
            "upload_prekeys_ok",
        )
        self.store.clear_pending_prekeys()

    async def _register(self) -> None:
        await self.request(
            {
                "type": "register",
                "username": self.username,
                "ik_sign_pub": b64e(self.identity.ik_sign_pub),
                "ik_dh_pub": b64e(self.identity.ik_dh_pub),
                "spk_pub": b64e(self.identity.spk.pub),
                "spk_sig": b64e(self.identity.spk.signature),
                "spk_created": self.identity.spk.created,
                "opks": [b64e(o.pub) for o in self.identity.opks],
            },
            "register_ok",
        )

    async def _login(self) -> None:
        chal = await self.request({"type": "login", "username": self.username}, "login_challenge")
        challenge = b64d(chal["challenge"]) or b""
        sig = sign_bytes(self.identity.ik_sign_priv, challenge)
        await self.request(
            {"type": "login", "username": self.username, "signature": b64e(sig)},
            "login_ok",
        )

    async def _reader(self) -> None:
        try:
            async for raw in self.ws:
                try:
                    msg = loads(raw)
                except Exception:
                    continue
                typ = msg.get("type")
                waiter = self._waiters.get(msg.get("request_id", ""))
                delivered = False
                if waiter is not None and not waiter.done():
                    waiter.set_result(msg)
                    delivered = True
                if typ in {"envelope", "group_update", "presence"} or (
                    typ == "error" and not delivered
                ):
                    await self._incoming_raw.put(msg)
        except Exception:
            pass
        finally:
            self.connected = False
            self.online_users.clear()
            self.last_error = "连接断开"
            for future in set(self._waiters.values()):
                if not future.done():
                    future.set_exception(ProtocolError("连接断开"))
            await self.inbox.put(Incoming("系统", "连接断开", None, "sys", "连接断开"))

    async def _processor(self) -> None:
        while True:
            msg = await self._incoming_raw.get()
            try:
                await self._on_server(msg)
            except Exception:
                continue

    async def _on_server(self, msg: dict[str, Any]) -> None:
        typ = msg.get("type")
        if typ == "envelope":
            await self._on_envelope(msg)
        elif typ == "group_update":
            name = msg["group"]
            members = list(msg["members"])
            self.groups[name] = members
            self.store.save_group(name, members)
            await self.inbox.put(Incoming("系统", "", name, "presence"))
        elif typ == "presence":
            self.online_users = set(msg.get("online") or [])
            await self.inbox.put(Incoming("", "", None, "presence"))
        elif typ == "error":
            self.last_error = msg.get("message")
            await self.inbox.put(Incoming("", "", None, "sys", self.last_error))

    async def fetch_user(self, name: str) -> tuple[bytes, bytes]:
        if name in self.peer_keys:
            return self.peer_keys[name]
        cached = self.store.load_peer(name)
        if cached:
            self.peer_keys[name] = cached
            return cached
        info = await self.request({"type": "fetch_user", "username": name}, "user")
        keys = (b64d(info["ik_sign_pub"]) or b"", b64d(info["ik_dh_pub"]) or b"")
        self.peer_keys[name] = keys
        self.store.save_peer(name, keys[0], keys[1])
        return keys

    async def start_session(self, peer: str) -> RatchetState:
        if peer in self.sessions:
            return self.sessions[peer]
        bundle = await self.request({"type": "fetch_bundle", "username": peer}, "bundle")
        ik_sign = b64d(bundle["ik_sign_pub"]) or b""
        ik_dh = b64d(bundle["ik_dh_pub"]) or b""
        spk_pub = b64d(bundle["spk_pub"]) or b""
        spk_sig = b64d(bundle["spk_sig"]) or b""
        try:
            verify_spk(ik_sign, spk_pub, peer, spk_sig)
        except InvalidSignature as exc:
            self.last_error = "对方预密钥签名无效"
            raise X3DHError("对方预密钥签名无效") from exc
        pinned = self.store.load_peer(peer)
        if pinned is not None and pinned != (ik_sign, ik_dh):
            self.last_error = "身份密钥发生变化"
            raise X3DHError("身份密钥发生变化：已拒绝覆盖已核对的指纹")
        self.peer_keys[peer] = (ik_sign, ik_dh)
        if pinned is None:
            self.store.save_peer(peer, ik_sign, ik_dh)
        ek_priv, ek_pub = generate_x25519()
        opk = b64d(bundle.get("opk"))
        sk = initiator_secret(
            self.identity.ik_dh_priv, ek_priv, spk_pub, ik_dh, opk
        )
        state = init_sender(sk, spk_pub, self.username, peer)
        self.pending_x3dh[peer] = build_initial_message(
            self.identity.ik_sign_priv, self.identity.ik_dh_pub, ek_pub, opk
        )
        self.sessions[peer] = state
        return state

    async def _ensure_session_for_send(self, peer: str) -> RatchetState:
        if peer in self.sessions:
            return self.sessions[peer]
        return await self.start_session(peer)

    async def send_text(self, text: str, *, peer: str | None = None, group: str | None = None) -> None:
        if group:
            members = self.groups.get(group) or []
            others = [m for m in members if m != self.username]
            if not others:
                raise ProtocolError("群里没有其他成员")
            self.store.add_history(f"group:{group}", self.username, text)
            delivered = 0
            try:
                for other in others:
                    await self._send_one(other, text, group=group, kind="chat")
                    delivered += 1
            except Exception:
                self.store.add_history(
                    f"group:{group}",
                    "系统",
                    f"群消息仅送达 {delivered}/{len(others)} 人，可稍后重试",
                )
                raise
            return
        dest = peer or self.current_peer
        if not dest:
            raise ProtocolError("先用 /chat 名字 选择对端")
        await self._send_one(dest, text, group=None, kind="chat")
        self.store.add_history(f"dm:{dest}", self.username, text)

    async def send_file(
        self,
        path: str | None = None,
        *,
        peer: str | None = None,
        group: str | None = None,
        caption: str = "",
        local_id: str | None = None,
        data: bytes | None = None,
        filename: str | None = None,
        mime: str | None = None,
    ) -> str:
        """上传一份密文，再给每个收件人发一封带文件钥匙的棘轮信封。"""
        if not isinstance(caption, str) or len(caption) > 2000:
            raise ProtocolError("附件说明过长")
        local_id = local_id or uuid.uuid4().hex
        if group:
            members = self.groups.get(group) or []
            recipients = sorted(member for member in members if member != self.username)
            if not recipients:
                raise ProtocolError("群里没有其他成员")
            conv = f"group:{group}"
            target_group: str | None = group
        else:
            dest = peer or self.current_peer
            if not dest:
                raise ProtocolError("先用 /chat 名字 选择对端")
            if dest == self.username:
                raise ProtocolError("不能给自己发文件")
            recipients = [dest]
            conv = f"dm:{dest}"
            target_group = None
        record = self.store.load_file_job(local_id)
        if record is None:
            record = self._new_file_job(
                local_id=local_id,
                conv=conv,
                group=target_group,
                recipients=recipients,
                caption=caption,
                path=path,
                data=data,
                filename=filename,
                mime=mime,
            )
        else:
            recipients = list(record["recipients"])
            conv = str(record["conv"])
            target_group = record.get("group")
        if not record.get("history"):
            record["history"] = self._file_history_body(record)
        self.store.save_file_job(local_id, record)
        self.store.save_message_status(local_id, conv, str(record["history"]), "sending")
        if not record.get("uploaded"):
            await self._upload_file(record)
            record["uploaded"] = True
            self.store.save_file_job(local_id, record)
        if not record.get("logged"):
            self.store.add_history(conv, self.username, str(record["history"]))
            record["logged"] = True
            self.store.save_file_job(local_id, record)
        delivered = 0
        try:
            for other in recipients:
                await self._deliver_file_envelope(other, record)
                delivered += 1
        except Exception:
            if target_group:
                self.store.add_history(
                    conv,
                    "系统",
                    f"文件仅送达 {delivered}/{len(recipients)} 人，可稍后重试",
                )
            raise
        size = int(record["meta"]["size"])
        self._progress(local_id, size, size)
        return str(record["history"])

    def _new_file_job(
        self,
        *,
        local_id: str,
        conv: str,
        group: str | None,
        recipients: list[str],
        caption: str,
        path: str | None,
        data: bytes | None,
        filename: str | None,
        mime: str | None,
    ) -> dict[str, Any]:
        if data is None:
            if not path:
                raise ProtocolError("没有要发送的文件")
            file_path = Path(path)
            if not file_path.is_file():
                raise ProtocolError("文件不存在")
            if file_path.stat().st_size > MAX_FILE_BYTES:
                raise ProtocolError("文件超过 32MiB")
            payload = file_path.read_bytes()
            filename = filename or file_path.name
        else:
            if len(data) > MAX_FILE_BYTES:
                raise ProtocolError("文件超过 32MiB")
            payload = bytes(data)
            filename = filename or "file"
        sealed = seal_bytes(payload, filename, mime)
        blob_hex = sealed.meta.file_id.hex()
        root = attachment_root(self.store.path)
        cipher = root / "cipher" / blob_hex
        cipher.mkdir(parents=True, exist_ok=True)
        for index, chunk in enumerate(sealed.chunks):
            (cipher / str(index)).write_bytes(chunk)
        rel = f"files/{blob_hex}/{sealed.meta.name}"
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        return {
            "local_id": local_id,
            "conv": conv,
            "group": group,
            "recipients": recipients,
            "caption": caption,
            "meta": meta_to_dict(sealed.meta),
            "rel": rel,
            "enveloped": [],
            "uploaded": False,
            "logged": False,
            "history": "",
        }

    def _file_history_body(self, record: dict[str, Any]) -> str:
        meta = meta_from_dict(record["meta"])
        return history_body(
            name=meta.name,
            mime=meta.mime,
            size=meta.size,
            sha256=meta.sha256,
            rel_path=str(record["rel"]),
            caption=str(record.get("caption") or ""),
        )

    async def _upload_file(self, record: dict[str, Any]) -> None:
        meta = meta_from_dict(record["meta"])
        blob_id = meta.file_id.hex()
        await self.request(
            {
                "type": "blob_begin",
                "id": blob_id,
                "size": meta.size,
                "chunks": meta.chunks,
                "recipients": list(record["recipients"]),
            },
            "blob_begin_ok",
        )
        cipher = attachment_root(self.store.path) / "cipher" / blob_id
        total = meta.size
        sent = 0
        self._progress(str(record["local_id"]), 0, total)
        for index in range(meta.chunks):
            chunk_path = cipher / str(index)
            if not chunk_path.is_file():
                raise ProtocolError("本地密文丢失")
            ciphertext = chunk_path.read_bytes()
            await self.request(
                {
                    "type": "blob_chunk",
                    "id": blob_id,
                    "idx": index,
                    "data": b64e(ciphertext),
                },
                "blob_chunk_ok",
            )
            sent += plaintext_len(meta.size, meta.chunks, index)
            self._progress(str(record["local_id"]), sent, total)
        await self.request({"type": "blob_finish", "id": blob_id}, "blob_finish_ok")

    async def _deliver_file_envelope(self, peer: str, record: dict[str, Any]) -> None:
        lock = self._peer_locks.setdefault(peer, asyncio.Lock())
        async with lock:
            if peer in (record.get("enveloped") or []):
                await self._flush_outbox(peer)
                return
            await self._flush_outbox(peer)
            state = await self._ensure_session_for_send(peer)
            x3dh = self.pending_x3dh.get(peer)
            inner = json.dumps(
                {
                    "v": 1,
                    "text": record.get("caption") or "",
                    "group": record.get("group"),
                    "kind": "file",
                    "file": record["meta"],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(inner) > 12 * 1024:
                raise ProtocolError("附件说明过长")
            msg, message_key = encrypt(state, inner)
            del message_key
            payload = encode_ratchet_payload(
                msg, x3dh=x3dh, group=record.get("group"), kind="file"
            )
            check_size(
                dumps(
                    {
                        "type": "envelope",
                        "from": self.username,
                        "to": peer,
                        "payload": payload,
                    }
                )
            )
            updated = dict(record)
            updated["enveloped"] = list(record.get("enveloped") or []) + [peer]
            self.store.save_session_with_outbox(
                peer,
                state,
                payload,
                file_job=(str(record["local_id"]), updated),
            )
            record["enveloped"] = updated["enveloped"]
            await self.request(
                {
                    "type": "envelope",
                    "from": self.username,
                    "to": peer,
                    "payload": payload,
                },
                "envelope_ok",
            )
            self.store.delete_outbox(peer)
            if x3dh is not None:
                self.pending_x3dh.pop(peer, None)

    async def _send_one(
        self, peer: str, text: str, *, group: str | None, kind: str
    ) -> dict[str, Any]:
        lock = self._peer_locks.setdefault(peer, asyncio.Lock())
        async with lock:
            await self._flush_outbox(peer)
            state = await self._ensure_session_for_send(peer)
            x3dh = self.pending_x3dh.get(peer)
            inner = json.dumps(
                {"v": 1, "text": text, "group": group, "kind": kind},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            msg, _mk = encrypt(state, inner)
            del _mk
            payload = encode_ratchet_payload(msg, x3dh=x3dh, group=group, kind=kind)
            # 先把推进后的加密状态和完全相同的信封原子落盘。崩溃后重发
            # 同一信封，不会丢 X3DH 初始字段，也不会重复推进发送链。
            self.store.save_session_with_outbox(peer, state, payload)
            await self.request(
                {
                    "type": "envelope",
                    "from": self.username,
                    "to": peer,
                    "payload": payload,
                },
                "envelope_ok",
            )
            self.store.delete_outbox(peer)
            if x3dh is not None:
                self.pending_x3dh.pop(peer, None)
            return payload

    async def _on_envelope(self, env: dict[str, Any]) -> None:
        sender = env["from"]
        payload = env["payload"]
        group = payload.get("group")
        try:
            text, verified_group, verified_kind, file_meta = await self._decrypt_envelope(
                sender, payload
            )
            group = verified_group
        except ReplayError:
            self._fail(sender, group, "重放拒绝")
            return
        except GCMError:
            self._fail(sender, group, "GCM 失败")
            return
        except X3DHError as exc:
            self._fail(sender, group, str(exc) or "验签失败")
            return
        except RatchetError as exc:
            self._fail(sender, group, exc.kind)
            return
        except Exception as exc:
            self._fail(sender, group, str(exc))
            return
        self.last_error = None
        if verified_kind == "file" and file_meta is not None:
            record = {
                "meta": meta_to_dict(file_meta),
                "sender": sender,
                "group": verified_group,
                "caption": text,
                "logged": False,
            }
            try:
                await self._accept_incoming(record)
            except AttachmentError:
                self._fail(sender, verified_group, "GCM 失败")
            except Exception:
                self._fail(sender, verified_group, "文件下载失败")
            return
        conv = f"group:{group}" if group else f"dm:{sender}"
        who = "系统" if verified_kind == "group_meta" else sender
        self.store.add_history(conv, who, text)
        await self.inbox.put(Incoming(who, text, group, verified_kind))

    def _fail(self, sender: str, group: str | None, phrase: str) -> None:
        self.last_error = phrase
        conv = f"group:{group}" if group else (f"dm:{sender}" if sender else None)
        if conv:
            self.store.add_history(conv, "系统", phrase)
        self.inbox.put_nowait(Incoming(sender, "", group, "error", phrase))

    async def _retry_incoming_files(self) -> None:
        for _blob_id, record in self.store.list_incoming_files():
            try:
                await self._accept_incoming(record)
            except AttachmentError:
                blob_id = str(record.get("meta", {}).get("id") or _blob_id)
                self.store.delete_incoming_file(blob_id)
                self._fail(str(record.get("sender") or ""), record.get("group"), "GCM 失败")
            except Exception:
                self.last_error = "文件下载将在下次连接重试"

    async def _accept_incoming(self, record: dict[str, Any]) -> None:
        """同一份文件只下载一次。登录补拉和实时信封可能撞在一起。"""
        blob_id = str(record.get("meta", {}).get("id") or "")
        async with self._incoming_lock:
            if blob_id in self._incoming_done:
                return
            self._incoming_done.add(blob_id)
        try:
            await self._finish_incoming(record)
        except Exception:
            async with self._incoming_lock:
                self._incoming_done.discard(blob_id)
            raise

    async def _finish_incoming(self, record: dict[str, Any]) -> None:
        meta = meta_from_dict(record["meta"])
        blob_id = meta.file_id.hex()
        self.store.save_incoming_file(blob_id, record)
        try:
            plain = await self._download_file(meta)
        except AttachmentError:
            self.store.delete_incoming_file(blob_id)
            raise
        rel = f"files/{blob_id}/{meta.name}"
        dest = attachment_root(self.store.path) / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".part")
        partial.write_bytes(plain)
        partial.replace(dest)
        body = history_body(
            name=meta.name,
            mime=meta.mime,
            size=meta.size,
            sha256=meta.sha256,
            rel_path=rel,
            caption=str(record.get("caption") or ""),
        )
        fresh = not record.get("logged")
        conv = (
            f"group:{record['group']}"
            if record.get("group")
            else f"dm:{record['sender']}"
        )
        if fresh:
            self.store.add_history(conv, str(record["sender"]), body)
            record["logged"] = True
            record["history"] = body
            self.store.save_incoming_file(blob_id, record)
        self.store.delete_incoming_file(blob_id)
        try:
            await self.request({"type": "blob_done", "id": blob_id}, "blob_done_ok")
        except Exception:
            self.last_error = "文件已收下，服务器清理将在下次重试"
        if fresh:
            await self.inbox.put(
                Incoming(
                    str(record["sender"]),
                    display_text(body, self.store.path),
                    record.get("group"),
                    "file",
                    attachment=attachment_view(self.store.path, body),
                )
            )

    async def _download_file(self, meta: Any) -> bytes:
        blob_id = meta.file_id.hex()
        chunks: list[bytes] = []
        for index in range(meta.chunks):
            resp = await self.request(
                {"type": "blob_fetch", "id": blob_id, "idx": index},
                "blob_fetch_ok",
            )
            if resp.get("id") != blob_id or resp.get("idx") != index:
                raise ProtocolError("分片编号对不上")
            data = b64d(resp.get("data"))
            if data is None:
                raise ProtocolError("分片缺失")
            chunks.append(data)
        return open_bytes(meta, chunks)

    async def _decrypt_envelope(
        self, sender: str, payload: dict[str, Any]
    ) -> tuple[str, str | None, str, Any]:
        ratchet_msg, init = decode_ratchet_payload(payload)
        new_identity = False
        consumed_opk: bytes | None = None
        if sender not in self.sessions:
            if init is None:
                raise X3DHError("没有会话且缺少 X3DH 初始消息")
            ik_sign, ik_dh = await self.fetch_user(sender)
            try:
                verify_initial(
                    ik_sign, init.ik_dh_pub, init.ek_pub, init.opk_pub, init.signature
                )
            except X3DHError:
                self.last_error = "验签失败"
                raise
            if init.ik_dh_pub != ik_dh:
                raise X3DHError("验签失败：身份协商公钥与服务器登记不一致")
            opk_priv = None
            if init.opk_pub:
                matching = next(
                    (item for item in self.identity.opks if item.pub == init.opk_pub),
                    None,
                )
                if matching is None:
                    raise X3DHError("本地没有对应的一次性预密钥私钥")
                opk_priv = matching.priv
                consumed_opk = init.opk_pub
            sk = responder_secret(
                self.identity.spk.priv,
                self.identity.ik_dh_priv,
                init.ik_dh_pub,
                init.ek_pub,
                opk_priv,
            )
            state = init_receiver(
                sk, self.identity.spk.priv, ratchet_msg.header.dh_pub, self.username, sender
            )
            new_identity = True
        else:
            state = self.sessions[sender]
        plaintext, mk = decrypt(state, ratchet_msg)
        del mk
        file_meta = None
        try:
            inner = json.loads(plaintext.decode("utf-8"))
            if not isinstance(inner, dict) or inner.get("v") != 1:
                raise ValueError
            text = inner["text"]
            verified_group = inner.get("group")
            verified_kind = inner.get("kind", "chat")
            if verified_kind not in {"chat", "group_meta", "file"}:
                raise ValueError
            if not isinstance(text, str) or verified_group != payload.get("group"):
                raise ValueError
            if verified_kind != (payload.get("kind") or "chat"):
                raise ValueError
            file_payload = inner.get("file")
            if verified_kind == "file":
                if not isinstance(file_payload, dict):
                    raise ValueError
                file_meta = meta_from_dict(file_payload)
            elif file_payload is not None:
                raise ValueError
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            ValueError,
            AttachmentError,
        ) as exc:
            raise GCMError("GCM 失败：消息语义元数据不一致") from exc
        if new_identity:
            self.sessions[sender] = state
            if consumed_opk is not None:
                self.identity.take_opk(consumed_opk)
            self.store.save_identity(self.identity)
        self.store.save_session(sender, state)
        if new_identity and self.identity.needs_refill():
            created = self.identity.refill_opks()
            self.store.save_identity(self.identity)
            self.store.save_pending_prekeys([item.pub for item in created])
            try:
                await self.request(
                    {"type": "upload_prekeys", "opks": [b64e(o.pub) for o in created]},
                    "upload_prekeys_ok",
                )
                self.store.clear_pending_prekeys()
            except Exception:
                # 明文已经认证成功且状态已提交；补池失败不能把消息伪装成解密失败。
                self.last_error = "预密钥补充将在下次登录重试"
        return text, verified_group, verified_kind, file_meta

    async def list_users(self) -> dict[str, Any]:
        return await self.request({"type": "list_users"}, "users")

    async def create_group(self, name: str, members: list[str]) -> None:
        all_members = list(dict.fromkeys([self.username, *members]))
        await self.request(
            {"type": "group_create", "group": name, "members": all_members},
            "group_update",
        )
        self.groups[name] = all_members
        self.store.save_group(name, all_members)
        self.current_group = name
        self.current_peer = None
        notice = f"{self.username} 创建了群，成员 {', '.join(all_members)}"
        self.store.add_history(f"group:{name}", "系统", notice)
        for other in all_members:
            if other == self.username:
                continue
            await self._send_one(other, notice, group=name, kind="group_meta")

    async def add_group_member(self, name: str, member: str) -> None:
        await self.request(
            {"type": "group_add", "group": name, "member": member},
            "group_update",
        )
        members = self.groups.get(name) or []
        if member not in members:
            members.append(member)
        self.groups[name] = members
        self.store.save_group(name, members)
        notice = f"{self.username} 将 {member} 加入 {name}"
        self.store.add_history(f"group:{name}", "系统", notice)
        for other in members:
            if other == self.username:
                continue
            await self._send_one(other, notice, group=name, kind="group_meta")

    async def close(self) -> None:
        self.persist()
        for task in self._tasks:
            task.cancel()
        if self.ws is not None:
            await self.ws.close()
        self.connected = False
        self.store.close()


def print_banner(engine: ChatEngine) -> None:
    body = Text()
    body.append(PROJECT_NAME + "\n", style="bold cyan")
    body.append(PROJECT_ABSTRACT + "\n\n", style="dim")
    body.append(engine.status_line())
    console.print(Panel(body, title=PROJECT_NAME, border_style="cyan"))
    console.print(
        "[dim]/chat 名字  /fingerprint 名字  /group create 群名 成员…  "
        "/group add 群名 新成员  /file 路径  /history  /users  /help  /quit[/dim]"
    )


def _history_text(engine: ChatEngine) -> str:
    if engine.current_group:
        conv = f"group:{engine.current_group}"
    elif engine.current_peer:
        conv = f"dm:{engine.current_peer}"
    else:
        return "先选择会话"
    lines = []
    for sender, body, _ts in engine.store.get_history(conv):
        lines.append(f"{sender}: {display_text(body, engine.store.path)}")
    return "\n".join(lines) if lines else "这个会话还没有消息"


async def command_loop(engine: ChatEngine) -> None:
    from src.ui import run_interface

    await run_interface(engine)


async def legacy_command_loop(engine: ChatEngine) -> None:
    print_banner(engine)

    def render_incoming(item: Incoming) -> None:
        if item.kind == "presence":
            return
        if item.error:
            console.print(Text(item.error, style="bold red"))
            return
        if item.kind in {"sys", "group_meta"} or item.sender == "系统":
            console.print(Text(item.text, style="yellow"))
            return
        where = f"#{item.group} " if item.group else ""
        style = "green" if item.sender == engine.username else "white"
        console.print(Text(f"{where}{item.sender}: {item.text}", style=style))

    async def printer() -> None:
        while True:
            item = await engine.inbox.get()
            render_incoming(item)
            console.print(f"[dim]{engine.status_line()}[/dim]")

    printer_task = asyncio.create_task(printer())
    loop = asyncio.get_event_loop()
    try:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if line == "":
                break
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                result = await handle_line(engine, line)
            except (ProtocolError, X3DHError, RatchetError) as exc:
                engine.last_error = str(exc)
                console.print(f"[bold red]{exc}[/bold red]")
                continue
            except Exception as exc:
                engine.last_error = str(exc)
                console.print(f"[bold red]{exc}[/bold red]")
                continue
            if result.overlay:
                console.print(Panel(result.overlay, border_style="cyan"))
            elif result.notice:
                console.print(result.notice)
            elif not line.startswith("/"):
                who = f"#{engine.current_group} " if engine.current_group else ""
                console.print(f"[green]{who}{engine.username}: {line}[/green]")
            console.print(f"[dim]{engine.status_line()}[/dim]")
    finally:
        printer_task.cancel()
        await engine.close()


async def handle_line(engine: ChatEngine, line: str) -> CommandResult:
    if not line.startswith("/"):
        if engine.current_group:
            await engine.send_text(line, group=engine.current_group)
        else:
            await engine.send_text(line)
        engine.last_error = None
        return CommandResult()
    parts = line.split()
    cmd = parts[0]
    if cmd in {"/quit", "/exit"}:
        raise SystemExit(0)
    if cmd == "/help":
        from src.ui import HELP_TEXT

        return CommandResult(overlay=HELP_TEXT)
    if cmd == "/theme":
        if len(parts) != 2 or parts[1] not in {"telegram", "wechat"}:
            raise ProtocolError("用法：/theme telegram 或 /theme wechat")
        engine.ui_theme = parts[1]
        return CommandResult(notice=f"已切换到 {parts[1]} 风格")
    if cmd == "/users":
        info = await engine.list_users()
        engine.directory = list(info.get("users") or [])
        engine.online_users = set(info.get("online") or [])
        rows = ["用户          状态"]
        for u in engine.directory:
            rows.append(f"{u:<14}{'在线' if u in engine.online_users else '离线'}")
        return CommandResult(overlay="\n".join(rows))
    if cmd == "/chat" and len(parts) == 2:
        validate_username(parts[1])
        if parts[1] == engine.username:
            raise ProtocolError("不能和自己建立会话")
        await engine.fetch_user(parts[1])
        engine.current_peer = parts[1]
        engine.current_group = None
        return CommandResult(notice=f"已打开与 {parts[1]} 的会话")
    if cmd == "/fingerprint" and len(parts) == 2:
        name = parts[1]
        if name == engine.username:
            ik = engine.identity.ik_sign_pub
        else:
            ik, _ = await engine.fetch_user(name)
        groups = fingerprint(ik).split()
        grid = "\n".join("  ".join(groups[i : i + 4]) for i in range(0, 16, 4))
        body = f"{name} 的 IK_sign 指纹\n用线下渠道核对这 16 组。不一致就不要继续聊。\n\n{grid}"
        return CommandResult(overlay=body, notice=f"{name} 指纹已显示")
    if cmd == "/file":
        pieces = line.split(maxsplit=1)
        if len(pieces) != 2 or not pieces[1].strip():
            raise ProtocolError("用法：/file 路径")
        file_path = pieces[1].strip()
        if engine.current_group:
            await engine.send_file(file_path, group=engine.current_group)
        else:
            await engine.send_file(file_path)
        engine.last_error = None
        return CommandResult(notice=f"已发送文件 {Path(file_path).name}")
    if cmd == "/history":
        return CommandResult(overlay=_history_text(engine))
    if cmd == "/group" and len(parts) >= 2:
        if parts[1] == "create" and len(parts) >= 4:
            await engine.create_group(parts[2], parts[3:])
            return CommandResult(notice=f"已创建群 {parts[2]}")
        if parts[1] == "add" and len(parts) == 4:
            await engine.add_group_member(parts[2], parts[3])
            return CommandResult(notice=f"已将 {parts[3]} 加入 {parts[2]}")
        if parts[1] not in engine.groups:
            raise ProtocolError(f"群 {parts[1]} 不存在")
        engine.current_group = parts[1]
        engine.current_peer = None
        return CommandResult(notice=f"已打开群 {parts[1]}")
    raise ProtocolError("无法识别的命令，输入 /help 查看")


async def async_main(args: argparse.Namespace) -> None:
    engine = ChatEngine.open(args.user, args.password, args.db)
    uri = f"ws://{args.host}:{args.port}"
    await engine.connect(uri)
    await command_loop(engine)


def main() -> None:
    parser = argparse.ArgumentParser(description=PROJECT_NAME)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=None)
    args = parser.parse_args()
    if args.db is None:
        args.db = f"data/{args.user}.db"
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
