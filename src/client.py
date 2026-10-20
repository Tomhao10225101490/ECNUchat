"""Rich 终端客户端：注册/登录、单聊、最多 8 人的逐人棘轮群聊。

群正文不是 Sender Keys。`ChatEngine.send_text` 对每个其他成员各发一封
独立双棘轮信封。这是对 Rösler、Mainka、Schwenk，EuroS&P 2018
（*More is Less*，ePrint 2017/713）的回应：他们指出 Signal / WhatsApp
的群对称链继承不到两人双棘轮的 future secrecy。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
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
from src.social import clean_file_payload, clean_filename
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
    friends: list[dict[str, Any]] = field(default_factory=list)
    incoming_requests: list[dict[str, Any]] = field(default_factory=list)
    outgoing_requests: list[dict[str, Any]] = field(default_factory=list)
    blocked_users: list[dict[str, Any]] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    privacy: dict[str, Any] = field(default_factory=dict)
    moments: list[dict[str, Any]] = field(default_factory=list)
    rejected_requests: list[dict[str, Any]] = field(default_factory=list)
    _send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    ws: Any = None
    _waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    _incoming_raw: asyncio.Queue = field(default_factory=asyncio.Queue)
    _tasks: list[asyncio.Task] = field(default_factory=list)
    _peer_locks: dict[str, asyncio.Lock] = field(default_factory=dict)

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
            async with self._send_lock:
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
            await self._retry_pending_prekeys()
        except Exception:
            self.last_error = "预密钥补充将在下次登录重试"
        try:
            await self.refresh_social()
        except Exception:
            self.last_error = "好友和朋友圈将在下次同步"

    async def _retry_outboxes(self) -> None:
        """重连后重发原始加密信封，不再次推进双棘轮。"""
        for peer in self.store.list_outbox_peers():
            payload = self.store.load_outbox(peer)
            if payload is None:
                continue
            try:
                await self.request(
                    {
                        "type": "envelope",
                        "from": self.username,
                        "to": peer,
                        "payload": payload,
                    },
                    "envelope_ok",
                )
            except Exception:
                self.last_error = "待发加密信封将在下次重连重试"
                continue
            self.store.delete_outbox(peer)
            if payload.get("x3dh") is not None:
                self.pending_x3dh.pop(peer, None)

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
                if typ in {"envelope", "group_update", "presence", "social_update", "moment_update"} or (
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
        elif typ == "social_update":
            self._apply_social(msg)
            await self.inbox.put(Incoming("系统", "", None, "social"))
        elif typ == "moment_update":
            try:
                await self.refresh_moments()
            except Exception:
                self.last_error = "朋友圈刷新失败"
            await self.inbox.put(Incoming("系统", "", None, "moment"))
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
        """发送一条聊天正文。群消息按成员扇出，每人一封双棘轮信封。

        对每个其他成员调用一次 `_send_one`，走已经建立的那一对双棘轮。
        没有全群共用的发送者钥匙，也没有一条群对称链。桌面端和终端端
        都走这里。

        Rösler、Mainka、Schwenk 在 EuroS&P 2018 分析的 Signal / WhatsApp
        群，先用两人会话分发一把 Sender Key，群正文再走这把钥匙自己的
        对称链。两人双棘轮上的 future secrecy 不会自动继承到那条群链。
        逐人信封把每一封留在那一对的 `kdf_ck` 和回复触发的 DH 棘轮上。
        正式题名是 *More is Less: On the End-to-End Security of Group
        Chats in Signal, WhatsApp, and Threema*。

        成员名单仍是服务器记录（`group_create` / `group_add`）。论文里的
        群完整性与「谁有权管理群」没有被这个扇出补上。`group_meta` 只是
        把通知正文放进同一套逐人信封。
        """
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
        filename: str,
        data: bytes,
        *,
        peer: str | None = None,
        group: str | None = None,
        caption: str = "",
    ) -> None:
        """把文件放进双棘轮信封。服务器只转发密文，投递箱只在本机解开。"""
        payload = clean_file_payload(
            {"name": filename, "data": base64.b64encode(data).decode("ascii")}
        )
        assert payload is not None
        label = f"[文件] {payload['name']}"
        shown = f"{caption.strip()}\n{label}" if caption.strip() else label
        if group:
            members = self.groups.get(group) or []
            others = [m for m in members if m != self.username]
            if not others:
                raise ProtocolError("群里没有其他成员")
            self.store.add_history(f"group:{group}", self.username, shown)
            delivered = 0
            try:
                for other in others:
                    await self._send_one(
                        other, caption, group=group, kind="chat", file=payload
                    )
                    delivered += 1
            except Exception:
                self.store.add_history(
                    f"group:{group}",
                    "系统",
                    f"文件仅送达 {delivered}/{len(others)} 人，可稍后重试",
                )
                raise
            self._write_dropbox(group, payload["name"], payload["data"], "out")
            return
        dest = peer or self.current_peer
        if not dest:
            raise ProtocolError("先用 /chat 名字 选择对端")
        await self._send_one(dest, caption, group=None, kind="chat", file=payload)
        self.store.add_history(f"dm:{dest}", self.username, shown)
        self._write_dropbox(dest, payload["name"], payload["data"], "out")

    async def _send_one(
        self,
        peer: str,
        text: str,
        *,
        group: str | None,
        kind: str,
        file: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        lock = self._peer_locks.setdefault(peer, asyncio.Lock())
        async with lock:
            pending_payload = self.store.load_outbox(peer)
            if pending_payload is not None:
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
            state = await self._ensure_session_for_send(peer)
            x3dh = self.pending_x3dh.get(peer)
            body: dict[str, Any] = {"v": 1, "text": text, "group": group, "kind": kind}
            if file is not None:
                body["file"] = clean_file_payload(file)
            inner = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            msg, _mk = encrypt(state, inner)
            # 消息钥匙用后即弃：MK 不进棘轮状态，也不进日志。
            # 这是 CRYPTO 2022 对称棘轮的一次性消息钥匙，不是把 MK 留到下一世代。
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
            text, verified_group, verified_kind, file_payload = await self._decrypt_envelope(
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
        conv = f"group:{group}" if group else f"dm:{sender}"
        who = "系统" if verified_kind == "group_meta" else sender
        if file_payload is not None:
            label = f"[文件] {file_payload['name']}"
            text = f"{text}\n{label}" if text else label
            try:
                self._write_dropbox(
                    group or sender,
                    file_payload["name"],
                    file_payload["data"],
                    "in",
                )
            except Exception:
                self.last_error = "文件已解密，但没有写进投递箱"
        self.store.add_history(conv, who, text)
        await self.inbox.put(Incoming(who, text, group, verified_kind))

    def _fail(self, sender: str, group: str | None, phrase: str) -> None:
        self.last_error = phrase
        conv = f"group:{group}" if group else (f"dm:{sender}" if sender else None)
        if conv:
            self.store.add_history(conv, "系统", phrase)
        self.inbox.put_nowait(Incoming(sender, "", group, "error", phrase))

    def _write_dropbox(self, peer: str, name: str, data_b64: str, direction: str) -> None:
        raw = base64.b64decode(data_b64)
        item_id = uuid.uuid4().hex
        safe = clean_filename(name)
        folder = Path(self.store.path).parent / "dropbox" / self.username
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{item_id}_{safe}"
        path.write_bytes(raw)
        self.store.add_dropbox(item_id, peer, safe, direction, len(raw), str(path))

    async def _decrypt_envelope(
        self, sender: str, payload: dict[str, Any]
    ) -> tuple[str, str | None, str, dict[str, str] | None]:
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
        # 解开后的 MK 立即丢掉。跳过缓存里的那一把已在 decrypt 内弹出。
        del mk
        try:
            inner = json.loads(plaintext.decode("utf-8"))
            if not isinstance(inner, dict) or inner.get("v") != 1:
                raise ValueError
            text = inner["text"]
            verified_group = inner.get("group")
            verified_kind = inner.get("kind", "chat")
            if not isinstance(text, str) or verified_group != payload.get("group"):
                raise ValueError
            if verified_kind != (payload.get("kind") or "chat"):
                raise ValueError
            file_payload = None
            if inner.get("file") is not None:
                file_payload = clean_file_payload(inner.get("file"))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError, ProtocolError) as exc:
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
        return text, verified_group, verified_kind, file_payload

    def _apply_social(self, msg: dict[str, Any]) -> None:
        self.friends = list(msg.get("friends") or [])
        self.incoming_requests = list(msg.get("incoming") or [])
        self.outgoing_requests = list(msg.get("outgoing") or [])
        self.blocked_users = list(msg.get("blocked") or [])
        self.rejected_requests = list(msg.get("rejected") or [])

    def friend_names(self) -> set[str]:
        return {str(item.get("username")) for item in self.friends}

    async def refresh_social(self) -> None:
        state = await self.request({"type": "friend_list"}, "friend_state")
        self._apply_social(state)
        profile = await self.request({"type": "profile_get"}, "profile")
        self.profile = dict(profile.get("profile") or {})
        privacy = await self.request({"type": "privacy_get"}, "privacy")
        self.privacy = dict(privacy.get("privacy") or {})
        await self.refresh_moments()

    async def refresh_moments(self) -> None:
        feed = await self.request({"type": "moment_feed"}, "moment_feed")
        moments = list(feed.get("moments") or [])
        loaded = 0
        for item in moments:
            if not item.get("has_image") or loaded >= 8:
                continue
            try:
                detail = await self.request(
                    {"type": "moment_get", "id": item.get("id")}, "moment_item"
                )
            except Exception:
                continue
            image = str((detail.get("moment") or {}).get("image") or "")
            if image:
                item["image"] = image
                loaded += 1
        self.moments = moments

    async def friend_request(self, username: str, greeting: str = "") -> dict[str, Any]:
        state = await self.request(
            {"type": "friend_request", "to": username, "greeting": greeting},
            "friend_state",
        )
        self._apply_social(state)
        return state

    async def friend_respond(self, username: str, accept: bool) -> dict[str, Any]:
        state = await self.request(
            {"type": "friend_respond", "username": username, "accept": bool(accept)},
            "friend_state",
        )
        self._apply_social(state)
        return state

    async def friend_remove(self, username: str) -> dict[str, Any]:
        state = await self.request(
            {"type": "friend_remove", "username": username},
            "friend_state",
        )
        self._apply_social(state)
        return state

    async def friend_block(self, username: str) -> dict[str, Any]:
        state = await self.request(
            {"type": "friend_block", "username": username},
            "friend_state",
        )
        self._apply_social(state)
        return state

    async def search_users(self, query: str) -> dict[str, Any]:
        return await self.request({"type": "user_search", "query": query}, "user_search")

    async def profile_set(self, display_name: str, bio: str, avatar: str) -> dict[str, Any]:
        result = await self.request(
            {
                "type": "profile_set",
                "display_name": display_name,
                "bio": bio,
                "avatar": avatar,
            },
            "profile",
        )
        self.profile = dict(result.get("profile") or {})
        return self.profile

    async def privacy_set(
        self,
        *,
        require_approval: bool,
        moments_visibility: str,
        show_online: bool,
        searchable: bool,
    ) -> dict[str, Any]:
        result = await self.request(
            {
                "type": "privacy_set",
                "require_approval": bool(require_approval),
                "moments_visibility": moments_visibility,
                "show_online": bool(show_online),
                "searchable": bool(searchable),
            },
            "privacy",
        )
        self.privacy = dict(result.get("privacy") or {})
        return self.privacy

    async def moment_post(
        self, body: str, image: str = "", visibility: str = "friends"
    ) -> dict[str, Any]:
        result = await self.request(
            {
                "type": "moment_post",
                "body": body,
                "image": image,
                "visibility": visibility,
            },
            "moment_ok",
        )
        await self.refresh_moments()
        return result

    async def moment_delete(self, moment_id: str) -> None:
        await self.request({"type": "moment_delete", "id": moment_id}, "moment_ok")
        await self.refresh_moments()

    async def moment_like(self, moment_id: str) -> None:
        await self.request({"type": "moment_like", "id": moment_id}, "moment_ok")
        await self.refresh_moments()

    async def moment_comment(self, moment_id: str, body: str) -> None:
        await self.request(
            {"type": "moment_comment", "id": moment_id, "body": body},
            "moment_ok",
        )
        await self.refresh_moments()

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
        "/group add 群名 新成员  /history  /users  /help  /quit[/dim]"
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
        lines.append(f"{sender}: {body}")
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
    if cmd == "/friend" and len(parts) >= 3:
        action, name = parts[1], parts[2]
        validate_username(name)
        if action == "add":
            greeting = line.split(maxsplit=3)[3] if len(parts) > 3 else ""
            await engine.friend_request(name, greeting)
            if name in engine.friend_names():
                return CommandResult(notice=f"{name} 已是好友")
            return CommandResult(notice=f"已向 {name} 发出好友申请")
        if action == "accept":
            await engine.friend_respond(name, True)
            return CommandResult(notice=f"已同意 {name}")
        if action == "reject":
            await engine.friend_respond(name, False)
            return CommandResult(notice=f"已拒绝 {name}")
        if action in {"remove", "cancel"}:
            await engine.friend_remove(name)
            return CommandResult(notice=f"已解除与 {name} 的关系")
        if action == "block":
            await engine.friend_block(name)
            return CommandResult(notice=f"已拉黑 {name}")
        raise ProtocolError("用法：/friend add|accept|reject|remove|block 名字")
    if cmd == "/friends":
        rows = ["好友"]
        rows.extend(
            f"  {item['username']}  {item.get('display_name') or ''}" for item in engine.friends
        )
        if engine.incoming_requests:
            rows.append("待我同意")
            rows.extend(
                f"  {item['username']}  {item.get('greeting') or ''}"
                for item in engine.incoming_requests
            )
        if engine.outgoing_requests:
            rows.append("等待对方同意")
            rows.extend(f"  {item['username']}" for item in engine.outgoing_requests)
        if engine.rejected_requests:
            rows.append("对方未通过")
            rows.extend(f"  {item['username']}" for item in engine.rejected_requests)
        if engine.blocked_users:
            rows.append("已拉黑")
            rows.extend(f"  {item['username']}" for item in engine.blocked_users)
        return CommandResult(overlay="\n".join(rows))
    if cmd == "/search" and len(parts) >= 2:
        found = await engine.search_users(line.split(maxsplit=1)[1])
        rows = ["用户          关系"]
        for item in found.get("users") or []:
            rows.append(f"{item['username']:<14}{item.get('relation') or ''}")
        return CommandResult(overlay="\n".join(rows) if len(rows) > 1 else "没有匹配的用户")
    if cmd == "/profile":
        if len(parts) == 1:
            profile = engine.profile
            body = (
                f"{profile.get('display_name') or engine.username}\n"
                f"{profile.get('bio') or '还没有简介'}"
            )
            return CommandResult(overlay=body)
        name = line.split(maxsplit=1)[1]
        await engine.profile_set(name, str(engine.profile.get("bio") or ""), str(engine.profile.get("avatar") or ""))
        return CommandResult(notice=f"昵称已改为 {engine.profile.get('display_name')}")
    if cmd == "/bio":
        bio = line.split(maxsplit=1)[1] if len(parts) > 1 else ""
        await engine.profile_set(
            str(engine.profile.get("display_name") or engine.username),
            bio,
            str(engine.profile.get("avatar") or ""),
        )
        return CommandResult(notice="简介已更新")
    if cmd == "/privacy" and len(parts) == 3:
        privacy = {
            "require_approval": bool(engine.privacy.get("require_approval", True)),
            "moments_visibility": str(engine.privacy.get("moments_visibility") or "friends"),
            "show_online": bool(engine.privacy.get("show_online", True)),
            "searchable": bool(engine.privacy.get("searchable", True)),
        }
        key, value = parts[1], parts[2]
        flag = value in {"on", "1", "true", "yes"}
        if key == "approval":
            privacy["require_approval"] = flag
        elif key == "online":
            privacy["show_online"] = flag
        elif key == "search":
            privacy["searchable"] = flag
        elif key == "moments" and value in {"friends", "three_days", "none"}:
            privacy["moments_visibility"] = value
        else:
            raise ProtocolError("用法：/privacy approval|online|search on|off，或 /privacy moments friends|three_days|none")
        await engine.privacy_set(**privacy)
        return CommandResult(notice="隐私设置已保存")
    if cmd == "/moment":
        if len(parts) == 1:
            await engine.refresh_moments()
            if not engine.moments:
                return CommandResult(notice="朋友圈还是空的")
            rows = []
            for item in engine.moments:
                rows.append(
                    f"{item.get('display_name') or item.get('author')}  {item.get('body') or '[图片]'}"
                )
            return CommandResult(overlay="\n".join(rows))
        await engine.moment_post(line.split(maxsplit=1)[1])
        return CommandResult(notice="已发布到朋友圈")
    if cmd == "/file" and len(parts) >= 2:
        path = Path(line.split(maxsplit=1)[1])
        data = path.read_bytes()
        if engine.current_group:
            await engine.send_file(path.name, data, group=engine.current_group)
        else:
            await engine.send_file(path.name, data)
        engine.last_error = None
        return CommandResult(notice=f"已投递 {path.name}")
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
