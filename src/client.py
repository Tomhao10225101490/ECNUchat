"""Rich 终端客户端：注册/登录、单聊、最多 8 人的逐人棘轮群聊。

群正文不是 Sender Keys。`ChatEngine.send_text` 对每个其他成员各发一封
独立双棘轮信封。这是对 Rösler、Mainka、Schwenk，EuroS&P 2018
（*More is Less*，ePrint 2017/713）的回应：他们指出 Signal / WhatsApp
的群对称链继承不到两人双棘轮的 future secrecy。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
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
    FILE_PLAIN_CHUNK,
    MAX_FILE_BYTES,
    AttachmentError,
    attachment_root,
    attachment_view,
    cache_rel,
    cipher_len,
    clear_playback_files,
    decrypt_chunk,
    display_text,
    encrypt_chunk,
    export_cipher_pack,
    guess_mime,
    hash_file,
    history_body,
    materialize_plain,
    media_kind,
    plaintext_len,
    meta_from_dict,
    meta_to_dict,
    new_file_meta,
    place_local_copy,
    read_plain_chunk,
    resolve_rel,
    seal_path,
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
from src.groups import (
    GroupStateError,
    build_add_state,
    build_genesis_state,
    verify_group_state_sig,
    verify_state_transition,
)
from src.prekeys import (
    MLKEM768_PUB_LEN,
    PqOneTimePrekey,
    generate_identity,
    generate_x25519,
    sign_bytes,
    verify_pq,
    verify_pq_opk,
    verify_spk,
)
from src.protocol import (
    MAX_BLOB_FRAME,
    ProtocolError,
    b64d,
    b64e,
    check_size,
    decode_group_state,
    decode_ratchet_payload,
    dumps,
    encode_group_state,
    encode_ratchet_payload,
    fingerprint,
    fingerprint_short,
    loads,
    pack_blob_frame,
    unpack_blob_frame,
    validate_username,
)
from src.store import ClientStore
from src.x3dh import (
    X3DHError,
    build_initial_message,
    initiator_hybrid_secret,
    initiator_secret,
    responder_hybrid_secret,
    responder_secret,
    verify_initial,
)

console = Console()
CHUNK_WINDOW = 8
BLOB_TIMEOUT = 120.0


@dataclass
class Incoming:
    sender: str
    text: str
    group: str | None
    kind: str
    error: str | None = None
    attachment: dict[str, Any] | None = None
    local_id: str | None = None


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
    group_chain: dict[str, list] = field(default_factory=dict)
    peer_keys: dict[str, tuple[bytes, bytes, bytes | None]] = field(default_factory=dict)
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
    rejected_requests: list[dict[str, Any]] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    privacy: dict[str, Any] = field(default_factory=dict)
    moments: list[dict[str, Any]] = field(default_factory=list)
    group_incoming: list[dict[str, Any]] = field(default_factory=list)
    group_outgoing: list[dict[str, Any]] = field(default_factory=list)
    group_requests: list[dict[str, Any]] = field(default_factory=list)
    group_joining: list[dict[str, Any]] = field(default_factory=list)
    _sign_queue: set[tuple[str, str]] = field(default_factory=set)
    _group_locks: dict[str, asyncio.Lock] = field(default_factory=dict)
    _send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
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
        engine._sign_queue = engine._load_sign_queue()
        clear_playback_files(store.path)
        for name in engine.groups:
            engine.group_chain[name] = store.load_group_chain(name)
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
        for name, chain in self.group_chain.items():
            for state in chain:
                self.store.save_group_state(state)

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

    async def send_json(self, obj: dict[str, Any], *, blob: bool = False) -> None:
        raw = dumps(obj)
        check_size(raw, MAX_BLOB_FRAME if blob else None)
        await self.ws.send(raw)

    def _arm(self, request_id: str) -> asyncio.Future:
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._waiters[request_id] = fut
        return fut

    def _disarm(self, request_id: str) -> None:
        self._waiters.pop(request_id, None)

    async def request(
        self,
        obj: dict[str, Any],
        *expect: str,
        timeout: float | None = None,
        blob: bool | None = None,
    ) -> dict[str, Any]:
        if not self.connected and obj.get("type") not in {"register", "login"}:
            raise ProtocolError("连接已断开")
        request_id = uuid.uuid4().hex
        request_obj = dict(obj)
        request_obj["request_id"] = request_id
        kind = str(request_obj.get("type") or "")
        if blob is None:
            blob = kind == "blob_chunk"
        if timeout is None:
            timeout = BLOB_TIMEOUT if kind.startswith("blob_") else 15
        fut = self._arm(request_id)
        try:
            async with self._send_lock:
                await self.send_json(request_obj, blob=blob)
            result = await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._disarm(request_id)
        if result.get("type") == "error":
            raise ProtocolError(result.get("message") or "服务器错误")
        if expect and result.get("type") not in expect:
            raise ProtocolError(f"响应类型错误：{result.get('type')}")
        return result

    async def connect(self, uri: str) -> None:
        # 密文压不下去。默认的 permessage-deflate 会把大视频拖慢一个数量级。
        self.ws = await websockets.connect(uri, max_size=MAX_BLOB_FRAME, compression=None)
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
                "__registered__",
                self.identity.ik_sign_pub,
                self.identity.ik_dh_pub,
                self.identity.pq_pub,
            )
        await self._retry_outboxes()
        try:
            await self._retry_incoming_files()
        except Exception:
            self.last_error = "文件下载将在下次连接重试"
        try:
            await self._retry_pending_prekeys()
            await self._ensure_local_prekey_pools()
        except Exception:
            self.last_error = "预密钥补充将在下次登录重试"
        try:
            await self.refresh_social()
        except Exception:
            self.last_error = "好友和朋友圈将在下次同步"
        try:
            await self.refresh_group_invites()
        except Exception:
            self.last_error = "群邀请将在下次同步"

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
        pending_pq = self.store.load_pending_pq_opks()
        if not pending and not pending_pq:
            return
        payload: dict[str, Any] = {"type": "upload_prekeys"}
        if pending:
            payload["opks"] = [b64e(pub) for pub in pending]
        if pending_pq:
            payload["pq_opks"] = [
                {"pub": b64e(pub), "sig": b64e(sig)} for pub, sig in pending_pq
            ]
        await self.request(payload, "upload_prekeys_ok")
        if pending:
            self.store.clear_pending_prekeys()
        if pending_pq:
            self.store.clear_pending_pq_opks()

    async def _push_prekeys(
        self, opks: list[Any], pq_opks: list[PqOneTimePrekey]
    ) -> None:
        """先把待上传公钥写入保险库，再发给服务器。失败则下次登录重试。"""
        if not opks and not pq_opks:
            return
        if opks:
            self.store.save_pending_prekeys([item.pub for item in opks])
        if pq_opks:
            self.store.save_pending_pq_opks(
                [(item.pub, item.signature) for item in pq_opks]
            )
        payload: dict[str, Any] = {"type": "upload_prekeys"}
        if opks:
            payload["opks"] = [b64e(item.pub) for item in opks]
        if pq_opks:
            payload["pq_opks"] = [
                {"pub": b64e(item.pub), "sig": b64e(item.signature)} for item in pq_opks
            ]
        await self.request(payload, "upload_prekeys_ok")
        if opks:
            self.store.clear_pending_prekeys()
        if pq_opks:
            self.store.clear_pending_pq_opks()

    async def _ensure_local_prekey_pools(self) -> None:
        """旧保险库没有一次性 PQ 预密钥时，登录后补池并上传。"""
        opk_created = self.identity.refill_opks() if self.identity.needs_refill() else []
        pq_created = (
            self.identity.refill_pq_opks() if self.identity.needs_pq_refill() else []
        )
        if not opk_created and not pq_created:
            return
        self.store.save_identity(self.identity)
        await self._push_prekeys(opk_created, pq_created)

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
                "pq_pub": b64e(self.identity.pq_pub),
                "pq_sig": b64e(self.identity.pq_sig),
                "pq_opks": [
                    {"pub": b64e(item.pub), "sig": b64e(item.signature)}
                    for item in self.identity.pq_opks
                ],
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
                if not isinstance(raw, str):
                    frame = unpack_blob_frame(raw if isinstance(raw, (bytes, bytearray)) else bytes(raw))
                    if frame is None:
                        continue
                    _kind, request_id, file_id, index, data = frame
                    waiter = self._waiters.get(request_id)
                    if waiter is not None and not waiter.done():
                        waiter.set_result(
                            {
                                "type": "blob_fetch_ok",
                                "id": file_id,
                                "idx": index,
                                "_bin": data,
                                "request_id": request_id,
                            }
                        )
                    continue
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
                if typ in {
                    "envelope",
                    "group_update",
                    "presence",
                    "social_update",
                    "moment_update",
                    "group_invite",
                    "group_join_ready",
                } or (
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
            name = msg.get("group", "")
            if msg.get("state"):
                await self._on_group_update(name, msg["state"])
            else:
                self._fail("", name, "群状态缺少签名，已拒绝未受保护的成员表")
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
        elif typ == "group_invite":
            await self._refresh_group_invites_quietly()
            await self.inbox.put(Incoming("系统", "", None, "presence"))
        elif typ == "group_join_ready":
            await self._complete_join(str(msg.get("group") or ""), str(msg.get("username") or ""))
            await self.inbox.put(Incoming("系统", "", None, "presence"))
        elif typ == "error":
            self.last_error = msg.get("message")
            await self.inbox.put(Incoming("", "", None, "sys", self.last_error))

    async def _on_group_update(self, name: str, raw_state: dict[str, Any]) -> None:
        """端到端验证一条群状态：验签 + 哈希链 + 授权，失败即拒绝。

        这是群成员完整性的防线：服务器只能转发合法成员签署的状态，
        伪造名单在这里被拦下。
        """
        try:
            state = decode_group_state(raw_state)
        except ProtocolError as exc:
            self._fail("", name, f"群状态无效：{exc}")
            return
        chain = self.group_chain.get(name) or []
        if chain and state.epoch <= chain[-1].epoch:
            return  # 已经验证过的纪元，幂等忽略
        previous = chain[-1] if chain else None
        try:
            verify_state_transition(previous, state)
            ik_sign, _, _ = await self.fetch_user(state.signer)
            verify_group_state_sig(state, ik_sign)
        except (GroupStateError, ProtocolError, X3DHError, InvalidSignature) as exc:
            # 可能是缺链（例如刚被拉进群，还没见过创世状态）。先同步补链：
            # 同步本身会整链验证，伪造的名单在同步里同样过不去。
            try:
                await self.sync_group(name)
            except Exception:
                self._fail("", name, f"群状态签名无效，已拒绝：{exc}")
                return
            chain_now = self.group_chain.get(name) or []
            if not chain_now or chain_now[-1].epoch < state.epoch:
                self._fail("", name, f"群状态签名无效，已拒绝：{exc}")
                return
            await self._refresh_group_invites_quietly()
            return
        chain.append(state)
        self.group_chain[name] = chain
        self.groups[name] = list(state.members)
        self.store.save_group_state(state)
        self.store.save_group(name, list(state.members))
        await self._refresh_group_invites_quietly()

    async def sync_group(self, name: str) -> None:
        """补拉群状态链并整体验证。漏投状态（而非伪造）靠这里发现。"""
        result = await self.request({"type": "group_sync", "group": name}, "group_states")
        raw_states = result.get("states") or []
        if not raw_states:
            return
        chain: list = []
        for raw in raw_states:
            state = decode_group_state(raw)
            verify_state_transition(chain[-1] if chain else None, state)
            ik_sign, _, _ = await self.fetch_user(state.signer)
            verify_group_state_sig(state, ik_sign)
            chain.append(state)
        self.group_chain[name] = chain
        self.groups[name] = list(chain[-1].members)
        self.store.save_group(name, list(chain[-1].members))
        for state in chain:
            self.store.save_group_state(state)

    async def fetch_user(self, name: str) -> tuple[bytes, bytes, bytes | None]:
        if name in self.peer_keys:
            return self.peer_keys[name]
        cached = self.store.load_peer(name)
        if cached:
            self.peer_keys[name] = cached
            return cached
        info = await self.request({"type": "fetch_user", "username": name}, "user")
        keys = (
            b64d(info["ik_sign_pub"]) or b"",
            b64d(info["ik_dh_pub"]) or b"",
            b64d(info.get("ik_pq_pub")),
        )
        self.peer_keys[name] = keys
        self.store.save_peer(name, keys[0], keys[1], keys[2])
        return keys

    async def start_session(self, peer: str) -> RatchetState:
        if peer in self.sessions:
            return self.sessions[peer]
        bundle = await self.request(
            {"type": "fetch_bundle", "username": peer, "consume_pq_opk": True},
            "bundle",
        )
        ik_sign = b64d(bundle["ik_sign_pub"]) or b""
        ik_dh = b64d(bundle["ik_dh_pub"]) or b""
        spk_pub = b64d(bundle["spk_pub"]) or b""
        spk_sig = b64d(bundle["spk_sig"]) or b""
        pq_pub = b64d(bundle.get("pq_pub"))
        pq_sig = b64d(bundle.get("pq_sig"))
        try:
            verify_spk(ik_sign, spk_pub, peer, spk_sig)
        except InvalidSignature as exc:
            self.last_error = "对方预密钥签名无效"
            raise X3DHError("对方预密钥签名无效") from exc
        if pq_pub is not None and pq_sig is not None:
            try:
                verify_pq(ik_sign, pq_pub, peer, pq_sig)
            except InvalidSignature as exc:
                self.last_error = "对方 PQ 密钥签名无效"
                raise X3DHError("对方 PQ 密钥签名无效") from exc
        if (pq_pub is None) != (pq_sig is None):
            raise X3DHError("对方预密钥包里的 PQK 公钥与签名不配套")
        pinned = self.store.load_peer(peer)
        if pinned is not None:
            p_sign, p_dh, p_pq = pinned
            if (
                p_sign != ik_sign
                or p_dh != ik_dh
                or (p_pq is not None and p_pq != pq_pub)
            ):
                self.last_error = "身份密钥发生变化"
                raise X3DHError("身份密钥发生变化：已拒绝覆盖已核对的指纹")
        self.peer_keys[peer] = (ik_sign, ik_dh, pq_pub)
        if pinned is None:
            self.store.save_peer(peer, ik_sign, ik_dh, pq_pub)
        ek_priv, ek_pub = generate_x25519()
        opk = b64d(bundle.get("opk"))
        pq_opk = b64d(bundle.get("pq_opk"))
        pq_opk_sig = b64d(bundle.get("pq_opk_sig"))
        if (pq_opk is None) != (pq_opk_sig is None):
            raise X3DHError("对方一次性 PQ 预密钥与签名不配套")
        if pq_opk is not None and (
            len(pq_opk) != MLKEM768_PUB_LEN or pq_opk_sig is None or len(pq_opk_sig) != 64
        ):
            raise X3DHError("对方一次性 PQ 预密钥长度无效")
        if pq_pub is not None and self.identity.pq_pub is not None:
            # 有签过名的一次性钥就用它；服务器扣留时才落到长期 PQK。
            # 棘轮封装目标始终是长期 PQK，不用这把一次性钥。
            ek_target = pq_pub
            handshake_pq = "pqk"
            if pq_opk is not None and pq_opk_sig is not None:
                try:
                    verify_pq_opk(ik_sign, pq_opk, peer, pq_opk_sig)
                except InvalidSignature as exc:
                    self.last_error = "对方一次性 PQ 预密钥签名无效"
                    raise X3DHError("对方一次性 PQ 预密钥签名无效") from exc
                ek_target = pq_opk
                handshake_pq = "pqopk"
            sk, pq_ct = initiator_hybrid_secret(
                self.identity.ik_dh_priv,
                ek_priv,
                spk_pub,
                ik_dh,
                opk,
                ek_target,
            )
            state = init_sender(
                sk,
                spk_pub,
                self.username,
                peer,
                remote_pq_pk=pq_pub,
                handshake_pq=handshake_pq,
            )
            self.pending_x3dh[peer] = build_initial_message(
                self.identity.ik_sign_priv,
                self.identity.ik_dh_pub,
                ek_pub,
                opk,
                ik_pq_pub_a=self.identity.pq_pub,
                pq_ek_pub=ek_target,
                pq_ct=pq_ct,
            )
        else:
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
        if peer not in self.sessions:
            return await self.start_session(peer)
        state = self.sessions[peer]
        # 旧会话迁移：状态里没有对端 PQK 公钥时补拉 bundle。
        # 之后这条会话换出的每条新链都混入 PQ，升级前的旧消息仍是经典密文。
        if state.remote_pq_pk is None:
            pq_pub = await self._upgrade_pq_key(peer)
            if pq_pub is not None:
                state.remote_pq_pk = pq_pub
                self.store.save_session(peer, state)
        return state

    async def _upgrade_pq_key(self, peer: str) -> bytes | None:
        """拉取对端 bundle 并核验 PQK 签名，返回已固定的 PQK 公钥。"""
        try:
            bundle = await self.request(
                {"type": "fetch_bundle", "username": peer}, "bundle"
            )
        except ProtocolError:
            return None
        pq_pub = b64d(bundle.get("pq_pub"))
        pq_sig = b64d(bundle.get("pq_sig"))
        if pq_pub is None or pq_sig is None:
            return None
        ik_sign = b64d(bundle["ik_sign_pub"]) or b""
        verify_pq(ik_sign, pq_pub, peer, pq_sig)
        keys = self.store.load_peer(peer)
        if keys and keys[2] is not None and keys[2] != pq_pub:
            raise X3DHError("对端 PQK 发生变化，已拒绝降级")
        self.store.save_peer(peer, ik_sign, b64d(bundle["ik_dh_pub"]) or b"", pq_pub)
        self.peer_keys[peer] = (ik_sign, b64d(bundle["ik_dh_pub"]) or b"", pq_pub)
        return pq_pub

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

        成员名单来自已验签的哈希链，不听服务器口头宣布。每封群消息的
        内层 JSON 带上 `gstate`。`group_meta` 用同一套逐人信封。
        """
        if group:
            state = self._verified_group_state(group)
            members = list(state.members)
            others = [m for m in members if m != self.username]
            if not others:
                raise ProtocolError("群里没有其他成员")
            gstate = state.state_hash().hex()
            self.store.add_history(f"group:{group}", self.username, text)
            delivered = 0
            try:
                for other in others:
                    await self._send_one(
                        other, text, group=group, kind="chat", gstate=gstate
                    )
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
        await self._send_one(dest, text, group=None, kind="chat", gstate=None)
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
        gstate = None
        if group:
            state = self._verified_group_state(group)
            members = list(state.members)
            recipients = sorted(member for member in members if member != self.username)
            if not recipients:
                raise ProtocolError("群里没有其他成员")
            conv = f"group:{group}"
            target_group: str | None = group
            gstate = state.state_hash().hex()
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
            record = await asyncio.to_thread(
                self._new_file_job,
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
            record["gstate"] = gstate
        else:
            recipients = list(record["recipients"])
            conv = str(record["conv"])
            target_group = record.get("group")
        if record.get("sealed"):
            self.store.save_file_cache(str(record["meta"]["id"]), dict(record["meta"]))
        if not record.get("uploaded"):
            self.store.save_file_job(local_id, record)
            await self._upload_file(record)
            record["uploaded"] = True
            record["history"] = self._file_history_body(record)
        elif not record.get("history"):
            record["history"] = self._file_history_body(record)
        self.store.save_file_job(local_id, record)
        self.store.save_message_status(local_id, conv, str(record["history"]), "sending")
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
        size = max(int(record["meta"]["size"]), 1)
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
        root = attachment_root(self.store.path)
        sealed = False
        if data is None:
            if not path:
                raise ProtocolError("没有要发送的文件")
            file_path = Path(path)
            if not file_path.is_file():
                raise ProtocolError("文件不存在")
            size = file_path.stat().st_size
            if size > MAX_FILE_BYTES:
                raise ProtocolError("文件超过 8GiB")
            filename = filename or file_path.name
            chosen_mime = mime or guess_mime(filename)
            if media_kind(chosen_mime) == "video":
                try:
                    meta = seal_path(file_path, root / "cache", filename, chosen_mime)
                except AttachmentError as exc:
                    raise ProtocolError(exc.message) from exc
                rel = cache_rel(meta.file_id)
                sealed = True
            else:
                try:
                    meta = new_file_meta(size, filename, mime)
                except AttachmentError as exc:
                    raise ProtocolError(exc.message) from exc
                rel = f"files/{meta.file_id.hex()}/{meta.name}"
                place_local_copy(file_path, root / rel)
        else:
            if len(data) > MAX_FILE_BYTES:
                raise ProtocolError("文件超过 8GiB")
            payload = bytes(data)
            filename = filename or "file"
            chosen_mime = mime or guess_mime(filename)
            if media_kind(chosen_mime) == "video":
                staging = root / "staging"
                staging.mkdir(parents=True, exist_ok=True)
                temporary = staging / f"{uuid.uuid4().hex}.bin"
                temporary.write_bytes(payload)
                try:
                    meta = seal_path(temporary, root / "cache", filename, chosen_mime)
                except AttachmentError as exc:
                    raise ProtocolError(exc.message) from exc
                finally:
                    temporary.unlink(missing_ok=True)
                rel = cache_rel(meta.file_id)
                sealed = True
            else:
                try:
                    meta = new_file_meta(len(payload), filename, mime)
                except AttachmentError as exc:
                    raise ProtocolError(exc.message) from exc
                rel = f"files/{meta.file_id.hex()}/{meta.name}"
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(payload)
        return {
            "local_id": local_id,
            "conv": conv,
            "group": group,
            "recipients": recipients,
            "caption": caption,
            "meta": meta_to_dict(meta),
            "rel": rel,
            "sealed": sealed,
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
            store="cipher" if record.get("sealed") else "plain",
        )

    async def _upload_file(self, record: dict[str, Any]) -> None:
        if record.get("sealed"):
            await self._upload_sealed(record)
            return
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
        src = attachment_root(self.store.path) / str(record["rel"])
        if not src.is_file():
            raise ProtocolError("文件不存在")
        total = max(meta.size, 1)
        sent = 0
        lock = asyncio.Lock()
        failed: list[BaseException] = []
        slots = asyncio.Semaphore(CHUNK_WINDOW)
        hasher = hashlib.sha256()
        fd = os.open(src, os.O_RDONLY)
        in_flight: list[asyncio.Task] = []

        def read_and_hash(index: int) -> bytes:
            piece = read_plain_chunk(fd, meta, index)
            hasher.update(piece)
            return piece

        async def send_one(index: int, piece: bytes) -> None:
            nonlocal sent
            try:
                ciphertext = await asyncio.to_thread(encrypt_chunk, meta, index, piece)
                await self._send_blob_chunk(blob_id, index, ciphertext)
                async with lock:
                    sent += len(piece)
                    done = sent
                self._progress(str(record["local_id"]), done, total)
            except Exception as exc:
                failed.append(exc)
            finally:
                slots.release()

        try:
            for index in range(meta.chunks):
                if failed:
                    break
                piece = await asyncio.to_thread(read_and_hash, index)
                await slots.acquire()
                if failed:
                    slots.release()
                    break
                in_flight.append(asyncio.create_task(send_one(index, piece)))
        finally:
            if in_flight:
                await asyncio.gather(*in_flight)
            os.close(fd)
        if failed:
            raise failed[0]
        record["meta"]["sha256"] = b64e(hasher.digest())
        await self.request({"type": "blob_finish", "id": blob_id}, "blob_finish_ok")

    async def _send_blob_chunk(self, blob_id: str, index: int, ciphertext: bytes) -> None:
        request_id = uuid.uuid4().hex
        frame = pack_blob_frame("U", request_id, blob_id, index, ciphertext)
        if len(frame) > MAX_BLOB_FRAME:
            raise ProtocolError("单条 WebSocket 消息超过 8MiB")
        fut = self._arm(request_id)
        try:
            async with self._send_lock:
                await self.ws.send(frame)
            result = await asyncio.wait_for(fut, timeout=BLOB_TIMEOUT)
        finally:
            self._disarm(request_id)
        if result.get("type") == "error":
            raise ProtocolError(result.get("message") or "服务器错误")
        if result.get("type") != "blob_chunk_ok" or result.get("idx") != index:
            raise ProtocolError("分片编号对不上")

    async def _upload_sealed(self, record: dict[str, Any]) -> None:
        """视频缓存已经是分片密文，上传时直接发送这些分片。"""
        meta = meta_from_dict(record["meta"])
        folder = resolve_rel(self.store.path, str(record["rel"]))
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
        total = max(meta.size, 1)
        sent = 0
        lock = asyncio.Lock()

        async def one(index: int) -> None:
            nonlocal sent

            def read() -> bytes:
                blob = (folder / str(index)).read_bytes()
                if len(blob) != cipher_len(meta.size, meta.chunks, index):
                    raise ProtocolError("加密缓存损坏")
                return blob

            ciphertext = await asyncio.to_thread(read)
            await self._send_blob_chunk(blob_id, index, ciphertext)
            async with lock:
                sent += plaintext_len(meta.size, meta.chunks, index)
                done = sent
            self._progress(str(record["local_id"]), done, total)

        await self._run_indexed(meta.chunks, one)
        await self.request({"type": "blob_finish", "id": blob_id}, "blob_finish_ok")

    async def materialize_video(self, file_id: str) -> str:
        raw = self.store.load_file_cache(file_id)
        if raw is None:
            raise ProtocolError("没有这支视频的加密缓存")
        meta = meta_from_dict(raw)
        cache_dir = resolve_rel(self.store.path, cache_rel(meta.file_id))
        dest = attachment_root(self.store.path) / "play" / f"{file_id}.mp4"
        await asyncio.to_thread(materialize_plain, meta, cache_dir, dest)
        return str(dest)

    async def export_video(self, file_id: str, dest: str) -> None:
        raw = self.store.load_file_cache(file_id)
        if raw is None:
            raise ProtocolError("没有这支视频的加密缓存")
        meta = meta_from_dict(raw)
        cache_dir = resolve_rel(self.store.path, cache_rel(meta.file_id))
        await asyncio.to_thread(export_cipher_pack, cache_dir, meta, Path(dest))

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
                    "gstate": record.get("gstate"),
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
        self,
        peer: str,
        text: str,
        *,
        group: str | None,
        kind: str,
        gstate: str | None = None,
    ) -> dict[str, Any]:
        lock = self._peer_locks.setdefault(peer, asyncio.Lock())
        async with lock:
            await self._flush_outbox(peer)
            state = await self._ensure_session_for_send(peer)
            x3dh = self.pending_x3dh.get(peer)
            inner = json.dumps(
                {"v": 1, "text": text, "group": group, "kind": kind, "gstate": gstate},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
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
        local_id = f"in:{blob_id}"
        self.store.save_incoming_file(blob_id, record)
        video = media_kind(meta.mime) == "video"
        rel = cache_rel(meta.file_id) if video else f"files/{blob_id}/{meta.name}"
        dest = attachment_root(self.store.path) / rel
        partial = dest.with_name(dest.name + ".part") if not video else dest
        caption = str(record.get("caption") or "")
        progress_view = {
            "name": meta.name,
            "mime": meta.mime,
            "size": meta.size,
            "sha256": meta.sha256.hex(),
            "path": "",
            "media": media_kind(meta.mime),
            "caption": caption,
            "encrypted": video,
            "file_id": blob_id if video else "",
        }
        await self.inbox.put(
            Incoming(
                str(record["sender"]),
                caption,
                record.get("group"),
                "file_progress",
                local_id=local_id,
                attachment=progress_view,
            )
        )
        try:
            if video:
                await self._download_cipher(meta, dest, local_id)
                self.store.save_file_cache(blob_id, meta_to_dict(meta))
            else:
                await self._download_file(meta, partial, local_id)
        except AttachmentError:
            if video:
                shutil.rmtree(dest, ignore_errors=True)
            else:
                partial.unlink(missing_ok=True)
            self.store.delete_incoming_file(blob_id)
            await self.inbox.put(
                Incoming(
                    str(record["sender"]),
                    "",
                    record.get("group"),
                    "file_abort",
                    local_id=local_id,
                )
            )
            raise
        except Exception:
            if video:
                shutil.rmtree(dest, ignore_errors=True)
            else:
                partial.unlink(missing_ok=True)
            await self.inbox.put(
                Incoming(
                    str(record["sender"]),
                    "",
                    record.get("group"),
                    "file_abort",
                    local_id=local_id,
                )
            )
            raise
        if not video:
            partial.replace(dest)
        body = history_body(
            name=meta.name,
            mime=meta.mime,
            size=meta.size,
            sha256=meta.sha256,
            rel_path=rel,
            caption=caption,
            store="cipher" if video else "plain",
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
            await self.request(
                {"type": "blob_done", "id": blob_id},
                "blob_done_ok",
            )
        except Exception:
            self.last_error = "文件已收下，服务器清理将在下次重试"
        if fresh:
            await self.inbox.put(
                Incoming(
                    str(record["sender"]),
                    display_text(body, self.store.path),
                    record.get("group"),
                    "file",
                    local_id=local_id,
                    attachment=attachment_view(self.store.path, body),
                )
            )

    async def _download_cipher(self, meta: Any, cache_dir: Path, local_id: str) -> None:
        """收下视频密文分片。明文只在校验摘要时在内存里走一块，不落盘。"""
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        got = 0
        lock = asyncio.Lock()
        blob_id = meta.file_id.hex()

        def store_chunk(index: int, ciphertext: bytes) -> int:
            piece = decrypt_chunk(meta, index, ciphertext)
            (cache_dir / str(index)).write_bytes(bytes(ciphertext))
            return len(piece)

        async def one(index: int) -> None:
            nonlocal got
            resp = await self.request(
                {"type": "blob_fetch", "id": blob_id, "idx": index},
                "blob_fetch_ok",
            )
            if resp.get("id") != blob_id or resp.get("idx") != index:
                raise ProtocolError("分片编号对不上")
            data = resp.get("_bin")
            if not isinstance(data, (bytes, bytearray)):
                encoded = resp.get("data")
                data = b64d(encoded) if isinstance(encoded, str) else None
            if data is None:
                raise ProtocolError("分片缺失")
            written = await asyncio.to_thread(store_chunk, index, bytes(data))
            async with lock:
                got += written
                done = got
            self._progress(local_id, done, max(meta.size, 1))

        await self._run_indexed(meta.chunks, one)

        def verify() -> None:
            digest = hashlib.sha256()
            total = 0
            for index in range(meta.chunks):
                ciphertext = (cache_dir / str(index)).read_bytes()
                piece = decrypt_chunk(meta, index, ciphertext)
                digest.update(piece)
                total += len(piece)
            if digest.digest() != meta.sha256 or total != meta.size:
                raise AttachmentError("摘要不一致")

        await asyncio.to_thread(verify)

    async def _download_file(self, meta: Any, dest: Path, local_id: str) -> None:
        blob_id = meta.file_id.hex()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as handle:
            handle.truncate(meta.size)
        got = 0
        lock = asyncio.Lock()
        out = os.open(dest, os.O_RDWR)

        def write_piece(index: int, ciphertext: bytes) -> int:
            piece = decrypt_chunk(meta, index, ciphertext)
            os.pwrite(out, piece, index * FILE_PLAIN_CHUNK)
            return len(piece)

        async def one(index: int) -> None:
            nonlocal got
            resp = await self.request(
                {"type": "blob_fetch", "id": blob_id, "idx": index},
                "blob_fetch_ok",
            )
            if resp.get("id") != blob_id or resp.get("idx") != index:
                raise ProtocolError("分片编号对不上")
            data = resp.get("_bin")
            if not isinstance(data, (bytes, bytearray)):
                encoded = resp.get("data")
                data = b64d(encoded) if isinstance(encoded, str) else None
            if data is None:
                raise ProtocolError("分片缺失")
            written = await asyncio.to_thread(write_piece, index, bytes(data))
            async with lock:
                got += written
                done = got
            self._progress(local_id, done, max(meta.size, 1))

        try:
            await self._run_indexed(meta.chunks, one)
        finally:
            os.close(out)
        digest = await asyncio.to_thread(hash_file, dest)
        if digest != meta.sha256 or dest.stat().st_size != meta.size:
            raise AttachmentError("摘要不一致")

    async def _run_indexed(self, count: int, fn: Any) -> None:
        if count <= 0:
            return
        pending: asyncio.Queue[int] = asyncio.Queue()
        for index in range(count):
            pending.put_nowait(index)
        failed: list[BaseException] = []

        async def worker() -> None:
            while not failed:
                try:
                    index = pending.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    await fn(index)
                except Exception as exc:
                    failed.append(exc)
                    return

        tasks = [asyncio.create_task(worker()) for _ in range(min(CHUNK_WINDOW, count))]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            raise
        if failed:
            raise failed[0]

    async def _decrypt_envelope(
        self, sender: str, payload: dict[str, Any]
    ) -> tuple[str, str | None, str, Any]:
        ratchet_msg, init = decode_ratchet_payload(payload)
        new_identity = False
        consumed_opk: bytes | None = None
        consumed_pq: bytes | None = None
        handshake_pq: str | None = None
        if sender not in self.sessions:
            if init is None:
                raise X3DHError("没有会话且缺少 X3DH 初始消息")
            ik_sign, ik_dh, server_pq = await self.fetch_user(sender)
            try:
                verify_initial(
                    ik_sign,
                    init.ik_dh_pub,
                    init.ek_pub,
                    init.opk_pub,
                    init.signature,
                    init.ik_pq_pub,
                    init.pq_ek_pub,
                    init.pq_ct,
                )
            except X3DHError:
                self.last_error = "验签失败"
                raise
            if init.ik_dh_pub != ik_dh:
                raise X3DHError("验签失败：身份协商公钥与服务器登记不一致")
            hybrid = (
                init.pq_ct is not None
                and init.ik_pq_pub is not None
                and init.pq_ek_pub is not None
            )
            if self.identity.pq_priv is not None and not hybrid:
                # 本机支持 PQ 却收到不完整或经典的初始消息：拒绝静默降级。
                raise X3DHError("缺少 PQ 握手，已拒绝降级")
            if server_pq is not None and init.ik_pq_pub != server_pq:
                raise X3DHError("验签失败：PQ 公钥与服务器登记不一致")
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
            if hybrid:
                if self.identity.pq_priv is None or self.identity.pq_pub is None:
                    raise X3DHError("本机身份没有 PQK 私钥，无法完成混合握手")
                if init.pq_ek_pub is None or init.pq_ct is None:
                    raise X3DHError("混合握手缺少封装公钥")
                match = next(
                    (
                        item
                        for item in self.identity.pq_opks
                        if item.pub == init.pq_ek_pub
                    ),
                    None,
                )
                if match is not None:
                    pq_priv_hs = match.priv
                    consumed_pq = init.pq_ek_pub
                    handshake_pq = "pqopk"
                elif init.pq_ek_pub == self.identity.pq_pub:
                    pq_priv_hs = self.identity.pq_priv
                    handshake_pq = "pqk"
                else:
                    raise X3DHError("本地没有对应的一次性 PQ 预密钥")
                sk = responder_hybrid_secret(
                    self.identity.spk.priv,
                    self.identity.ik_dh_priv,
                    init.ik_dh_pub,
                    init.ek_pub,
                    opk_priv,
                    pq_priv_hs,
                    init.pq_ct,
                    init.pq_ek_pub,
                )
            else:
                sk = responder_secret(
                    self.identity.spk.priv,
                    self.identity.ik_dh_priv,
                    init.ik_dh_pub,
                    init.ek_pub,
                    opk_priv,
                )
            state = init_receiver(
                sk,
                self.identity.spk.priv,
                ratchet_msg.header.dh_pub,
                self.username,
                sender,
                remote_pq_pk=init.ik_pq_pub if hybrid else None,
                pq_ct=ratchet_msg.pq_ct if hybrid else None,
                local_pq_priv=self.identity.pq_priv if hybrid else None,
                handshake_pq=handshake_pq,
            )
            new_identity = True
        else:
            state = self.sessions[sender]
            if state.remote_pq_pk is None and ratchet_msg.pq_ct is not None:
                # 旧会话收到带 PQ 的链：补拉对端 PQK 并固定，完成迁移。
                state.remote_pq_pk = await self._upgrade_pq_key(sender)
                if state.remote_pq_pk is None:
                    raise RatchetError("协议错误", "对端没有 PQK，无法迁移该会话")
                self.store.save_session(sender, state)
        plaintext, mk = decrypt(
            state, ratchet_msg, pq_priv=self.identity.pq_priv
        )
        # 解开后的 MK 立即丢掉。跳过缓存里的那一把已在 decrypt 内弹出。
        del mk
        file_meta = None
        try:
            inner = json.loads(plaintext.decode("utf-8"))
            if not isinstance(inner, dict) or inner.get("v") != 1:
                raise ValueError
            text = inner["text"]
            verified_group = inner.get("group")
            verified_kind = inner.get("kind", "chat")
            verified_gstate = inner.get("gstate")
            if verified_kind not in {"chat", "group_meta", "file"}:
                raise ValueError
            if not isinstance(text, str) or verified_group != payload.get("group"):
                raise ValueError
            if verified_kind != (payload.get("kind") or "chat"):
                raise ValueError
            if verified_group:
                if not verified_gstate or not self._check_group_binding(
                    verified_group, verified_gstate, sender
                ):
                    raise ValueError
            elif verified_gstate:
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
            if consumed_pq is not None:
                self.identity.take_pq_opk(consumed_pq)
            self.store.save_identity(self.identity)
        self.store.save_session(sender, state)
        if new_identity and (
            self.identity.needs_refill() or self.identity.needs_pq_refill()
        ):
            created = (
                self.identity.refill_opks() if self.identity.needs_refill() else []
            )
            created_pq = (
                self.identity.refill_pq_opks() if self.identity.needs_pq_refill() else []
            )
            if created or created_pq:
                self.store.save_identity(self.identity)
                try:
                    await self._push_prekeys(created, created_pq)
                except Exception:
                    # 明文已经认证成功且状态已提交；补池失败不能把消息伪装成解密失败。
                    self.last_error = "预密钥补充将在下次登录重试"
        return text, verified_group, verified_kind, file_meta

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

    def _verified_group_state(self, name: str):
        """返回本地已通过端到端验证的最新群状态。"""
        chain = self.group_chain.get(name) or []
        if not chain:
            raise ProtocolError(f"群 {name} 没有已验证的成员状态，先 /group {name} 同步")
        return chain[-1]

    def _check_group_binding(self, group: str, gstate: str, sender: str) -> bool:
        """群消息必须绑定到一条已验签的群状态，且发送者在该状态的成员表里。"""
        chain = self.group_chain.get(group) or []
        for state in chain:
            if state.state_hash().hex() == gstate:
                return sender in state.members
        return False

    def _load_sign_queue(self) -> set[tuple[str, str]]:
        raw = self.store.load_ui_value("group_sign_queue", "[]")
        try:
            data = json.loads(raw)
        except Exception:
            return set()
        found: set[tuple[str, str]] = set()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    found.add((str(item[0]), str(item[1])))
        return found

    def _save_sign_queue(self) -> None:
        self.store.save_ui_value(
            "group_sign_queue",
            json.dumps(sorted(self._sign_queue), ensure_ascii=False),
        )

    def _apply_group_invites(self, msg: dict[str, Any]) -> None:
        self.group_incoming = list(msg.get("incoming") or [])
        self.group_outgoing = list(msg.get("outgoing") or [])
        self.group_requests = list(msg.get("requests") or [])
        self.group_joining = list(msg.get("joining") or [])

    async def _refresh_group_invites_quietly(self) -> None:
        try:
            await self.refresh_group_invites()
        except Exception:
            self.last_error = "群邀请刷新失败"

    async def refresh_group_invites(self) -> None:
        state = await self.request({"type": "group_invite_sync"}, "group_invites")
        self._apply_group_invites(state)
        for item in list(state.get("ready") or []):
            await self._complete_join(str(item.get("group") or ""), str(item.get("username") or ""))

    async def _complete_join(self, group: str, username: str) -> None:
        """对方已经同意后，由当初发出邀请或点了同意的成员补签群状态。"""
        if not group or not username or username == self.username:
            return
        if (group, username) not in self._sign_queue:
            return
        lock = self._group_locks.setdefault(group, asyncio.Lock())
        async with lock:
            if (group, username) not in self._sign_queue:
                return
            if group not in self.group_chain:
                try:
                    await self.sync_group(group)
                except ProtocolError:
                    return
            if group not in self.group_chain:
                return
            if username in set(self.groups.get(group, [])):
                self._sign_queue.discard((group, username))
                self._save_sign_queue()
                return
            try:
                await self.add_group_member(group, username)
            except ProtocolError as exc:
                text = str(exc)
                if "已在" in text:
                    self._sign_queue.discard((group, username))
                    self._save_sign_queue()
                    return
                if "同意" in text or "新增" in text:
                    return
                self.last_error = text
                await self.inbox.put(Incoming("", "", group, "sys", text))
                return
            self._sign_queue.discard((group, username))
            self._save_sign_queue()

    async def create_group(self, name: str, members: list[str]) -> None:
        invites = [member for member in dict.fromkeys(members) if member and member != self.username]
        state = build_genesis_state(
            self.identity.ik_sign_priv, name, self.username, [self.username]
        )
        await self.request(
            {
                "type": "group_create",
                "group": name,
                "invites": invites,
                "state": encode_group_state(state),
            },
            "group_update",
        )
        self.group_chain[name] = [state]
        self.groups[name] = [self.username]
        self.store.save_group_state(state)
        self.store.save_group(name, [self.username])
        self.current_group = name
        self.current_peer = None
        for member in invites:
            self._sign_queue.add((name, member))
        self._save_sign_queue()
        notice = f"你创建了群 {name}"
        if invites:
            notice += f"，已邀请 {'、'.join(invites)}，等待同意"
        self.store.add_history(f"group:{name}", "系统", notice)
        await self.refresh_group_invites()

    async def invite_group_member(self, name: str, member: str) -> None:
        result = await self.request(
            {"type": "group_invite", "group": name, "username": member},
            "group_invites",
        )
        self._apply_group_invites(result)
        self._sign_queue.add((name, member))
        self._save_sign_queue()

    async def respond_group(self, name: str, accept: bool) -> None:
        result = await self.request(
            {"type": "group_respond", "group": name, "accept": bool(accept)},
            "group_invites",
        )
        self._apply_group_invites(result)

    async def request_group(self, name: str) -> None:
        result = await self.request(
            {"type": "group_join_request", "group": name},
            "group_invites",
        )
        self._apply_group_invites(result)

    async def approve_group(self, name: str, member: str, accept: bool) -> None:
        result = await self.request(
            {
                "type": "group_approve",
                "group": name,
                "username": member,
                "accept": bool(accept),
            },
            "group_invites",
        )
        self._apply_group_invites(result)
        if accept:
            self._sign_queue.add((name, member))
            self._save_sign_queue()
            await self._complete_join(name, member)

    async def search_groups(self, query: str) -> dict[str, Any]:
        return await self.request({"type": "group_search", "query": query}, "group_search")

    async def add_group_member(self, name: str, member: str) -> None:
        previous = self._verified_group_state(name)
        state = build_add_state(
            self.identity.ik_sign_priv, previous, member, self.username
        )
        await self.request(
            {
                "type": "group_add",
                "group": name,
                "member": member,
                "state": encode_group_state(state),
            },
            "group_update",
        )
        members = list(state.members)
        chain = self.group_chain.get(name) or []
        chain.append(state)
        self.group_chain[name] = chain
        self.groups[name] = members
        self.store.save_group_state(state)
        self.store.save_group(name, members)
        notice = f"{self.username} 将 {member} 加入 {name}"
        self.store.add_history(f"group:{name}", "系统", notice)
        gstate = state.state_hash().hex()
        for other in members:
            if other == self.username:
                continue
            await self._send_one(
                other, notice, group=name, kind="group_meta", gstate=gstate
            )

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
        "/group add 群名 新成员  /group accept 群名  /file 路径  /history  /help  /quit[/dim]"
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
            ik, *_ = await engine.fetch_user(name)
        groups = fingerprint(ik).split()
        grid = "\n".join("  ".join(groups[i : i + 4]) for i in range(0, 16, 4))
        body = f"{name} 的 IK_sign 指纹\n用线下渠道核对这 16 组。不一致就不要继续聊。\n\n{grid}"
        return CommandResult(overlay=body, notice=f"{name} 指纹已显示")
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
        query = line.split(maxsplit=1)[1]
        found = await engine.search_users(query)
        groups = await engine.search_groups(query)
        rows: list[str] = []
        users = list(found.get("users") or [])
        if users:
            rows.append("用户          关系")
            for item in users:
                rows.append(f"{item['username']:<14}{item.get('relation') or ''}")
        labels = {
            "member": "已加入",
            "invited": "邀请你",
            "requested": "已申请",
            "joining": "正在加入",
            "discover": "可申请",
        }
        found_groups = list(groups.get("groups") or [])
        if found_groups:
            rows.append("群聊          关系")
            for item in found_groups:
                rows.append(f"{item.get('name') or '':<14}{labels.get(item.get('relation'), '')}")
        return CommandResult(overlay="\n".join(rows) if rows else "没有匹配的用户或群")
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
    if cmd == "/pq" and len(parts) == 3 and parts[1] == "status":
        name = parts[2]
        if name == engine.username:
            if engine.identity.pq_pub:
                row = (
                    "本机 PQK：已生成 (ML-KEM-768)，长期封装公钥\n"
                    f"一次性 PQ 预密钥剩余 {len(engine.identity.pq_opks)} 把"
                )
            else:
                row = "本机 PQK：无"
            return CommandResult(overlay=row)
        if name not in engine.sessions:
            raise ProtocolError(f"还没有与 {name} 的会话")
        state = engine.sessions[name]
        if state.remote_pq_pk is None:
            upgraded = await engine._upgrade_pq_key(name)
            if upgraded is None:
                return CommandResult(
                    overlay=f"{name}：经典 X3DH，对端没有 PQK，无法迁移"
                )
            state.remote_pq_pk = upgraded
            engine.store.save_session(name, state)
        if state.handshake_pq == "pqopk":
            handshake = "一次性 PQ 预密钥（首条认证成功后私钥已删除）"
        elif state.handshake_pq == "pqk":
            handshake = "签过名的长期 PQK（服务器未提供一次性钥）"
        else:
            handshake = "经典 X3DH，棘轮侧已补上长期 PQK"
        return CommandResult(
            overlay=(
                f"{name}：混合 PQXDH\n"
                f"握手封装：{handshake}\n"
                f"棘轮已混入 PQ：{'是' if state.dhs_pq_ct else '否（下一次换链起生效）'}\n"
                f"棘轮代数 {state.dh_ratchet_count}"
            )
        )
    if cmd == "/history":
        return CommandResult(overlay=_history_text(engine))
    if cmd == "/group" and len(parts) >= 2:
        if parts[1] == "create" and len(parts) >= 4:
            await engine.create_group(parts[2], parts[3:])
            return CommandResult(notice=f"已创建群 {parts[2]}，等待对方同意")
        if parts[1] == "add" and len(parts) == 4:
            await engine.invite_group_member(parts[2], parts[3])
            return CommandResult(notice=f"已邀请 {parts[3]}，等待对方同意")
        if parts[1] == "accept" and len(parts) == 3:
            await engine.respond_group(parts[2], True)
            return CommandResult(notice=f"已同意加入 {parts[2]}")
        if parts[1] == "reject" and len(parts) == 3:
            await engine.respond_group(parts[2], False)
            return CommandResult(notice=f"已拒绝加入 {parts[2]}")
        if parts[1] == "approve" and len(parts) == 4:
            await engine.approve_group(parts[2], parts[3], True)
            return CommandResult(notice=f"已同意 {parts[3]} 加入 {parts[2]}")
        if parts[1] == "deny" and len(parts) == 4:
            await engine.approve_group(parts[2], parts[3], False)
            return CommandResult(notice=f"已拒绝 {parts[3]} 加入 {parts[2]}")
        if parts[1] not in engine.groups:
            raise ProtocolError(f"群 {parts[1]} 不存在")
        if parts[1] not in engine.group_chain:
            await engine.sync_group(parts[1])
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
