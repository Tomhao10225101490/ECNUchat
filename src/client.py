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
import shutil
import time
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
    clean_name,
    decrypt_chunk,
    display_text,
    guess_mime,
    hash_file,
    history_body,
    media_kind,
    meta_from_dict,
    meta_to_dict,
    open_bytes,
    parse_history_body,
    place_local_copy,
    plaintext_len,
    resolve_rel,
    seal_bytes,
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
CHUNK_WINDOW = 6
BLOB_TIMEOUT = 120.0


def split_dm_conv(conv: str) -> tuple[str, str | None]:
    """拆分 `dm:名字#线程`；旧格式 `dm:名字` 的线程为 None。"""
    body = conv[3:] if conv.startswith("dm:") else conv
    if "#" in body:
        peer, tid = body.split("#", 1)
        return peer, tid or None
    return body, None


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
    threads: dict[str, dict[str, Any]] = field(default_factory=dict)
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
        engine.threads = store.load_threads()
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
        self.ws = await websockets.connect(uri, max_size=MAX_BLOB_FRAME)
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
        chain.append(state)
        self.group_chain[name] = chain
        self.groups[name] = list(state.members)
        self.store.save_group_state(state)
        self.store.save_group(name, list(state.members))

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

    async def send_text(
        self,
        text: str,
        *,
        peer: str | None = None,
        group: str | None = None,
        conv: str | None = None,
    ) -> None:
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
        thread: str | None = None
        thread_title: str | None = None
        if conv and conv.startswith("dm:"):
            dest, thread = split_dm_conv(conv)
            thread_title = (self.threads.get(conv) or {}).get("title")
        if not dest:
            raise ProtocolError("先用 /chat 名字 选择对端")
        conv_key = conv or f"dm:{dest}"
        await self._send_one(
            dest,
            text,
            group=None,
            kind="chat",
            gstate=None,
            thread=thread,
            thread_title=thread_title,
        )
        self.store.add_history(conv_key, self.username, text)

    async def send_file(
        self,
        path: str | None = None,
        *,
        peer: str | None = None,
        group: str | None = None,
        conv: str | None = None,
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
        thread: str | None = None
        thread_title: str | None = None
        if group:
            state = self._verified_group_state(group)
            members = list(state.members)
            recipients = sorted(member for member in members if member != self.username)
            if not recipients:
                raise ProtocolError("群里没有其他成员")
            conv_key = f"group:{group}"
            target_group: str | None = group
            gstate = state.state_hash().hex()
        else:
            dest = peer or self.current_peer
            if conv and conv.startswith("dm:"):
                dest, thread = split_dm_conv(conv)
                thread_title = (self.threads.get(conv) or {}).get("title")
            if not dest:
                raise ProtocolError("先用 /chat 名字 选择对端")
            if dest == self.username:
                raise ProtocolError("不能给自己发文件")
            recipients = [dest]
            conv_key = conv or f"dm:{dest}"
            target_group = None
        probe_name = filename or (Path(path).name if path else None)
        probe_mime = mime or (guess_mime(probe_name) if probe_name else "")
        save_allowed = self._media_save_allowed(conv_key, probe_mime)
        record = self.store.load_file_job(local_id)
        if record is None:
            record = await asyncio.to_thread(
                self._new_file_job,
                local_id=local_id,
                conv=conv_key,
                group=target_group,
                recipients=recipients,
                caption=caption,
                path=path,
                data=data,
                filename=filename,
                mime=mime,
                save_allowed=save_allowed,
            )
            record["gstate"] = gstate
            record["thread"] = thread
            record["thread_title"] = thread_title
            record["privacy"] = self._privacy_level(conv_key)
        else:
            recipients = list(record["recipients"])
            conv_key = str(record["conv"])
            target_group = record.get("group")
        # SQLite 连接属于引擎线程：媒体元数据必须在 to_thread 之外落库。
        if record.get("media"):
            self.store.save_media_meta(str(record["meta"]["id"]), record["meta"])
        if not record.get("history"):
            record["history"] = self._file_history_body(record)
        self.store.save_file_job(local_id, record)
        self.store.save_message_status(local_id, conv_key, str(record["history"]), "sending")
        if not record.get("uploaded"):
            await self._upload_file(record)
            record["uploaded"] = True
            self.store.save_file_job(local_id, record)
            if not record.get("media"):
                cipher = attachment_root(self.store.path) / "cipher" / str(record["meta"]["id"])
                await asyncio.to_thread(shutil.rmtree, cipher, True)
        if not record.get("logged"):
            self.store.add_history(conv_key, self.username, str(record["history"]))
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
                    conv_key,
                    "系统",
                    f"文件仅送达 {delivered}/{len(recipients)} 人，可稍后重试",
                )
            raise
        size = int(record["meta"]["size"])
        span = max(size, 1) * 2
        self._progress(local_id, span, span)
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
        save_allowed: bool = True,
    ) -> dict[str, Any]:
        root = attachment_root(self.store.path)
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
            span = max(size, 1) * 2

            def on_plain(done: int) -> None:
                self._progress(local_id, done, span)

            try:
                meta = seal_path(file_path, root / "cipher", filename, mime, on_plain=on_plain)
            except AttachmentError as exc:
                raise ProtocolError(exc.message) from exc
            blob_id = meta.file_id.hex()
            media = media_kind(meta.mime) in {"image", "video"}
            if media:
                rel = ""
            else:
                rel = f"files/{blob_id}/{meta.name}"
                place_local_copy(file_path, root / rel)
        else:
            if len(data) > MAX_FILE_BYTES:
                raise ProtocolError("文件超过 8GiB")
            payload = bytes(data)
            filename = filename or "file"
            sealed = seal_bytes(payload, filename, mime)
            meta = sealed.meta
            blob_hex = meta.file_id.hex()
            cipher = root / "cipher" / blob_hex
            cipher.mkdir(parents=True, exist_ok=True)
            for index, chunk in enumerate(sealed.chunks):
                (cipher / str(index)).write_bytes(chunk)
            blob_id = meta.file_id.hex()
            media = media_kind(meta.mime) in {"image", "video"}
            if media:
                rel = ""
            else:
                rel = f"files/{blob_id}/{meta.name}"
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
            "media": media,
            "enveloped": [],
            "uploaded": False,
            "logged": False,
            "history": "",
        }

    def _file_history_body(self, record: dict[str, Any]) -> str:
        meta = meta_from_dict(record["meta"])
        if record.get("media"):
            return history_body(
                name=meta.name,
                mime=meta.mime,
                size=meta.size,
                sha256=meta.sha256,
                rel_path="",
                caption=str(record.get("caption") or ""),
                blob_id=meta.file_id.hex(),
                saved=False,
            )
        return history_body(
            name=meta.name,
            mime=meta.mime,
            size=meta.size,
            sha256=meta.sha256,
            rel_path=str(record["rel"]),
            caption=str(record.get("caption") or ""),
            saved=True,
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
        span = max(meta.size, 1) * 2
        sent = 0
        lock = asyncio.Lock()
        self._progress(str(record["local_id"]), meta.size, span)

        async def one(index: int) -> None:
            nonlocal sent
            chunk_path = cipher / str(index)
            if not chunk_path.is_file():
                raise ProtocolError("本地密文丢失")
            ciphertext = await asyncio.to_thread(chunk_path.read_bytes)
            await self.request(
                {
                    "type": "blob_chunk",
                    "id": blob_id,
                    "idx": index,
                    "data": b64e(ciphertext),
                },
                "blob_chunk_ok",
            )
            async with lock:
                sent += plaintext_len(meta.size, meta.chunks, index)
                done = meta.size + sent
            self._progress(str(record["local_id"]), done, span)

        await self._run_indexed(meta.chunks, one)
        await self.request(
            {"type": "blob_finish", "id": blob_id},
            "blob_finish_ok",
        )

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
                    "thread": record.get("thread"),
                    "thread_title": record.get("thread_title"),
                    "privacy": record.get("privacy") or "low",
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
        thread: str | None = None,
        thread_title: str | None = None,
    ) -> dict[str, Any]:
        lock = self._peer_locks.setdefault(peer, asyncio.Lock())
        async with lock:
            await self._flush_outbox(peer)
            state = await self._ensure_session_for_send(peer)
            x3dh = self.pending_x3dh.get(peer)
            conv = (
                f"group:{group}"
                if group
                else (f"dm:{peer}#{thread}" if thread else f"dm:{peer}")
            )
            inner = json.dumps(
                {
                    "v": 1,
                    "text": text,
                    "group": group,
                    "kind": kind,
                    "gstate": gstate,
                    "thread": thread,
                    "thread_title": thread_title,
                    "privacy": self._privacy_level(conv),
                },
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
            text, verified_group, verified_kind, file_meta, inner = await self._decrypt_envelope(
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
        thread = inner.get("thread") if not verified_group else None
        privacy = inner.get("privacy")
        new_thread = False
        if not verified_group and isinstance(thread, str) and thread:
            conv = f"dm:{sender}#{thread}"
            if conv not in self.threads:
                new_thread = True
                title = str(inner.get("thread_title") or sender)
                self.threads[conv] = {
                    "peer": sender,
                    "tid": thread,
                    "title": title,
                    "created": time.time(),
                }
                self.store.save_thread(conv, sender, thread, title)
        else:
            conv = f"group:{verified_group}" if verified_group else f"dm:{sender}"
        if privacy in {"low", "high"}:
            self.store.set_conversation_privacy(conv, privacy)
        if verified_kind == "thread_init":
            if new_thread:
                self.store.add_history(conv, "系统", "对方创建了这个聊天")
            await self.inbox.put(Incoming(sender, "", None, "presence"))
            return
        if verified_kind == "file" and file_meta is not None:
            record = {
                "meta": meta_to_dict(file_meta),
                "sender": sender,
                "group": verified_group,
                "conv": conv,
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
        caption = str(record.get("caption") or "")
        conv = str(record.get("conv") or (
            f"group:{record['group']}"
            if record.get("group")
            else f"dm:{record['sender']}"
        ))
        media = media_kind(meta.mime) in {"image", "video"}
        root = attachment_root(self.store.path)
        dest = root / "files" / blob_id / meta.name
        partial = dest.with_name(dest.name + ".part")
        await self.inbox.put(
            Incoming(
                str(record["sender"]),
                caption,
                record.get("group"),
                "file_progress",
                local_id=local_id,
                attachment={
                    "name": meta.name,
                    "mime": meta.mime,
                    "size": meta.size,
                    "sha256": meta.sha256.hex(),
                    "id": blob_id if media else None,
                    "media": media_kind(meta.mime),
                    "caption": caption,
                    "saved": not media,
                },
            )
        )
        try:
            if media:
                await self._download_to_cache(meta, local_id)
            else:
                await self._download_file(meta, partial, local_id)
                partial.replace(dest)
        except AttachmentError:
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
        if media:
            self.store.save_media_meta(blob_id, meta_to_dict(meta))
            body = history_body(
                name=meta.name,
                mime=meta.mime,
                size=meta.size,
                sha256=meta.sha256,
                rel_path="",
                caption=caption,
                blob_id=blob_id,
                saved=False,
            )
        else:
            body = history_body(
                name=meta.name,
                mime=meta.mime,
                size=meta.size,
                sha256=meta.sha256,
                rel_path=f"files/{blob_id}/{meta.name}",
                caption=caption,
                saved=True,
            )
        fresh = not record.get("logged")
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

    async def _download_to_cache(self, meta: Any, local_id: str) -> None:
        """把密文分片原样存进加密缓存，同时在内存里解密校验摘要。

        磁盘上只保留发送方的密文，不写任何明文。预览/保存时再按需解密。
        """
        blob_id = meta.file_id.hex()
        folder = attachment_root(self.store.path) / "cipher" / blob_id
        folder.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        got = 0
        lock = asyncio.Lock()

        def keep_piece(index: int, ciphertext: bytes) -> int:
            plain = decrypt_chunk(meta, index, ciphertext)
            nonlocal digest
            digest.update(plain)
            (folder / str(index)).write_bytes(ciphertext)
            return len(plain)

        async def one(index: int) -> None:
            nonlocal got
            resp = await self.request(
                {"type": "blob_fetch", "id": blob_id, "idx": index},
                "blob_fetch_ok",
            )
            if resp.get("id") != blob_id or resp.get("idx") != index:
                raise ProtocolError("分片编号对不上")
            data = b64d(resp.get("data"))
            if data is None:
                raise ProtocolError("分片缺失")
            written = await asyncio.to_thread(keep_piece, index, data)
            async with lock:
                got += written
                done = got
            self._progress(local_id, done, max(meta.size, 1))

        await self._run_indexed(meta.chunks, one)
        if digest.digest() != meta.sha256 or got != meta.size:
            raise AttachmentError("摘要不一致")

    async def _download_file(self, meta: Any, dest: Path, local_id: str) -> None:
        blob_id = meta.file_id.hex()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as handle:
            handle.truncate(meta.size)
        got = 0
        lock = asyncio.Lock()

        def write_piece(index: int, ciphertext: bytes) -> int:
            piece = decrypt_chunk(meta, index, ciphertext)
            with dest.open("r+b") as handle:
                handle.seek(index * FILE_PLAIN_CHUNK)
                handle.write(piece)
            return len(piece)

        async def one(index: int) -> None:
            nonlocal got
            resp = await self.request(
                {"type": "blob_fetch", "id": blob_id, "idx": index},
                "blob_fetch_ok",
            )
            if resp.get("id") != blob_id or resp.get("idx") != index:
                raise ProtocolError("分片编号对不上")
            data = b64d(resp.get("data"))
            if data is None:
                raise ProtocolError("分片缺失")
            written = await asyncio.to_thread(write_piece, index, data)
            async with lock:
                got += written
                done = got
            self._progress(local_id, done, max(meta.size, 1))

        try:
            await self._run_indexed(meta.chunks, one)
            digest = await asyncio.to_thread(hash_file, dest)
        except AttachmentError:
            raise
        except ProtocolError:
            raise
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
    ) -> tuple[str, str | None, str, Any, dict[str, Any]]:
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
            if verified_kind not in {"chat", "group_meta", "file", "thread_init"}:
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
        return text, verified_group, verified_kind, file_meta, inner

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
        show_online: bool,
        searchable: bool,
        moments_visibility: str = "friends",
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

    def _privacy_level(self, conv: str) -> str:
        """会话私密等级：low 为普通（默认），high 为私密。"""
        return self.store.get_conversation_privacy(conv) or "low"

    def create_thread(self, peer: str, level: str = "low", title: str = "") -> str:
        """同一好友可以开多个聊天线程；每个线程有自己的私密等级。"""
        count = sum(1 for item in self.threads.values() if item.get("peer") == peer)
        tid = uuid.uuid4().hex[:8]
        conv = f"dm:{peer}#{tid}"
        name = (title or "").strip() or (
            peer if count == 0 else f"{peer} · {count + 1}"
        )
        self.threads[conv] = {
            "peer": peer,
            "tid": tid,
            "title": name,
            "created": time.time(),
        }
        self.store.save_thread(conv, peer, tid, name)
        self.store.set_conversation_privacy(
            conv, level if level in {"low", "high"} else "low"
        )
        self.store.add_history(conv, "系统", "聊天已创建")
        return conv

    async def announce_thread(self, conv: str) -> None:
        """把新聊天通过加密棘轮通知对方，对方不发言也能看到会话。"""
        peer, tid = split_dm_conv(conv)
        info = self.threads.get(conv) or {}
        if not peer or not tid or not info:
            raise ProtocolError("聊天线程无效")
        await self._send_one(
            peer,
            "",
            group=None,
            kind="thread_init",
            gstate=None,
            thread=tid,
            thread_title=str(info.get("title") or peer),
        )

    def _media_save_allowed(self, conv: str, mime: str) -> bool:
        """私密等级的会话不把图片/视频落盘；其它文件不受影响。"""
        if self._privacy_level(conv) == "high" and media_kind(mime or "") in {"image", "video"}:
            return False
        return True

    def _media_meta(self, blob_id: str):
        raw = self.store.load_media_meta(blob_id)
        if raw is None:
            raise ProtocolError("媒体元数据缺失")
        return meta_from_dict(raw)

    def media_plaintext(self, blob_id: str) -> bytes:
        """从加密缓存里按需解出明文（只进内存，不写盘）。"""
        meta = self._media_meta(blob_id)
        folder = attachment_root(self.store.path) / "cipher" / blob_id
        chunks: list[bytes] = []
        for index in range(meta.chunks):
            path = folder / str(index)
            if not path.is_file():
                raise ProtocolError("媒体密文缺失")
            chunks.append(path.read_bytes())
        return open_bytes(meta, chunks)

    def media_temp_path(self, blob_id: str) -> Path:
        """视频播放用：解出明文到临时文件，播放器关闭后由调用方删除。"""
        meta = self._media_meta(blob_id)
        plain = self.media_plaintext(blob_id)
        tmp = attachment_root(self.store.path) / "tmp" / f"{blob_id}-{clean_name(meta.name)}"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(plain)
        return tmp

    def save_attachment(self, conv: str, body: str, dest_path: str) -> str:
        """把媒体另存到用户选择的路径；不修改历史，可重复保存。"""
        record = parse_history_body(body)
        if record is None:
            raise ProtocolError("这条消息没有可保存的媒体")
        if not self._media_save_allowed(conv, record["mime"]):
            raise ProtocolError("私密会话不允许保存媒体")
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if record.get("id"):
            dest.write_bytes(self.media_plaintext(record["id"]))
        else:
            src = resolve_rel(self.store.path, record["path"])
            if not src.is_file():
                raise ProtocolError("文件不在本机")
            if src.resolve() != dest.resolve():
                shutil.copyfile(src, dest)
        return str(dest)

    async def create_group(self, name: str, members: list[str]) -> None:
        all_members = list(dict.fromkeys([self.username, *members]))
        state = build_genesis_state(
            self.identity.ik_sign_priv, name, self.username, all_members
        )
        await self.request(
            {
                "type": "group_create",
                "group": name,
                "members": all_members,
                "state": encode_group_state(state),
            },
            "group_update",
        )
        self.group_chain[name] = [state]
        self.groups[name] = all_members
        self.store.save_group_state(state)
        self.store.save_group(name, all_members)
        self.current_group = name
        self.current_peer = None
        notice = f"{self.username} 创建了群，成员 {', '.join(all_members)}"
        self.store.add_history(f"group:{name}", "系统", notice)
        gstate = state.state_hash().hex()
        for other in all_members:
            if other == self.username:
                continue
            await self._send_one(
                other, notice, group=name, kind="group_meta", gstate=gstate
            )

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
        "/group add 群名 新成员  /file 路径  /pq status 名字  /history  /users  /help  /quit[/dim]"
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
    if cmd == "/chat" and len(parts) in (2, 3):
        validate_username(parts[1])
        if parts[1] == engine.username:
            raise ProtocolError("不能和自己建立会话")
        level = "low"
        if len(parts) == 3:
            if parts[2] not in {"low", "high"}:
                raise ProtocolError("私密等级只能是 low（普通）或 high（私密）")
            level = parts[2]
        await engine.fetch_user(parts[1])
        engine.store.set_conversation_privacy(f"dm:{parts[1]}", level)
        engine.current_peer = parts[1]
        engine.current_group = None
        label = "私密（不保存媒体）" if level == "high" else "普通（可保存媒体）"
        return CommandResult(notice=f"已打开与 {parts[1]} 的会话（{label}）")
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
            return CommandResult(notice=f"已创建群 {parts[2]}")
        if parts[1] == "add" and len(parts) == 4:
            await engine.add_group_member(parts[2], parts[3])
            return CommandResult(notice=f"已将 {parts[3]} 加入 {parts[2]}")
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
