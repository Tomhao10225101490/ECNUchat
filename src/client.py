"""Rich 终端客户端：注册/登录、单聊、最多 8 人的逐人棘轮群聊。

群正文不是 Sender Keys。`ChatEngine.send_text` 对每个其他成员各发一封
独立双棘轮信封。这是对 Rösler、Mainka、Schwenk，EuroS&P 2018
（*More is Less*，ePrint 2017/713）的回应：他们指出 Signal / WhatsApp
的群对称链继承不到两人双棘轮的 future secrecy。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
import sys
from dataclasses import dataclass, field
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
from src.groups import (
    GroupStateError,
    build_add_state,
    build_genesis_state,
    verify_group_state_sig,
    verify_state_transition,
)
from src.prekeys import (
    generate_identity,
    generate_x25519,
    sign_bytes,
    verify_pq,
    verify_spk,
)
from src.protocol import (
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
                "__registered__",
                self.identity.ik_sign_pub,
                self.identity.ik_dh_pub,
                self.identity.pq_pub,
            )
        await self._retry_outboxes()
        try:
            await self._retry_pending_prekeys()
        except Exception:
            self.last_error = "预密钥补充将在下次登录重试"

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
                "pq_pub": b64e(self.identity.pq_pub),
                "pq_sig": b64e(self.identity.pq_sig),
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
            name = msg.get("group", "")
            if msg.get("state"):
                await self._on_group_update(name, msg["state"])
            else:
                self._fail("", name, "群状态缺少签名，已拒绝未受保护的成员表")
            await self.inbox.put(Incoming("系统", "", name, "presence"))
        elif typ == "presence":
            self.online_users = set(msg.get("online") or [])
            await self.inbox.put(Incoming("", "", None, "presence"))
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
        bundle = await self.request({"type": "fetch_bundle", "username": peer}, "bundle")
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
        if pq_pub is not None and self.identity.pq_pub is not None:
            sk, pq_ct = initiator_hybrid_secret(
                self.identity.ik_dh_priv,
                ek_priv,
                spk_pub,
                ik_dh,
                opk,
                pq_pub,
            )
            state = init_sender(
                sk, spk_pub, self.username, peer, remote_pq_pk=pq_pub
            )
            self.pending_x3dh[peer] = build_initial_message(
                self.identity.ik_sign_priv,
                self.identity.ik_dh_pub,
                ek_pub,
                opk,
                ik_pq_pub_a=self.identity.pq_pub,
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

        成员名单仍是服务器记录（`group_create` / `group_add`）。论文里的
        群完整性与「谁有权管理群」没有被这个扇出补上。`group_meta` 只是
        把通知正文放进同一套逐人信封。
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
            text, verified_group, verified_kind = await self._decrypt_envelope(
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
        self.store.add_history(conv, who, text)
        await self.inbox.put(Incoming(who, text, group, verified_kind))

    def _fail(self, sender: str, group: str | None, phrase: str) -> None:
        self.last_error = phrase
        conv = f"group:{group}" if group else (f"dm:{sender}" if sender else None)
        if conv:
            self.store.add_history(conv, "系统", phrase)
        self.inbox.put_nowait(Incoming(sender, "", group, "error", phrase))

    async def _decrypt_envelope(
        self, sender: str, payload: dict[str, Any]
    ) -> tuple[str, str | None, str]:
        ratchet_msg, init = decode_ratchet_payload(payload)
        new_identity = False
        consumed_opk: bytes | None = None
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
                    init.pq_ct,
                )
            except X3DHError:
                self.last_error = "验签失败"
                raise
            if init.ik_dh_pub != ik_dh:
                raise X3DHError("验签失败：身份协商公钥与服务器登记不一致")
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
            hybrid = init.pq_ct is not None and init.ik_pq_pub is not None
            if self.identity.pq_priv is not None and not hybrid:
                # 本机支持 PQ 却收到经典初始消息：拒绝静默降级。
                raise X3DHError("缺少 PQ 握手，已拒绝降级")
            if hybrid:
                if self.identity.pq_priv is None:
                    raise X3DHError("本机身份没有 PQK 私钥，无法完成混合握手")
                sk = responder_hybrid_secret(
                    self.identity.spk.priv,
                    self.identity.ik_dh_priv,
                    init.ik_dh_pub,
                    init.ek_pub,
                    opk_priv,
                    self.identity.pq_priv,
                    init.pq_ct,
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
        try:
            inner = json.loads(plaintext.decode("utf-8"))
            if not isinstance(inner, dict) or inner.get("v") != 1:
                raise ValueError
            text = inner["text"]
            verified_group = inner.get("group")
            verified_kind = inner.get("kind", "chat")
            verified_gstate = inner.get("gstate")
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
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as exc:
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
        return text, verified_group, verified_kind

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
            ik, *_ = await engine.fetch_user(name)
        groups = fingerprint(ik).split()
        grid = "\n".join("  ".join(groups[i : i + 4]) for i in range(0, 16, 4))
        body = f"{name} 的 IK_sign 指纹\n用线下渠道核对这 16 组。不一致就不要继续聊。\n\n{grid}"
        return CommandResult(overlay=body, notice=f"{name} 指纹已显示")
    if cmd == "/pq" and len(parts) == 3 and parts[1] == "status":
        name = parts[2]
        if name == engine.username:
            row = (
                f"本机 PQK：{'已生成 (ML-KEM-768)' if engine.identity.pq_pub else '无'}"
            )
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
        return CommandResult(
            overlay=(
                f"{name}：混合 PQXDH\n"
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
