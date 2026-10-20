"""转发服务器：只保存公钥、预密钥和离线信封，不接触口令、私钥、明文、消息密钥。"""

from __future__ import annotations

import argparse
import asyncio
import contextvars
import logging
import os
import re
import sys
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed

from src.attachments import AttachmentError, cipher_len, expected_chunks
from src.groups import (
    verify_group_state_sig,
    verify_state_transition,
)
from src.prekeys import MLKEM768_PUB_LEN, verify_pq, verify_pq_opk, verify_spk
from src.protocol import (
    MAX_GROUP_MEMBERS,
    PROJECT_NAME,
    ProtocolError,
    b64d,
    b64e,
    check_size,
    decode_group_state,
    dumps,
    encode_group_state,
    error_msg,
    loads,
    validate_group_name,
    validate_username,
)
from src.store import ServerStore

# 一次性 KEM 公钥 1184 字节。16 把加签名仍低于单帧 64KB。
MAX_PQ_OPK_UPLOAD = 16


def _decode_pq_opks(
    raw: Any, ik_sign_pub: bytes, username: str
) -> tuple[list[tuple[bytes, bytes]] | None, str | None]:
    """解析并验签一次性 PQ 预密钥。失败时返回错误文案，不入库。"""
    if raw is None:
        return [], None
    if not isinstance(raw, list):
        return None, "一次性 PQ 预密钥格式无效"
    if len(raw) > MAX_PQ_OPK_UPLOAD:
        return None, "一次性 PQ 预密钥一次最多 16 把"
    items: list[tuple[bytes, bytes]] = []
    for item in raw:
        if not isinstance(item, dict):
            return None, "一次性 PQ 预密钥格式无效"
        pub = b64d(item.get("pub"))
        sig = b64d(item.get("sig"))
        if (
            pub is None
            or len(pub) != MLKEM768_PUB_LEN
            or sig is None
            or len(sig) != 64
        ):
            return None, "一次性 PQ 预密钥长度无效"
        try:
            verify_pq_opk(ik_sign_pub, pub, username, sig)
        except Exception:
            return None, "一次性 PQ 预密钥签名无效，拒绝入库"
        items.append((pub, sig))
    return items, None


# 日志里禁止明文、私钥、SK、RK、CK、MK。聊天内容只允许 base64。
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("e2ee-server")

UNSOLICITED_TYPES = {"envelope", "presence"}


class RequestSocket:
    """给响应透明附加 request_id，同时保持推送消息不带关联 ID。"""

    def __init__(self, raw: Any) -> None:
        self.raw = raw
        self._request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            f"request_id_{id(self)}", default=None
        )

    async def send(self, raw: str | bytes) -> None:
        request_id = self._request_id.get()
        if request_id and isinstance(raw, str):
            try:
                message = loads(raw)
            except Exception:
                message = None
            if (
                isinstance(message, dict)
                and message.get("type") not in UNSOLICITED_TYPES
                and "request_id" not in message
            ):
                message["request_id"] = request_id
                raw = dumps(message)
        await self.raw.send(raw)

    def begin_request(self, request_id: str | None) -> contextvars.Token:
        return self._request_id.set(request_id)

    def end_request(self, token: contextvars.Token) -> None:
        self._request_id.reset(token)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw, name)


class ChatServer:
    def __init__(self, store: ServerStore) -> None:
        self.store = store
        self.online: dict[str, Any] = {}
        self.pending_challenge: dict[int, tuple[str, bytes]] = {}

    async def handler(self, ws: Any) -> None:
        socket = RequestSocket(ws)
        username: str | None = None
        try:
            async for raw in ws:
                if isinstance(raw, bytes):
                    if len(raw) > 64 * 1024:
                        await ws.send(dumps(error_msg("单条 WebSocket 消息超过 64KB")))
                        continue
                else:
                    try:
                        check_size(raw)
                    except Exception as exc:
                        await ws.send(dumps(error_msg(str(exc))))
                        continue
                try:
                    msg = loads(raw)
                except Exception as exc:
                    await ws.send(dumps(error_msg(str(exc))))
                    continue
                try:
                    token = socket.begin_request(msg.get("request_id"))
                    username = await self.dispatch(socket, username, msg)
                except Exception as exc:
                    log.info("error type=%s detail=%s", msg.get("type"), type(exc).__name__)
                    await socket.send(dumps(error_msg(str(exc))))
                finally:
                    socket.end_request(token)
        except ConnectionClosed:
            pass
        finally:
            if username and self.online.get(username) is socket:
                del self.online[username]
                log.info("offline user=%s", username)
                await self._broadcast_presence()

    async def dispatch(self, ws: Any, username: str | None, msg: dict[str, Any]) -> str | None:
        typ = msg.get("type")
        if typ == "register":
            return await self.on_register(ws, msg)
        if typ == "login":
            return await self.on_login(ws, username, msg)
        if username is None:
            await ws.send(dumps(error_msg("请先注册或登录")))
            return None
        if typ == "upload_prekeys":
            await self.on_upload_prekeys(ws, username, msg)
        elif typ == "fetch_bundle":
            await self.on_fetch_bundle(ws, msg)
        elif typ == "fetch_user":
            await self.on_fetch_user(ws, msg)
        elif typ == "envelope":
            await self.on_envelope(ws, username, msg)
        elif typ == "list_users":
            await self.on_list_users(ws)
        elif typ == "group_create":
            await self.on_group_create(ws, username, msg)
        elif typ == "group_add":
            await self.on_group_add(ws, username, msg)
        elif typ == "group_info":
            await self.on_group_info(ws, msg)
        elif typ == "group_sync":
            await self.on_group_sync(ws, msg)
        elif typ == "blob_begin":
            await self.on_blob_begin(ws, username, msg)
        elif typ == "blob_chunk":
            await self.on_blob_chunk(ws, username, msg)
        elif typ == "blob_finish":
            await self.on_blob_finish(ws, username, msg)
        elif typ == "blob_fetch":
            await self.on_blob_fetch(ws, username, msg)
        elif typ == "blob_done":
            await self.on_blob_done(ws, username, msg)
        else:
            await ws.send(dumps(error_msg(f"未知类型 {typ}")))
        return username

    async def on_register(self, ws: Any, msg: dict[str, Any]) -> str | None:
        username = msg.get("username", "")
        validate_username(username)
        if self.store.user_exists(username):
            await ws.send(dumps(error_msg("用户名已存在")))
            return None
        ik_sign_pub = b64d(msg["ik_sign_pub"])
        ik_dh_pub = b64d(msg["ik_dh_pub"])
        spk_pub = b64d(msg["spk_pub"])
        spk_sig = b64d(msg["spk_sig"])
        pq_pub = b64d(msg.get("pq_pub"))
        pq_sig = b64d(msg.get("pq_sig"))
        if (
            ik_sign_pub is None
            or len(ik_sign_pub) != 32
            or ik_dh_pub is None
            or len(ik_dh_pub) != 32
            or spk_pub is None
            or len(spk_pub) != 32
            or spk_sig is None
            or len(spk_sig) != 64
        ):
            await ws.send(dumps(error_msg("注册公钥不完整")))
            return None
        try:
            verify_spk(ik_sign_pub, spk_pub, username, spk_sig)
        except Exception:
            await ws.send(dumps(error_msg("SPK 签名无效，拒绝入库")))
            return None
        if (pq_pub is None) != (pq_sig is None):
            await ws.send(dumps(error_msg("PQK 公钥与签名必须同时提供")))
            return None
        if pq_pub is not None:
            if len(pq_pub) != MLKEM768_PUB_LEN or pq_sig is None or len(pq_sig) != 64:
                await ws.send(dumps(error_msg("PQK 公钥或签名长度无效")))
                return None
            try:
                verify_pq(ik_sign_pub, pq_pub, username, pq_sig)
            except Exception:
                await ws.send(dumps(error_msg("PQK 签名无效，拒绝入库")))
                return None
        opks = [b64d(x) for x in msg.get("opks") or []]
        opk_bytes = [x for x in opks if x]
        if len(opk_bytes) > 100 or any(len(item) != 32 for item in opk_bytes):
            await ws.send(dumps(error_msg("OPK 必须是最多 100 把 32 字节公钥")))
            return None
        pq_opks, pq_err = _decode_pq_opks(msg.get("pq_opks"), ik_sign_pub, username)
        if pq_err or pq_opks is None:
            await ws.send(dumps(error_msg(pq_err or "一次性 PQ 预密钥无效")))
            return None
        self.store.create_user(
            username,
            ik_sign_pub,
            ik_dh_pub,
            spk_pub,
            spk_sig,
            float(msg.get("spk_created") or 0),
            pq_pub,
            pq_sig,
            opk_bytes,
            pq_opks,
        )
        await self._bind(ws, username)
        await ws.send(dumps({"type": "register_ok", "username": username}))
        log.info(
            "register user=%s opk_count=%s pq_opk_count=%s",
            username,
            len(opk_bytes),
            len(pq_opks),
        )
        return username

    async def on_login(self, ws: Any, username: str | None, msg: dict[str, Any]) -> str | None:
        name = msg.get("username", "")
        validate_username(name)
        user = self.store.get_user(name)
        if not user:
            await ws.send(dumps(error_msg("用户不存在")))
            return username
        sig = msg.get("signature")
        if not sig:
            challenge = os.urandom(32)
            self.pending_challenge[id(ws)] = (name, challenge)
            await ws.send(
                dumps({"type": "login_challenge", "challenge": b64e(challenge)})
            )
            log.info("login_challenge user=%s", name)
            return username
        pending = self.pending_challenge.pop(id(ws), None)
        if not pending or pending[0] != name:
            await ws.send(dumps(error_msg("没有对应的登录挑战")))
            return username
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            signature = b64d(sig)
            if signature is None or len(signature) != 64:
                raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(user[0]).verify(
                signature, pending[1]
            )
        except (InvalidSignature, ProtocolError):
            await ws.send(dumps(error_msg("登录验签失败")))
            return username
        await self._bind(ws, name)
        await ws.send(dumps({"type": "login_ok", "username": name}))
        log.info("login user=%s", name)
        await self._push_offline(ws, name)
        return name

    async def _bind(self, ws: Any, username: str) -> None:
        old = self.online.get(username)
        if old is not None and old is not ws:
            try:
                await old.send(dumps(error_msg("账号在其他终端登录")))
                await old.close()
            except Exception:
                pass
        self.online[username] = ws
        await self._broadcast_presence()

    async def _broadcast_presence(self) -> None:
        raw = dumps({"type": "presence", "online": sorted(self.online)})
        for sock in list(self.online.values()):
            try:
                await sock.send(raw)
            except Exception:
                pass
        log.info("presence count=%s", len(self.online))

    async def _push_offline(self, ws: Any, username: str) -> None:
        delivered = 0
        for envelope_id, raw in self.store.list_offline(username):
            try:
                await ws.send(raw)
            except Exception:
                break
            self.store.delete_offline(envelope_id)
            delivered += 1
        if delivered:
            log.info("offline_push user=%s count=%s", username, delivered)

    async def on_upload_prekeys(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        opks = [b64d(x) for x in msg.get("opks") or []]
        opk_bytes = [x for x in opks if x]
        if len(opk_bytes) > 100 or any(len(item) != 32 for item in opk_bytes):
            await ws.send(dumps(error_msg("OPK 必须是最多 100 把 32 字节公钥")))
            return
        spk = None
        if msg.get("spk_pub"):
            spk_pub = b64d(msg["spk_pub"]) or b""
            spk_sig = b64d(msg["spk_sig"]) or b""
            user = self.store.get_user(username)
            if not user:
                await ws.send(dumps(error_msg("用户不存在")))
                return
            verify_spk(user[0], spk_pub, username, spk_sig)
            spk = (spk_pub, spk_sig, float(msg.get("spk_created") or 0))
        user = self.store.get_user(username)
        if not user:
            await ws.send(dumps(error_msg("用户不存在")))
            return
        pq_opks, pq_err = _decode_pq_opks(msg.get("pq_opks"), user[0], username)
        if pq_err or pq_opks is None:
            await ws.send(dumps(error_msg(pq_err or "一次性 PQ 预密钥无效")))
            return
        self.store.upload_prekeys(username, opk_bytes, spk, pq_opks)
        await ws.send(
            dumps(
                {
                    "type": "upload_prekeys_ok",
                    "count": len(opk_bytes),
                    "pq_count": len(pq_opks),
                }
            )
        )
        log.info(
            "upload_prekeys user=%s count=%s pq_count=%s",
            username,
            len(opk_bytes),
            len(pq_opks),
        )

    async def on_fetch_bundle(self, ws: Any, msg: dict[str, Any]) -> None:
        name = msg.get("username", "")
        validate_username(name)
        # 只有发起新会话才消耗一次性 PQ 预密钥。补拉长期 PQK 不能把池子烧掉。
        consume_pq = msg.get("consume_pq_opk") is True
        bundle = self.store.fetch_bundle(name, consume_pq_opk=consume_pq)
        if not bundle:
            await ws.send(dumps(error_msg("找不到该用户的预密钥")))
            return
        await ws.send(
            dumps(
                {
                    "type": "bundle",
                    "username": name,
                    "ik_sign_pub": b64e(bundle["ik_sign_pub"]),
                    "ik_dh_pub": b64e(bundle["ik_dh_pub"]),
                    "spk_pub": b64e(bundle["spk_pub"]),
                    "spk_sig": b64e(bundle["spk_sig"]),
                    "spk_created": bundle["spk_created"],
                    "opk": b64e(bundle["opk_pub"]) if bundle["opk_pub"] else None,
                    "pq_pub": b64e(bundle["pq_pub"]) if bundle["pq_pub"] else None,
                    "pq_sig": b64e(bundle["pq_sig"]) if bundle["pq_sig"] else None,
                    "pq_opk": b64e(bundle["pq_opk_pub"]) if bundle["pq_opk_pub"] else None,
                    "pq_opk_sig": (
                        b64e(bundle["pq_opk_sig"]) if bundle["pq_opk_sig"] else None
                    ),
                }
            )
        )
        log.info(
            "fetch_bundle user=%s opk=%s pq_opk=%s",
            name,
            "yes" if bundle["opk_pub"] else "no",
            "yes" if bundle["pq_opk_pub"] else "no",
        )

    async def on_fetch_user(self, ws: Any, msg: dict[str, Any]) -> None:
        name = msg.get("username", "")
        validate_username(name)
        user = self.store.get_user(name)
        if not user:
            await ws.send(dumps(error_msg("用户不存在")))
            return
        await ws.send(
            dumps(
                {
                    "type": "user",
                    "username": name,
                    "ik_sign_pub": b64e(user[0]),
                    "ik_dh_pub": b64e(user[1]),
                    "ik_pq_pub": b64e(user[2]) if user[2] else None,
                }
            )
        )

    async def on_list_users(self, ws: Any) -> None:
        users = self.store.list_users()
        online = sorted(self.online.keys())
        await ws.send(dumps({"type": "users", "users": users, "online": online}))

    async def on_envelope(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        src = msg.get("from") or username
        dst = msg.get("to")
        if src != username:
            await ws.send(dumps(error_msg("信封发送方必须是自己")))
            return
        validate_username(dst)
        payload = msg.get("payload")
        if not isinstance(payload, dict):
            await ws.send(dumps(error_msg("信封缺少 payload")))
            return
        if "ciphertext" not in payload:
            await ws.send(dumps(error_msg("信封缺少密文")))
            return
        group = payload.get("group")
        if group:
            members = self.store.group_members(group)
            if username not in members or dst not in members:
                await ws.send(dumps(error_msg("发送方或收件人不在该群")))
                return
        outgoing = dumps(
            {"type": "envelope", "from": src, "to": dst, "payload": payload}
        )
        check_size(outgoing)
        ct_b64 = payload.get("ciphertext") or ""
        log.info(
            "envelope %s -> %s ciphertext_b64_len=%s",
            src,
            dst,
            len(ct_b64) if isinstance(ct_b64, str) else 0,
        )
        peer = self.online.get(dst)
        if peer is not None:
            try:
                await peer.send(outgoing)
            except Exception:
                self.online.pop(dst, None)
                self.store.enqueue_offline(dst, outgoing)
                log.info("offline_queue %s -> %s after send failure", src, dst)
                await self._broadcast_presence()
        else:
            self.store.enqueue_offline(dst, outgoing)
            log.info("offline_queue %s -> %s", src, dst)
        await ws.send(dumps({"type": "envelope_ok", "to": dst}))

    async def on_group_create(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        try:
            state = decode_group_state(msg.get("state") or {})
        except (ProtocolError, KeyError) as exc:
            await ws.send(dumps(error_msg(f"群状态无效：{exc}")))
            return
        name = state.name
        validate_group_name(name)
        if self.store.group_exists(name):
            await ws.send(dumps(error_msg("群名已存在")))
            return
        members = list(state.members)
        if len(members) < 2:
            await ws.send(dumps(error_msg("群至少需要两名成员")))
            return
        if len(members) > MAX_GROUP_MEMBERS:
            await ws.send(dumps(error_msg("群最多 8 人")))
            return
        if state.signer != username or username not in members:
            await ws.send(dumps(error_msg("只有创建者能签署创世状态")))
            return
        for m in members:
            validate_username(m)
            if not self.store.user_exists(m):
                await ws.send(dumps(error_msg(f"成员 {m} 未注册")))
                return
        try:
            verify_state_transition(None, state)
            verify_group_state_sig(state, self.store.get_user(state.signer)[0])
        except Exception as exc:
            await ws.send(dumps(error_msg(f"群状态签名无效：{exc}")))
            return
        # 成员表仍是服务器状态，但现在只能是「由合法成员签署过的状态」：
        # 服务器伪造不了，客户端还会自己再验一遍。
        self.store.create_group(name, members)
        self.store.save_group_state(state)
        update = dumps(
            {
                "type": "group_update",
                "group": name,
                "members": members,
                "state": encode_group_state(state),
            }
        )
        await self._fanout_control(members, update)
        log.info("group_create name=%s size=%s epoch=%s", name, len(members), state.epoch)

    async def on_group_add(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        try:
            state = decode_group_state(msg.get("state") or {})
        except (ProtocolError, KeyError) as exc:
            await ws.send(dumps(error_msg(f"群状态无效：{exc}")))
            return
        name = state.name
        validate_group_name(name)
        if not self.store.group_exists(name):
            await ws.send(dumps(error_msg("群不存在")))
            return
        last = self.store.latest_group_state(name)
        if last is None:
            await ws.send(dumps(error_msg("群状态链缺失，无法拉人")))
            return
        newbies = [m for m in state.members if m not in last.members]
        if len(newbies) != 1:
            await ws.send(dumps(error_msg("每次拉人必须恰好新增一名成员")))
            return
        newbie = newbies[0]
        validate_username(newbie)
        if state.signer != username:
            await ws.send(dumps(error_msg("签署者必须是你自己")))
            return
        if not self.store.user_exists(newbie):
            await ws.send(dumps(error_msg("新成员未注册")))
            return
        if len(state.members) > MAX_GROUP_MEMBERS:
            await ws.send(dumps(error_msg("群最多 8 人")))
            return
        try:
            verify_state_transition(last, state)
            verify_group_state_sig(state, self.store.get_user(state.signer)[0])
        except Exception as exc:
            await ws.send(dumps(error_msg(f"群状态签名无效：{exc}")))
            return
        self.store.add_group_member(name, newbie)
        self.store.save_group_state(state)
        members = list(state.members)
        update = dumps(
            {
                "type": "group_update",
                "group": name,
                "members": members,
                "state": encode_group_state(state),
            }
        )
        await self._fanout_control(members, update)
        log.info("group_add name=%s member=%s epoch=%s", name, newbie, state.epoch)

    async def on_group_info(self, ws: Any, msg: dict[str, Any]) -> None:
        name = msg.get("group", "")
        validate_group_name(name)
        if not self.store.group_exists(name):
            await ws.send(dumps(error_msg("群不存在")))
            return
        state = self.store.latest_group_state(name)
        await ws.send(
            dumps(
                {
                    "type": "group_update",
                    "group": name,
                    "members": self.store.group_members(name),
                    "state": encode_group_state(state) if state else None,
                }
            )
        )

    async def on_group_sync(self, ws: Any, msg: dict[str, Any]) -> None:
        name = msg.get("group", "")
        validate_group_name(name)
        if not self.store.group_exists(name):
            await ws.send(dumps(error_msg("群不存在")))
            return
        states = self.store.load_group_states(name)
        await ws.send(
            dumps(
                {
                    "type": "group_states",
                    "group": name,
                    "states": [encode_group_state(s) for s in states],
                }
            )
        )

    def _blob_id(self, msg: dict[str, Any]) -> str | None:
        blob_id = msg.get("id")
        if isinstance(blob_id, str) and re.fullmatch(r"[0-9a-f]{32}", blob_id):
            return blob_id
        return None

    async def on_blob_begin(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        blob_id = self._blob_id(msg)
        if blob_id is None:
            await ws.send(dumps(error_msg("文件编号无效")))
            return
        size = msg.get("size")
        chunks = msg.get("chunks")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or isinstance(chunks, bool)
            or not isinstance(chunks, int)
        ):
            await ws.send(dumps(error_msg("文件大小无效")))
            return
        try:
            expect = expected_chunks(size)
        except AttachmentError:
            await ws.send(dumps(error_msg("文件超过 32MiB")))
            return
        if chunks != expect:
            await ws.send(dumps(error_msg("分片数量不对")))
            return
        recipients = msg.get("recipients")
        if (
            not isinstance(recipients, list)
            or not recipients
            or len(recipients) > MAX_GROUP_MEMBERS
        ):
            await ws.send(dumps(error_msg("收件人无效")))
            return
        clean: list[str] = []
        for name in recipients:
            if not isinstance(name, str):
                await ws.send(dumps(error_msg("收件人无效")))
                return
            try:
                validate_username(name)
            except ProtocolError:
                await ws.send(dumps(error_msg("收件人无效")))
                return
            if not self.store.user_exists(name):
                await ws.send(dumps(error_msg(f"收件人 {name} 未注册")))
                return
            clean.append(name)
        clean = sorted(set(clean))
        current = self.store.blob_get(blob_id)
        if current is not None:
            if (
                current["owner"] != username
                or current["size"] != size
                or current["chunks"] != chunks
                or set(current["recipients"]) != set(clean)
            ):
                await ws.send(dumps(error_msg("文件参数不一致")))
                return
        else:
            self.store.blob_begin(blob_id, username, size, chunks, clean)
        log.info(
            "blob_begin user=%s id=%s bytes=%s chunks=%s",
            username,
            blob_id,
            size,
            chunks,
        )
        await ws.send(dumps({"type": "blob_begin_ok", "id": blob_id}))

    async def on_blob_chunk(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        blob_id = self._blob_id(msg)
        if blob_id is None:
            await ws.send(dumps(error_msg("文件编号无效")))
            return
        info = self.store.blob_get(blob_id)
        if info is None or info["owner"] != username:
            await ws.send(dumps(error_msg("无权上传")))
            return
        index = msg.get("idx")
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < info["chunks"]:
            await ws.send(dumps(error_msg("分片序号无效")))
            return
        encoded = msg.get("data")
        data = b64d(encoded) if isinstance(encoded, str) else None
        if data is None:
            await ws.send(dumps(error_msg("分片无效")))
            return
        try:
            expect = cipher_len(info["size"], info["chunks"], index)
        except AttachmentError:
            await ws.send(dumps(error_msg("分片无效")))
            return
        if len(data) != expect:
            await ws.send(dumps(error_msg("分片长度不对")))
            return
        if info["complete"]:
            old = self.store.blob_chunk(blob_id, index)
            if old != data:
                await ws.send(dumps(error_msg("文件已完成，不能改分片")))
                return
        else:
            self.store.blob_put_chunk(blob_id, index, data)
        log.info(
            "blob_chunk user=%s id=%s idx=%s bytes=%s",
            username,
            blob_id,
            index,
            len(data),
        )
        await ws.send(dumps({"type": "blob_chunk_ok", "id": blob_id, "idx": index}))

    async def on_blob_finish(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        blob_id = self._blob_id(msg)
        if blob_id is None:
            await ws.send(dumps(error_msg("文件编号无效")))
            return
        info = self.store.blob_get(blob_id)
        if info is None or info["owner"] != username:
            await ws.send(dumps(error_msg("无权上传")))
            return
        if not info["complete"]:
            if self.store.blob_chunk_count(blob_id) != info["chunks"]:
                await ws.send(dumps(error_msg("分片不齐")))
                return
            for index in range(info["chunks"]):
                if self.store.blob_chunk(blob_id, index) is None:
                    await ws.send(dumps(error_msg("分片不齐")))
                    return
            self.store.blob_mark_complete(blob_id)
        log.info("blob_finish user=%s id=%s bytes=%s", username, blob_id, info["size"])
        await ws.send(dumps({"type": "blob_finish_ok", "id": blob_id}))

    async def on_blob_fetch(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        blob_id = self._blob_id(msg)
        if blob_id is None:
            await ws.send(dumps(error_msg("文件编号无效")))
            return
        info = self.store.blob_get(blob_id)
        if info is None or not info["complete"]:
            await ws.send(dumps(error_msg("文件尚未传完")))
            return
        if username not in info["recipients"]:
            await ws.send(dumps(error_msg("无权下载")))
            return
        index = msg.get("idx")
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < info["chunks"]:
            await ws.send(dumps(error_msg("分片序号无效")))
            return
        data = self.store.blob_chunk(blob_id, index)
        if data is None:
            await ws.send(dumps(error_msg("分片缺失")))
            return
        frame = dumps(
            {
                "type": "blob_fetch_ok",
                "id": blob_id,
                "idx": index,
                "data": b64e(data),
            }
        )
        check_size(frame)
        log.info(
            "blob_fetch user=%s id=%s idx=%s bytes=%s",
            username,
            blob_id,
            index,
            len(data),
        )
        await ws.send(frame)

    async def on_blob_done(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        blob_id = self._blob_id(msg)
        if blob_id is None:
            await ws.send(dumps(error_msg("文件编号无效")))
            return
        info = self.store.blob_get(blob_id)
        if info is not None and username not in info["recipients"]:
            await ws.send(dumps(error_msg("无权下载")))
            return
        if info is not None:
            self.store.blob_mark_download(blob_id, username)
        log.info("blob_done user=%s id=%s", username, blob_id)
        await ws.send(dumps({"type": "blob_done_ok", "id": blob_id}))

    async def _fanout_control(self, members: list[str], raw: str) -> None:
        for m in members:
            peer = self.online.get(m)
            if peer is not None:
                await peer.send(raw)
            else:
                self.store.enqueue_offline(m, raw)


async def run_server(host: str, port: int, db_path: str) -> None:
    store = ServerStore(db_path)
    server = ChatServer(store)
    log.info("%s 监听 %s:%s db=%s", PROJECT_NAME, host, port, db_path)
    async with websockets.serve(server.handler, host, port, max_size=64 * 1024):
        await asyncio.Future()


def main() -> None:
    parser = argparse.ArgumentParser(description=PROJECT_NAME)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="data/server.db")
    args = parser.parse_args()
    try:
        asyncio.run(run_server(args.host, args.port, args.db))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
