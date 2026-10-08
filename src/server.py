"""转发服务器：只保存公钥、预密钥和离线信封，不接触口令、私钥、明文、消息密钥。"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed

from src.prekeys import verify_spk
from src.protocol import (
    MAX_GROUP_MEMBERS,
    PROJECT_NAME,
    b64d,
    b64e,
    check_size,
    dumps,
    error_msg,
    loads,
    validate_group_name,
    validate_username,
)
from src.store import ServerStore

# 日志里禁止明文、私钥、SK、RK、CK、MK。聊天内容只允许 base64。
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("e2ee-server")


class ChatServer:
    def __init__(self, store: ServerStore) -> None:
        self.store = store
        self.online: dict[str, Any] = {}
        self.pending_challenge: dict[int, tuple[str, bytes]] = {}

    async def handler(self, ws: Any) -> None:
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
                    username = await self.dispatch(ws, username, msg)
                except Exception as exc:
                    log.info("error type=%s detail=%s", msg.get("type"), type(exc).__name__)
                    await ws.send(dumps(error_msg(str(exc))))
        except ConnectionClosed:
            pass
        finally:
            if username and self.online.get(username) is ws:
                del self.online[username]
                log.info("offline user=%s", username)

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
        if not ik_sign_pub or not ik_dh_pub or not spk_pub or not spk_sig:
            await ws.send(dumps(error_msg("注册公钥不完整")))
            return None
        try:
            verify_spk(ik_sign_pub, spk_pub, username, spk_sig)
        except Exception:
            await ws.send(dumps(error_msg("SPK 签名无效，拒绝入库")))
            return None
        opks = [b64d(x) for x in msg.get("opks") or []]
        opk_bytes = [x for x in opks if x]
        self.store.create_user(
            username,
            ik_sign_pub,
            ik_dh_pub,
            spk_pub,
            spk_sig,
            float(msg.get("spk_created") or 0),
            opk_bytes,
        )
        await self._bind(ws, username)
        await ws.send(dumps({"type": "register_ok", "username": username}))
        log.info("register user=%s opk_count=%s", username, len(opk_bytes))
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
            Ed25519PublicKey.from_public_bytes(user[0]).verify(
                b64d(sig) or b"", pending[1]
            )
        except InvalidSignature:
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

    async def _push_offline(self, ws: Any, username: str) -> None:
        items = self.store.drain_offline(username)
        for raw in items:
            await ws.send(raw)
        if items:
            log.info("offline_push user=%s count=%s", username, len(items))

    async def on_upload_prekeys(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        opks = [b64d(x) for x in msg.get("opks") or []]
        opk_bytes = [x for x in opks if x]
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
        self.store.upload_prekeys(username, opk_bytes, spk)
        await ws.send(dumps({"type": "upload_prekeys_ok", "count": len(opk_bytes)}))
        log.info("upload_prekeys user=%s count=%s", username, len(opk_bytes))

    async def on_fetch_bundle(self, ws: Any, msg: dict[str, Any]) -> None:
        name = msg.get("username", "")
        validate_username(name)
        bundle = self.store.fetch_bundle(name)
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
                }
            )
        )
        log.info(
            "fetch_bundle user=%s opk=%s",
            name,
            "yes" if bundle["opk_pub"] else "no",
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
            await peer.send(outgoing)
        else:
            self.store.enqueue_offline(dst, outgoing)
            log.info("offline_queue %s -> %s", src, dst)
        await ws.send(dumps({"type": "envelope_ok", "to": dst}))

    async def on_group_create(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        name = msg.get("group", "")
        validate_group_name(name)
        if self.store.group_exists(name):
            await ws.send(dumps(error_msg("群名已存在")))
            return
        members = list(dict.fromkeys([username, *(msg.get("members") or [])]))
        if len(members) < 2:
            await ws.send(dumps(error_msg("群至少需要两名成员")))
            return
        if len(members) > MAX_GROUP_MEMBERS:
            await ws.send(dumps(error_msg("群最多 8 人")))
            return
        for m in members:
            validate_username(m)
            if not self.store.user_exists(m):
                await ws.send(dumps(error_msg(f"成员 {m} 未注册")))
                return
        self.store.create_group(name, members)
        update = dumps({"type": "group_update", "group": name, "members": members})
        await self._fanout_control(members, update)
        log.info("group_create name=%s size=%s", name, len(members))

    async def on_group_add(self, ws: Any, username: str, msg: dict[str, Any]) -> None:
        name = msg.get("group", "")
        newbie = msg.get("member", "")
        validate_group_name(name)
        validate_username(newbie)
        members = self.store.group_members(name)
        if username not in members:
            await ws.send(dumps(error_msg("只有群内成员能拉人")))
            return
        if not self.store.user_exists(newbie):
            await ws.send(dumps(error_msg("新成员未注册")))
            return
        if newbie in members:
            await ws.send(dumps(error_msg("已在群内")))
            return
        if len(members) + 1 > MAX_GROUP_MEMBERS:
            await ws.send(dumps(error_msg("群最多 8 人")))
            return
        self.store.add_group_member(name, newbie)
        members = self.store.group_members(name)
        update = dumps({"type": "group_update", "group": name, "members": members})
        await self._fanout_control(members, update)
        log.info("group_add name=%s member=%s", name, newbie)

    async def on_group_info(self, ws: Any, msg: dict[str, Any]) -> None:
        name = msg.get("group", "")
        validate_group_name(name)
        if not self.store.group_exists(name):
            await ws.send(dumps(error_msg("群不存在")))
            return
        await ws.send(
            dumps(
                {
                    "type": "group_update",
                    "group": name,
                    "members": self.store.group_members(name),
                }
            )
        )

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
