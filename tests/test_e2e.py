"""联网验收：注册登录、中文单聊、离线队列、群、重放/篡改、Carol 解不开。"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import pytest
import websockets

from src.client import ChatEngine
from src.double_ratchet import GCMError, RatchetError, RatchetState, decrypt
from src.protocol import decode_ratchet_payload
from src.server import ChatServer
from src.store import ServerStore


async def wait_pred(engine: ChatEngine, pred, timeout: float = 10.0) -> Incoming:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while True:
        remain = deadline - loop.time()
        if remain <= 0:
            raise AssertionError("等待收件箱超时")
        item = await asyncio.wait_for(engine.inbox.get(), timeout=remain)
        if pred(item):
            return item


def engine(tmp_path: Path, name: str) -> ChatEngine:
    return ChatEngine.open(name, "password123", str(tmp_path / f"{name}.db"))


def test_e2e_chat_group_tamper_and_offline(tmp_path: Path) -> None:
    asyncio.run(_e2e(tmp_path))


async def _e2e(tmp_path: Path) -> None:
    store = ServerStore(tmp_path / "server.db")
    server = ChatServer(store)
    async with websockets.serve(server.handler, "127.0.0.1", 0, max_size=64 * 1024) as srv:
        uri = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
        alice = engine(tmp_path, "alice")
        bob = engine(tmp_path, "bob")
        carol = engine(tmp_path, "carol")
        await alice.connect(uri)
        await bob.connect(uri)
        await carol.connect(uri)

        users = await alice.list_users()
        assert set(users["users"]) >= {"alice", "bob", "carol"}

        first = await alice.request({"type": "fetch_bundle", "username": "bob"}, "bundle")
        second = await carol.request({"type": "fetch_bundle", "username": "bob"}, "bundle")
        assert first.get("opk")
        if second.get("opk"):
            assert second["opk"] != first["opk"]

        await alice.send_text("你好鲍勃", peer="bob")
        assert (await wait_pred(bob, lambda i: i.text == "你好鲍勃")).sender == "alice"

        await bob.send_text("你好爱丽丝", peer="alice")
        assert (await wait_pred(alice, lambda i: i.text == "你好爱丽丝")).sender == "bob"
        assert alice.sessions["bob"].dh_ratchet_count >= 2
        assert bob.sessions["alice"].dh_ratchet_count >= 2

        await alice.send_text("给卡罗尔", peer="carol")
        assert (await wait_pred(carol, lambda i: i.text == "给卡罗尔")).text == "给卡罗尔"
        await carol.send_text("回爱丽丝", peer="alice")
        assert (await wait_pred(alice, lambda i: i.text == "回爱丽丝")).text == "回爱丽丝"

        payload = await alice._send_one("bob", "第二封给鲍勃", group=None, kind="chat")
        assert (await wait_pred(bob, lambda i: i.text == "第二封给鲍勃")).text == "第二封给鲍勃"
        msg, _ = decode_ratchet_payload(payload)
        probe = RatchetState.from_record(carol.sessions["alice"].to_record())
        with pytest.raises((GCMError, RatchetError)):
            decrypt(probe, msg)

        await bob._on_envelope({"from": "alice", "to": "bob", "payload": payload})
        assert (await wait_pred(bob, lambda i: i.error == "重放拒绝")).error == "重放拒绝"

        raw = bytearray(base64.b64decode(payload["ciphertext"]))
        raw[0] ^= 0x5A
        flipped = dict(payload)
        flipped["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
        await bob._on_envelope({"from": "alice", "to": "bob", "payload": flipped})
        assert (await wait_pred(bob, lambda i: i.error in {"重放拒绝", "GCM 失败"})).error

        await alice.create_group("三人组", ["bob", "carol"])
        await alice.send_text("群里大家好", group="三人组")
        assert await wait_pred(bob, lambda i: i.text == "群里大家好")
        assert await wait_pred(carol, lambda i: i.text == "群里大家好")

        await alice.close()
        await bob.close()
        await carol.close()

    store2 = ServerStore(tmp_path / "server.db")
    assert store2.user_exists("alice")
    server2 = ChatServer(store2)
    async with websockets.serve(server2.handler, "127.0.0.1", 0, max_size=64 * 1024) as srv:
        uri = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
        alice = ChatEngine.open("alice", "password123", str(tmp_path / "alice.db"))
        await alice.connect(uri)
        await alice.send_text("离线也能到", peer="bob")
        await alice.close()

        bob = ChatEngine.open("bob", "password123", str(tmp_path / "bob.db"))
        await bob.connect(uri)
        assert (await wait_pred(bob, lambda i: i.text == "离线也能到", timeout=15)).text == "离线也能到"
        await bob.close()
