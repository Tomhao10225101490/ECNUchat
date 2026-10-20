"""好友申请、隐私、朋友圈和投递箱。"""

from __future__ import annotations

import asyncio
import base64
import time
from pathlib import Path

import pytest
import websockets

from src.client import ChatEngine
from src.protocol import ProtocolError
from src.server import ChatServer
from src.social import THREE_DAYS, clean_avatar, clean_file_payload
from src.store import ServerStore


def engine(tmp_path: Path, name: str) -> ChatEngine:
    return ChatEngine.open(name, "password123", str(tmp_path / f"{name}.db"))


async def wait_until(pred, timeout: float = 6.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if pred():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("状态没有在时限内变化")


def test_cleaners_reject_oversize_avatar_and_file() -> None:
    huge = "jpeg:" + base64.b64encode(b"\xff\xd8" + b"\x00" * 2000).decode("ascii")
    with pytest.raises(ProtocolError, match="头像太大"):
        clean_avatar(huge)
    with pytest.raises(ProtocolError, match="24KB"):
        clean_file_payload({"name": "a.bin", "data": base64.b64encode(b"x" * (24 * 1024 + 1)).decode("ascii")})
    assert clean_avatar("preset:3") == "preset:3"


def test_social_friends_moments_privacy_and_files(tmp_path: Path) -> None:
    asyncio.run(_social(tmp_path))


async def _social(tmp_path: Path) -> None:
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

        with pytest.raises(ProtocolError, match="好友"):
            await alice.send_text("太早了", peer="bob")
        with pytest.raises(ProtocolError, match="好友"):
            await alice.create_group("太早", ["bob"])

        await alice.friend_request("bob", "一起聊天")
        await wait_until(lambda: any(item["username"] == "alice" for item in bob.incoming_requests))
        assert bob.incoming_requests[0]["greeting"] == "一起聊天"
        await bob.friend_respond("alice", False)
        await wait_until(lambda: any(item["username"] == "bob" for item in alice.rejected_requests))
        with pytest.raises(ProtocolError, match="好友"):
            await alice.send_text("拒绝之后还不行", peer="bob")

        await alice.friend_request("bob", "再试一次")
        await wait_until(lambda: any(item["username"] == "alice" for item in bob.incoming_requests))
        await bob.friend_respond("alice", True)
        await wait_until(lambda: "bob" in alice.friend_names() and "alice" in bob.friend_names())
        await alice.send_text("现在可以了", peer="bob")
        await wait_until(lambda: any(row[1] == "现在可以了" for row in bob.store.get_history("dm:alice")))
        await bob.friend_request("carol", "互相")
        await carol.friend_request("bob", "互相")
        await wait_until(lambda: "carol" in bob.friend_names() and "bob" in carol.friend_names())

        await alice.friend_block("carol")
        with pytest.raises(ProtocolError, match="拉黑"):
            await alice.friend_request("carol")
        with pytest.raises(ProtocolError, match="无法向对方"):
            await carol.friend_request("alice")
        await alice.friend_remove("carol")

        dave_name = "dave"
        dave = engine(tmp_path, dave_name)
        await dave.connect(uri)
        await dave.privacy_set(
            require_approval=False,
            moments_visibility="friends",
            show_online=True,
            searchable=True,
        )
        await alice.friend_request(dave_name, "不用验证")
        assert dave_name in alice.friend_names()
        await wait_until(lambda: "alice" in dave.friend_names())

        await alice.profile_set("爱丽丝", "课程项目", "preset:1")
        await wait_until(lambda: any(item.get("display_name") == "爱丽丝" for item in bob.friends))

        jpeg = base64.b64encode(b"\xff\xd8" + b"\x11" * 40).decode("ascii")
        posted = await alice.moment_post("今天的朋友圈", image=jpeg, visibility="friends")
        moment_id = posted["moment"]["id"]
        await bob.refresh_moments()
        seen = next(item for item in bob.moments if item["id"] == moment_id)
        assert seen["body"] == "今天的朋友圈"
        assert seen["image"].startswith("/9j/") or seen["image"] == jpeg
        assert not any(item["id"] == moment_id for item in carol.moments)
        await carol.refresh_moments()
        assert not any(item["id"] == moment_id for item in carol.moments)

        await bob.moment_like(moment_id)
        await bob.moment_comment(moment_id, "看到了")
        await wait_until(
            lambda: any(
                item["id"] == moment_id and "bob" in item["likes"] and any(c["body"] == "看到了" for c in item["comments"])
                for item in alice.moments
            )
        )
        await alice.moment_post("只给自己", visibility="private")
        await bob.refresh_moments()
        assert not any(item["body"] == "只给自己" for item in bob.moments)
        assert any(item["body"] == "只给自己" for item in alice.moments)

        old = await alice.moment_post("三天前的事")
        old_id = old["moment"]["id"]
        server.store.conn.execute(
            "UPDATE moments SET created=? WHERE id=?",
            (time.time() - THREE_DAYS - 10, old_id),
        )
        server.store.conn.commit()
        await alice.privacy_set(
            require_approval=True,
            moments_visibility="three_days",
            show_online=True,
            searchable=True,
        )
        await bob.refresh_moments()
        assert not any(item["id"] == old_id for item in bob.moments)
        assert any(item["id"] == moment_id for item in bob.moments)
        await alice.privacy_set(
            require_approval=True,
            moments_visibility="none",
            show_online=False,
            searchable=False,
        )
        await bob.refresh_moments()
        await alice.refresh_moments()
        assert not any(item["author"] == "alice" and item["id"] == moment_id for item in bob.moments)
        assert any(item["id"] == moment_id for item in alice.moments)
        await wait_until(lambda: "alice" not in bob.online_users and "alice" in alice.online_users)
        users = await bob.list_users()
        assert "alice" in users["users"]
        stranger = await carol.list_users()
        assert "alice" not in stranger["users"]
        found = await carol.search_users("爱丽丝")
        assert found["users"] == []

        await alice.moment_delete(moment_id)
        await wait_until(lambda: not any(item["id"] == moment_id for item in alice.moments))

        payload = b"hello-dropbox"
        await alice.send_file(data=payload, filename="note.txt", peer="bob")
        await wait_until(lambda: any("note.txt" in row[1] for row in bob.store.get_history("dm:alice")))

        await alice.friend_remove("bob")
        with pytest.raises(ProtocolError, match="好友"):
            await alice.send_text("删掉之后不行", peer="bob")

        await alice.close()
        await bob.close()
        await carol.close()
        await dave.close()
