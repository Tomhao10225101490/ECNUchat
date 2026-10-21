"""一对一语音通话：棘轮信令、ECC1 音频帧，服务器只转发密文。"""

import asyncio
import base64
import logging
import time
from pathlib import Path

import websockets

from src.call import (
    FRAME_BYTES,
    format_call_clock,
    invite_is_fresh,
    open_frame,
    pack_call_frame,
    parse_call_body,
    seal_frame,
    unpack_call_frame,
)
from src.client import ChatEngine
from src.protocol import ProtocolError, pack_blob_frame, unpack_blob_frame
from src.server import ChatServer
from src.store import ServerStore
from tests.test_e2e import make_friends

MARKER = b"CALL-PLAIN-91af"


def test_call_frames_reject_tampering_and_direction_mixups() -> None:
    assert format_call_clock(0) == "00:00"
    assert format_call_clock(12) == "00:12"
    assert format_call_clock(65) == "01:05"
    assert format_call_clock(3661) == "1:01:01"
    assert invite_is_fresh(int(time.time()))
    assert not invite_is_fresh(int(time.time()) - 90)

    call_id = b"c" * 16
    key = b"k" * 32
    pcm = b"\x01\x02" * 20
    left = seal_frame(key, call_id, 0, 3, pcm)
    assert open_frame(key, call_id, 0, 3, left) == pcm
    try:
        open_frame(key, call_id, 1, 3, left)
    except ProtocolError:
        pass
    else:
        raise AssertionError("两个方向的 nonce 撞在一起了")
    flipped = left[:-1] + bytes([left[-1] ^ 0x01])
    try:
        open_frame(key, call_id, 0, 3, flipped)
    except ProtocolError:
        pass
    else:
        raise AssertionError("改过的通话帧被解开了")

    frame = pack_call_frame("alice", "bob", call_id, 0, 3, left)
    assert unpack_call_frame(frame) == ("alice", "bob", call_id, 0, 3, left)
    assert unpack_blob_frame(frame) is None
    blob = pack_blob_frame("U", "a" * 32, "b" * 32, 0, b"cipher")
    assert unpack_call_frame(blob) is None
    assert unpack_call_frame(frame + b"\x00" * 3000) is None

    invite = parse_call_body(
        {"op": "invite", "id": call_id.hex(), "ts": 10, "key": base64.b64encode(key).decode("ascii")}
    )
    assert invite["key"] == key
    try:
        parse_call_body({"op": "accept", "id": call_id.hex(), "ts": 10, "key": invite_key(key)})
    except ValueError:
        pass
    else:
        raise AssertionError("接听信令不该再带钥匙")
    try:
        parse_call_body({"op": "invite", "id": call_id.hex(), "ts": 10})
    except ValueError:
        pass
    else:
        raise AssertionError("邀请没有钥匙也被收下了")


def invite_key(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def test_encrypted_call_is_relayed_not_stored(tmp_path: Path) -> None:
    asyncio.run(_call(tmp_path))


async def _wait_phase(engine: ChatEngine, phase: str, timeout: float = 6.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        session = engine._call
        if phase == "idle":
            if session is None:
                return None
        elif session is not None and session.phase == phase:
            return session
        await asyncio.sleep(0.02)
    have = engine._call.phase if engine._call is not None else "idle"
    raise AssertionError(f"等 {phase}，实际是 {have}")


def _bodies(engine: ChatEngine, peer: str) -> list[str]:
    return [body for _sender, body, _ts in engine.store.get_history(f"dm:{peer}")]


async def _call(tmp_path: Path) -> None:
    store = ServerStore(tmp_path / "server.db")
    server = ChatServer(store)
    caught = _LogGrab()
    logging.getLogger("e2ee-server").addHandler(caught)
    async with websockets.serve(
        server.handler, "127.0.0.1", 0, max_size=8 * 1024 * 1024 + 64 * 1024, compression=None
    ) as srv:
        uri = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
        alice = ChatEngine.open("alice", "password123", str(tmp_path / "alice.db"))
        bob = ChatEngine.open("bob", "password123", str(tmp_path / "bob.db"))
        carol = ChatEngine.open("carol", "password123", str(tmp_path / "carol.db"))
        await alice.connect(uri)
        await bob.connect(uri)
        await carol.connect(uri)
        try:
            try:
                await alice.call_invite("carol")
            except ProtocolError as exc:
                assert "好友" in str(exc)
            else:
                raise AssertionError("还不是好友也能打通")
            assert alice._call is None
            assert "carol" not in alice.sessions

            await make_friends(alice, bob)
            await make_friends(bob, carol)

            await alice.call_invite("bob")
            await _wait_phase(bob, "incoming")
            await bob.call_reject()
            await _wait_phase(alice, "idle")
            assert "已拒绝" in _bodies(bob, "alice")
            assert "对方已拒绝" in _bodies(alice, "bob")

            await alice.call_invite("bob")
            await _wait_phase(bob, "incoming")
            await alice.call_hangup()
            await _wait_phase(bob, "idle")
            assert "已取消" in _bodies(alice, "bob")
            assert "对方已取消" in _bodies(bob, "alice")

            heard_bob: list[bytes] = []
            heard_alice: list[bytes] = []
            bob.on_call_audio = heard_bob.append
            alice.on_call_audio = heard_alice.append
            await alice.call_invite("bob")
            await _wait_phase(bob, "incoming")
            await bob.call_accept()
            await _wait_phase(alice, "active")
            await _wait_phase(bob, "active")
            assert alice._call is not None and bob._call is not None
            key = alice._call.key
            assert bob._call.key == key
            assert key not in str(alice.call_view()).encode()

            pcm = (MARKER * 80)[:FRAME_BYTES]
            alice_ns = alice.sessions["bob"].ns
            bob_ns = bob.sessions["alice"].ns
            alice.offer_call_audio(pcm)
            for _ in range(100):
                if heard_bob:
                    break
                await asyncio.sleep(0.02)
            assert heard_bob == [pcm]
            assert alice.sessions["bob"].ns == alice_ns
            assert bob.sessions["alice"].ns == bob_ns

            bad = seal_frame(key, bob._call.call_id, 0, 0, b"\x11\x22" * 40)
            await bob.ws.send(pack_call_frame("bob", "alice", bob._call.call_id, 0, 0, bad))
            tampered = seal_frame(key, bob._call.call_id, 1, 1, b"\x33\x44" * 40)
            tampered = tampered[:-1] + bytes([tampered[-1] ^ 1])
            await bob.ws.send(pack_call_frame("bob", "alice", bob._call.call_id, 1, 1, tampered))
            await asyncio.sleep(0.1)
            assert heard_alice == []
            assert alice._call.phase == "active"
            assert bob._call.phase == "active"

            reply = b"\x55\x66" * (FRAME_BYTES // 2)
            bob.offer_call_audio(reply)
            for _ in range(100):
                if heard_alice:
                    break
                await asyncio.sleep(0.02)
            assert heard_alice == [reply]
            assert alice.sessions["bob"].ns == alice_ns
            assert bob.sessions["alice"].ns == bob_ns

            await alice.call_hangup()
            await _wait_phase(bob, "idle")
            assert any(line.startswith("语音通话 ") for line in _bodies(alice, "bob"))
            assert any(line.startswith("语音通话 ") for line in _bodies(bob, "alice"))

            await alice.call_invite("bob")
            await _wait_phase(bob, "incoming")
            await alice._call_timer(alice._call, 0, "caller")
            await _wait_phase(alice, "idle")
            await _wait_phase(bob, "idle")
            assert "对方无应答" in _bodies(alice, "bob")
            assert _bodies(bob, "alice").count("对方已取消") >= 1

            await alice.call_invite("bob")
            await _wait_phase(bob, "incoming")
            await bob.call_accept()
            await _wait_phase(alice, "active")
            try:
                await alice.call_invite("bob")
            except ProtocolError as exc:
                assert "正在通话" in str(exc)
            else:
                raise AssertionError("通话中还能再打一通")
            await carol.call_invite("bob")
            await _wait_phase(carol, "idle")
            assert "对方忙线中" in _bodies(carol, "bob")
            assert bob._call is not None and bob._call.peer == "alice" and bob._call.phase == "active"
            assert alice._call is not None and alice._call.phase == "active"
            await alice.call_hangup()
            await _wait_phase(bob, "idle")

            stale = {
                "op": "invite",
                "id": b"\xab" * 16,
                "ts": int(time.time()) - 90,
                "key": b"\xcd" * 32,
            }
            await bob._on_call_signal("alice", stale)
            assert bob._call is None

            for owner in (alice, bob, carol):
                for _sender, body, _ts in owner.store.get_history("dm:" + ("bob" if owner is alice else "alice" if owner is bob else "bob")):
                    assert MARKER.decode() not in body
                    assert key.hex() not in body
            for path in tmp_path.rglob("*"):
                if path.is_file():
                    blob = path.read_bytes()
                    assert MARKER not in blob
                    assert key not in blob
            logged = "\n".join(caught.lines)
            assert MARKER.decode() not in logged
            assert key.hex() not in logged
        finally:
            logging.getLogger("e2ee-server").removeHandler(caught)
            await alice.close()
            await bob.close()
            await carol.close()
    store.close()


class _LogGrab(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())
