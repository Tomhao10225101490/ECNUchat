"""联网：密文上传、群隔离、篡改、离线下载和失败重试。"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import pytest
import websockets

from src.attachments import (
    FILE_PLAIN_CHUNK,
    MAX_FILE_BYTES,
    attachment_root,
    parse_history_body,
)
from src.client import ChatEngine, handle_line
from src.double_ratchet import GCMError, RatchetError, RatchetState, decrypt
from src.protocol import MAX_BLOB_FRAME, MAX_WS_MESSAGE, ProtocolError, decode_ratchet_payload, dumps
from src.server import ChatServer
from src.store import ServerStore
from tests.test_e2e import accept_group, engine, make_friends, wait_pred

MARKER = "明文标记-不应出现在服务器-7f3a".encode() + b"\x00photo"


def test_file_upload_group_tamper_offline_and_retry(tmp_path: Path) -> None:
    import asyncio

    asyncio.run(_all(tmp_path))


async def _all(tmp_path: Path) -> None:
    store = ServerStore(tmp_path / "server.db")
    server = ChatServer(store)
    log_buffer = _capture_server_log()
    try:
        async with websockets.serve(
            server.handler, "127.0.0.1", 0, max_size=MAX_BLOB_FRAME, compression=None
        ) as srv:
            uri = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
            alice = engine(tmp_path, "alice")
            bob = engine(tmp_path, "bob")
            carol = engine(tmp_path, "carol")
            dave = engine(tmp_path, "dave")
            await alice.connect(uri)
            await bob.connect(uri)
            await carol.connect(uri)
            await dave.connect(uri)
            await make_friends(alice, bob)
            await make_friends(alice, carol)
            await _roundtrip_and_blind(server, alice, bob, log_buffer)
            await _group_isolation(server, alice, bob, carol)
            await _retry_does_not_ratchet_twice(alice, bob)
            bob = await _video_cache(alice, bob, tmp_path)
            await alice.close()
            await bob.close()
            await carol.close()
            await dave.close()

        async with websockets.serve(
            server.handler, "127.0.0.1", 0, max_size=MAX_BLOB_FRAME, compression=None
        ) as srv:
            uri = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
            await _offline_tamper_and_delivery(tmp_path, store, uri)
    finally:
        logging.getLogger("e2ee-server").removeHandler(log_buffer[0])


def _capture_server_log():
    import io

    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    logging.getLogger("e2ee-server").addHandler(handler)
    return handler, buffer


async def _roundtrip_and_blind(server, alice, bob, log_buffer) -> None:
    frames: list[dict] = []
    original = server.on_envelope

    async def capture(ws, username, msg):
        frames.append(msg)
        await original(ws, username, msg)

    server.on_envelope = capture
    plain = MARKER + b"hello-bob"
    path = alice.store.path.parent / "note.txt"
    path.write_bytes(plain)
    alice.current_peer = "bob"
    await handle_line(alice, f"/file {path}")
    item = await wait_pred(bob, lambda incoming: incoming.kind == "file" and incoming.attachment is not None)
    assert item.sender == "alice"
    assert Path(item.attachment["path"]).read_bytes() == plain
    assert "note.txt" in item.text
    saved = attachment_root(bob.store.path)
    assert any(parse_history_body(body) for _s, body, _t in bob.store.get_history("dm:alice"))
    file_frames = [frame for frame in frames if frame.get("payload", {}).get("kind") == "file"]
    assert len(file_frames) == 1
    raw = dumps(
        {
            "type": "envelope",
            "from": file_frames[0]["from"],
            "to": file_frames[0]["to"],
            "payload": file_frames[0]["payload"],
        }
    )
    assert len(raw.encode("utf-8")) < MAX_WS_MESSAGE
    job = alice.store.list_file_jobs()[0]
    key = base64.b64decode(job["meta"]["key"])
    blob = Path(server.store.path).read_bytes()
    assert plain not in blob
    assert key not in blob
    assert job["meta"]["key"] not in raw
    text = log_buffer[1].getvalue()
    assert plain.decode("utf-8", "ignore") not in text
    assert key.hex() not in text
    assert job["meta"]["key"] not in text
    assert saved.exists()
    server.on_envelope = original

    huge = path.parent / "huge.bin"
    with huge.open("wb") as handle:
        handle.seek(MAX_FILE_BYTES)
        handle.write(b"x")
    before = server.store.conn.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
    with pytest.raises(ProtocolError, match="8GiB"):
        await alice.send_file(str(huge), peer="bob")
    after = server.store.conn.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
    assert after == before


async def _group_isolation(server, alice, bob, carol) -> None:
    await alice.create_group("文件组", ["bob", "carol"])
    await accept_group(bob, "文件组", alice)
    await accept_group(carol, "文件组", alice, bob)
    frames: list[dict] = []
    original = server.on_envelope

    async def capture(ws, username, msg):
        frames.append(msg)
        await original(ws, username, msg)

    server.on_envelope = capture
    plain = b"group-same-plain" + MARKER
    await alice.send_file(data=plain, filename="same.txt", mime="text/plain", group="文件组")
    bob_item = await wait_pred(
        bob,
        lambda incoming: incoming.kind == "file"
        and bool(incoming.attachment)
        and incoming.attachment.get("name") == "same.txt",
    )
    carol_item = await wait_pred(
        carol,
        lambda incoming: incoming.kind == "file"
        and bool(incoming.attachment)
        and incoming.attachment.get("name") == "same.txt",
    )
    assert Path(bob_item.attachment["path"]).read_bytes() == plain
    assert Path(carol_item.attachment["path"]).read_bytes() == plain
    file_frames = [frame for frame in frames if frame.get("payload", {}).get("kind") == "file"]
    assert {frame["to"] for frame in file_frames} == {"bob", "carol"}
    bob_frame = next(frame for frame in file_frames if frame["to"] == "bob")
    message, _init = decode_ratchet_payload(bob_frame["payload"])
    probe = RatchetState.from_record(carol.sessions["alice"].to_record())
    with pytest.raises((GCMError, RatchetError)):
        decrypt(probe, message)
    server.on_envelope = original


async def _retry_does_not_ratchet_twice(alice, bob) -> None:
    await alice.send_text("先建立会话", peer="bob")
    await wait_pred(bob, lambda incoming: incoming.text == "先建立会话")
    before = alice.sessions["bob"].ns
    original = alice.request
    seen = {"n": 0}

    async def flaky(obj, *expect):
        if obj.get("type") == "envelope":
            seen["n"] += 1
            if seen["n"] == 1:
                raise ProtocolError("断线")
        return await original(obj, *expect)

    alice.request = flaky
    try:
        with pytest.raises(ProtocolError, match="断线"):
            await alice.send_file(
                data=b"retry-me",
                filename="retry.txt",
                peer="bob",
                local_id="retry-job",
            )
    finally:
        alice.request = original
    assert alice.sessions["bob"].ns == before + 1
    await alice.send_file(local_id="retry-job", peer="bob")
    assert alice.sessions["bob"].ns == before + 1
    item = await wait_pred(
        bob,
        lambda incoming: incoming.kind == "file"
        and bool(incoming.attachment)
        and incoming.attachment.get("name") == "retry.txt",
    )
    assert Path(item.attachment["path"]).read_bytes() == b"retry-me"


async def _video_cache(alice, bob, tmp_path: Path):
    plain = b"VIDEO" + MARKER + b"\x00" * 80
    await alice.send_file(
        data=plain,
        filename="clip.mp4",
        mime="video/mp4",
        peer="bob",
        local_id="clip-job",
    )
    item = await wait_pred(
        bob,
        lambda incoming: incoming.kind == "file"
        and bool(incoming.attachment)
        and incoming.attachment.get("name") == "clip.mp4",
    )
    assert item.attachment["encrypted"] is True
    assert item.attachment.get("saved") is False
    file_id = str(item.attachment.get("file_id") or item.attachment.get("id"))
    cache = attachment_root(bob.store.path) / "cipher" / file_id
    assert cache.is_dir()
    stored = b"".join(
        (cache / str(index)).read_bytes() for index in range(len(list(cache.iterdir())))
    )
    assert MARKER not in stored
    plain_copy = attachment_root(bob.store.path) / "files" / file_id
    assert not plain_copy.exists()
    opened = Path(await bob.materialize_video(file_id))
    assert opened.read_bytes() == plain
    packed = tmp_path / "clip.evideo"
    await bob.export_video(file_id, str(packed))
    raw = packed.read_bytes()
    assert raw.startswith(b"ECV1")
    assert MARKER not in raw
    saved = bob.store.load_file_cache(file_id)
    assert saved is not None
    assert saved["key"] not in raw.decode("ascii", "ignore")
    history = [
        body
        for _sender, body, _ts in bob.store.get_history("dm:alice")
        if "clip.mp4" in body
    ]
    assert history and saved["key"] not in history[0]
    saved_copy = tmp_path / "saved-clip.mp4"
    history_before = bob.store.get_history("dm:alice")
    bob.save_attachment("dm:alice", history[0], str(saved_copy))
    assert saved_copy.read_bytes() == plain
    assert bob.store.get_history("dm:alice") == history_before
    sender_id = alice.store.load_file_job("clip-job")["meta"]["id"]
    sender_cache = attachment_root(alice.store.path) / "cipher" / sender_id
    sender_bytes = b"".join(path.read_bytes() for path in sender_cache.iterdir())
    assert MARKER not in sender_bytes
    db = bob.store.path
    await bob.close()
    reopened = ChatEngine.open("bob", "password123", str(db))
    again = Path(await reopened.materialize_video(file_id))
    assert again.read_bytes() == plain
    return reopened


async def _offline_tamper_and_delivery(tmp_path: Path, store: ServerStore, uri: str) -> None:
    alice = ChatEngine.open("alice", "password123", str(tmp_path / "alice.db"))
    dave = ChatEngine.open("dave", "password123", str(tmp_path / "dave.db"))
    await alice.connect(uri)
    await dave.connect(uri)
    good = b"offline-ok-plain"
    swapped = b"A" * FILE_PLAIN_CHUNK + b"B" * FILE_PLAIN_CHUNK
    await alice.send_file(data=swapped, filename="swap.bin", peer="bob", local_id="swap-job")
    await alice.send_file(data=MARKER, filename="flip.bin", peer="bob", local_id="flip-job")
    await alice.send_file(data=good, filename="later.bin", peer="bob", local_id="later-job")
    swap_id = alice.store.load_file_job("swap-job")["meta"]["id"]
    first = store.blob_chunk(swap_id, 0)
    second = store.blob_chunk(swap_id, 1)
    assert first is not None and second is not None and first != second
    store.blob_put_chunk(swap_id, 0, second)
    store.blob_put_chunk(swap_id, 1, first)
    flip_id = alice.store.load_file_job("flip-job")["meta"]["id"]
    chunk = bytearray(store.blob_chunk(flip_id, 0) or b"")
    chunk[0] ^= 0x5A
    store.blob_put_chunk(flip_id, 0, bytes(chunk))
    raw_db = Path(store.path).read_bytes()
    assert MARKER not in raw_db
    assert good not in raw_db
    with pytest.raises(ProtocolError, match="无权下载"):
        await dave.request({"type": "blob_fetch", "id": flip_id, "idx": 0}, "blob_fetch_ok")
    await alice.close()
    await dave.close()

    bob = ChatEngine.open("bob", "password123", str(tmp_path / "bob.db"))
    await bob.connect(uri)
    errors = 0
    received = None
    while received is None:
        item = await wait_pred(
            bob,
            lambda incoming: incoming.error == "GCM 失败"
            or (
                incoming.kind == "file"
                and bool(incoming.attachment)
                and incoming.attachment.get("name") == "later.bin"
            ),
        )
        if item.error:
            errors += 1
        else:
            received = item
    assert errors == 2
    assert Path(received.attachment["path"]).read_bytes() == good
    rows = bob.store.get_history("dm:alice")
    parsed = [parse_history_body(body) for _sender, body, _ts in rows]
    assert any(body == "GCM 失败" for _sender, body, _ts in rows)
    names = [item["name"] for item in parsed if item]
    assert "later.bin" in names
    assert "swap.bin" not in names and "flip.bin" not in names
    root = attachment_root(bob.store.path)
    assert not list(root.rglob("*.part"))
    assert not list(root.rglob("swap.bin"))
    assert not list(root.rglob("flip.bin"))
    await bob.close()
