"""语音消息：波形、密文缓存，以及棘轮信封里的钥匙。"""

import asyncio
from pathlib import Path

import websockets

from src.attachments import (
    attachment_root,
    attachment_view,
    history_body,
    parse_history_body,
    preview_text,
)
from src.client import ChatEngine
from src.prekeys import generate_identity
from src.protocol import MAX_BLOB_FRAME, ProtocolError
from src.server import ChatServer
from src.store import ClientStore, ServerStore
from src.voice import (
    PEAK_COUNT,
    duration_ms,
    format_duration,
    hold_should_cancel,
    pcm_to_wav,
    peaks_from_pcm,
    read_voice,
    wav_to_pcm,
)
from tests.test_e2e import make_friends, wait_pred

MARKER = b"VOICE-PLAIN-91af"


def _pcm(ms: int = 600) -> bytes:
    samples = 16_000 * ms // 1000
    raw = (MARKER * (samples * 2 // len(MARKER) + 1))[: samples * 2]
    return raw[: len(raw) - (len(raw) % 2)]


def test_wav_duration_and_cancel_gesture() -> None:
    pcm = _pcm()
    wav = pcm_to_wav(pcm)
    again, rate = wav_to_pcm(wav)
    assert again == pcm
    assert rate == 16_000
    assert duration_ms(pcm) == 600
    assert format_duration(600) == "0:01"
    assert format_duration(3200) == "0:03"
    assert format_duration(65_000) == "1:05"
    peaks = peaks_from_pcm(pcm)
    assert len(peaks) == PEAK_COUNT
    assert read_voice({"ms": 600, "peaks": peaks}, "audio/wav") == {"ms": 600, "peaks": peaks}
    assert read_voice({"ms": 600, "peaks": peaks}, "image/png") is None
    assert read_voice({"ms": 600, "peaks": [1, 2]}, "audio/wav") is None
    assert hold_should_cancel(0, 100, 0, 40)
    assert hold_should_cancel(100, 0, 20, 0)
    assert not hold_should_cancel(0, 0, 10, 10)


def test_voice_history_has_no_key() -> None:
    pcm = _pcm()
    peaks = peaks_from_pcm(pcm)
    body = history_body(
        name="voice.wav",
        mime="audio/wav",
        size=len(pcm_to_wav(pcm)),
        sha256=b"\xab" * 32,
        rel_path="",
        caption="",
        blob_id="cd" * 16,
        saved=False,
        voice={"ms": 600, "peaks": peaks},
    )
    record = parse_history_body(body)
    assert record is not None
    assert record["voice"]["ms"] == 600
    assert MARKER not in body.encode()
    assert b"key" not in body.encode()
    view = attachment_view("unused.db", body)
    assert view is not None
    assert view["media"] == "voice"
    assert view["encrypted"] is True
    assert view["file_id"] == "cd" * 16
    assert view["path"] == ""
    assert preview_text(body) == "语音 0:01"
    broken = body[:-1] + ',"voice":{"ms":"bad"}}'
    parsed = parse_history_body(broken)
    assert parsed is None or "voice" not in parsed


def test_plain_wav_attachment_is_not_a_voice_message(tmp_path: Path) -> None:
    alice = generate_identity("alice")
    store = ClientStore(tmp_path / "alice.db")
    store.create("password123", alice)
    engine = ChatEngine(
        username="alice",
        password="password123",
        store=store,
        identity=alice,
        connected=True,
    )
    wav = pcm_to_wav(_pcm())
    path = tmp_path / "song.wav"
    path.write_bytes(wav)
    record = engine._new_file_job(
        local_id="song",
        conv="dm:bob",
        group=None,
        recipients=["bob"],
        caption="",
        path=str(path),
        data=None,
        filename=None,
        mime="audio/wav",
        save_allowed=True,
    )
    assert record["media"] is False
    assert record["voice"] is None
    assert str(record["rel"]).startswith("files/")
    stored = attachment_root(store.path) / record["rel"]
    assert stored.read_bytes() == wav
    store.close()


def test_voice_is_sealed_and_delivered(tmp_path: Path) -> None:
    asyncio.run(_deliver(tmp_path))


async def _deliver(tmp_path: Path) -> None:
    store = ServerStore(tmp_path / "server.db")
    server = ChatServer(store)
    async with websockets.serve(
        server.handler, "127.0.0.1", 0, max_size=MAX_BLOB_FRAME, compression=None
    ) as srv:
        uri = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"
        alice = ChatEngine.open("alice", "password123", str(tmp_path / "alice.db"))
        bob = ChatEngine.open("bob", "password123", str(tmp_path / "bob.db"))
        await alice.connect(uri)
        await bob.connect(uri)
        await make_friends(alice, bob)
        wav = pcm_to_wav(_pcm())
        try:
            await alice.send_voice(pcm_to_wav(b"\x00\x00" * 100), peer="bob")
        except ProtocolError as exc:
            assert "太短" in str(exc)
        else:
            raise AssertionError("过短的语音也被发出去了")
        await alice.send_voice(wav, peer="bob")
        got = await wait_pred(
            bob,
            lambda item: item.kind == "file" and isinstance(item.attachment, dict) and item.attachment.get("media") == "voice",
        )
        assert got.attachment is not None
        assert got.attachment["duration_ms"] == 600
        assert got.attachment["encrypted"] is True
        file_id = str(got.attachment["id"])
        assert bob.media_plaintext(file_id) == wav
        for owner in (alice, bob):
            root = attachment_root(owner.store.path)
            plain_dir = root / "files"
            assert not plain_dir.exists() or not any(plain_dir.rglob("*"))
            for path in root.rglob("*"):
                if path.is_file():
                    assert MARKER not in path.read_bytes()
            _sender, body, _ts = owner.store.get_history("dm:" + ("bob" if owner is alice else "alice"))[-1]
            assert "语音" in preview_text(body)
            assert MARKER not in body.encode()
            record = parse_history_body(body)
            assert record is not None and record["voice"]["ms"] == 600
            meta = owner.store.load_media_meta(file_id)
            assert meta is not None
            assert meta["key"] not in body
        blob_root = tmp_path / "server.blobs"
        assert blob_root.is_dir()
        for path in blob_root.rglob("*"):
            if path.is_file():
                assert MARKER not in path.read_bytes()
        assert MARKER not in (tmp_path / "server.db").read_bytes()
        await alice.close()
        await bob.close()
    store.close()
