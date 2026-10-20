"""会话私密等级：媒体默认只存加密缓存，点了保存才落明文。"""

import asyncio

import pytest

from src.attachments import (
    attachment_view,
    history_body,
    meta_to_dict,
    seal_bytes,
)
from src.client import ChatEngine
from src.prekeys import generate_identity
from src.protocol import ProtocolError
from src.store import ClientStore


def _sealed_record(mime: str, data: bytes) -> tuple[dict, object]:
    sealed = seal_bytes(data, "media.bin", mime)
    record = {
        "meta": meta_to_dict(sealed.meta),
        "sender": "bob",
        "group": None,
        "caption": "",
        "logged": False,
    }
    return record, sealed


def test_history_body_with_blob_id_is_unsaved() -> None:
    body = history_body(
        name="pic.png",
        mime="image/png",
        size=4,
        sha256=b"a" * 32,
        rel_path="",
        caption="看图",
        blob_id="ab" * 16,
        saved=False,
    )
    view = attachment_view("unused", body)
    assert view is not None
    assert view["id"] == "ab" * 16
    assert view["saved"] is False
    assert view["path"] == ""


def test_conversation_privacy_store_roundtrip(tmp_path) -> None:
    alice = generate_identity("alice")
    store = ClientStore(tmp_path / "alice.db")
    store.create("password123", alice)
    assert store.get_conversation_privacy("dm:bob") is None
    store.set_conversation_privacy("dm:bob", "high")
    assert store.get_conversation_privacy("dm:bob") == "high"
    assert store.load_conversation_privacy() == {"dm:bob": "high"}
    store.close()


def test_media_save_allowed_logic(tmp_path) -> None:
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
    assert engine._media_save_allowed("dm:bob", "image/png") is True
    store.set_conversation_privacy("dm:bob", "high")
    assert engine._media_save_allowed("dm:bob", "image/png") is False
    assert engine._media_save_allowed("dm:bob", "video/mp4") is False
    assert engine._media_save_allowed("dm:bob", "application/pdf") is True
    store.close()


def _finish(engine: ChatEngine, record: dict, sealed) -> None:
    async def fake_download_to_cache(meta, local_id) -> None:
        root = engine.store.path.parent / f"{engine.store.path.stem}.attachments"
        folder = root / "cipher" / meta.file_id.hex()
        folder.mkdir(parents=True, exist_ok=True)
        for index, chunk in enumerate(sealed.chunks):
            (folder / str(index)).write_bytes(chunk)

    async def fake_request(obj, *_expect):
        assert obj.get("type") == "blob_done"
        return {"type": "blob_done_ok"}

    engine._download_to_cache = fake_download_to_cache  # type: ignore[method-assign]
    engine.request = fake_request  # type: ignore[method-assign]
    asyncio.run(engine._finish_incoming(record))


def test_media_not_saved_by_default_and_save_writes_plaintext(tmp_path) -> None:
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
    record, sealed = _sealed_record("image/png", b"img-data")
    blob_id = str(record["meta"]["id"])
    _finish(engine, record, sealed)

    _sender, body, _ts = store.get_history("dm:bob")[-1]
    view = attachment_view(store.path, body)
    assert view is not None and view["saved"] is False and view["id"] == blob_id
    root = store.path.parent / f"{store.path.stem}.attachments"
    assert not (root / "files" / blob_id).exists()
    assert (root / "cipher" / blob_id).exists()

    first = tmp_path / "chosen.png"
    second = tmp_path / "again.png"
    engine.save_attachment("dm:bob", body, str(first))
    engine.save_attachment("dm:bob", body, str(second))
    assert first.read_bytes() == b"img-data"
    assert second.read_bytes() == b"img-data"
    # 另存为不修改历史，保存按钮可以反复使用
    assert store.get_history("dm:bob")[-1][1] == body
    store.close()


def test_high_privacy_cannot_save(tmp_path) -> None:
    alice = generate_identity("alice")
    store = ClientStore(tmp_path / "alice.db")
    store.create("password123", alice)
    store.set_conversation_privacy("dm:bob", "high")
    engine = ChatEngine(
        username="alice",
        password="password123",
        store=store,
        identity=alice,
        connected=True,
    )
    record, sealed = _sealed_record("image/png", b"img-data")
    _finish(engine, record, sealed)
    _sender, body, _ts = store.get_history("dm:bob")[-1]
    with pytest.raises(ProtocolError):
        engine.save_attachment("dm:bob", body, str(tmp_path / "blocked.png"))


def test_new_file_job_avoids_sqlite_in_worker_thread(tmp_path) -> None:
    """回归：封装任务跑在 to_thread 里，不能碰引擎线程的 SQLite 连接。"""
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
    image = tmp_path / "pic.png"
    image.write_bytes(b"png-bytes")

    async def run():
        return await asyncio.to_thread(
            engine._new_file_job,
            local_id="job-1",
            conv="dm:bob",
            group=None,
            recipients=["bob"],
            caption="",
            path=str(image),
            data=None,
            filename=None,
            mime=None,
            save_allowed=True,
        )

    record = asyncio.run(run())
    assert record["media"] is True
    engine.store.save_media_meta(str(record["meta"]["id"]), record["meta"])
    store.close()
