"""分块 AES-256-GCM：对调、篡改、摘要和 8GiB 上限。"""

from pathlib import Path

from src.attachments import (
    FILE_PLAIN_CHUNK,
    MAX_FILE_BYTES,
    AttachmentError,
    decrypt_chunk,
    expected_chunks,
    hash_file,
    history_body,
    meta_from_dict,
    meta_to_dict,
    open_bytes,
    parse_history_body,
    preview_text,
    seal_bytes,
    seal_path,
)
from src.protocol import MAX_BLOB_FRAME, MAX_WS_MESSAGE, pack_blob_frame


def test_roundtrip_and_history_omits_key() -> None:
    plain = "图片里的句子".encode() + b"\x00\xff" * 100
    sealed = seal_bytes(plain, "照片.png", "image/png")
    assert open_bytes(sealed.meta, sealed.chunks) == plain
    again = seal_bytes(plain, "照片.png", "image/png")
    assert again.meta.key != sealed.meta.key
    assert again.meta.file_id != sealed.meta.file_id
    body = history_body(
        name=sealed.meta.name,
        mime=sealed.meta.mime,
        size=sealed.meta.size,
        sha256=sealed.meta.sha256,
        rel_path=f"files/{sealed.meta.file_id.hex()}/{sealed.meta.name}",
        caption="说明",
    )
    record = parse_history_body(body)
    assert record is not None
    assert "key" not in record
    assert sealed.meta.key not in body.encode()
    assert preview_text(body).startswith("说明")
    assert "图片" in preview_text(body)


def test_tamper_swap_and_digest() -> None:
    plain = b"A" * FILE_PLAIN_CHUNK + b"B" * FILE_PLAIN_CHUNK
    sealed = seal_bytes(plain, "two.bin", "application/octet-stream")
    assert len(sealed.chunks) == 2
    flipped = bytearray(sealed.chunks[0])
    flipped[0] ^= 0x5A
    broken = [bytes(flipped), sealed.chunks[1]]
    try:
        open_bytes(sealed.meta, broken)
    except AttachmentError as exc:
        assert "GCM" in str(exc)
    else:
        raise AssertionError("改一个密文字节后仍解开了")
    try:
        open_bytes(sealed.meta, [sealed.chunks[1], sealed.chunks[0]])
    except AttachmentError:
        pass
    else:
        raise AssertionError("对调两块后仍解开了")
    forged = meta_from_dict(meta_to_dict(sealed.meta))
    forged.sha256 = b"\x11" * 32
    try:
        open_bytes(forged, sealed.chunks)
    except AttachmentError as exc:
        assert "摘要" in str(exc)
    else:
        raise AssertionError("换掉摘要后仍解开了")


def test_over_8gib_is_rejected(tmp_path: Path) -> None:
    assert MAX_FILE_BYTES == 8 * 1024 * 1024 * 1024
    assert FILE_PLAIN_CHUNK == 8 * 1024 * 1024
    try:
        expected_chunks(MAX_FILE_BYTES + 1)
    except AttachmentError as exc:
        assert "8GiB" in str(exc)
    else:
        raise AssertionError("超过 8GiB 仍被接受")
    huge = tmp_path / "huge.bin"
    with huge.open("wb") as handle:
        handle.seek(MAX_FILE_BYTES)
        handle.write(b"x")
    try:
        seal_path(huge, tmp_path / "cipher", "huge.bin")
    except AttachmentError as exc:
        assert "8GiB" in str(exc)
    else:
        raise AssertionError("超过 8GiB 仍被加密")
    assert not (tmp_path / "cipher").exists()


def test_stream_roundtrip_and_blob_frame_fits(tmp_path: Path) -> None:
    plain = b"V" * (FILE_PLAIN_CHUNK + 17)
    src = tmp_path / "clip.bin"
    src.write_bytes(plain)
    meta = seal_path(src, tmp_path / "cipher", "clip.mp4", "video/mp4")
    assert meta.chunks == 2
    dest = tmp_path / "out.bin"
    with dest.open("wb") as handle:
        handle.truncate(meta.size)
        for index in range(meta.chunks):
            ciphertext = (tmp_path / "cipher" / meta.file_id.hex() / str(index)).read_bytes()
            piece = decrypt_chunk(meta, index, ciphertext)
            handle.seek(index * FILE_PLAIN_CHUNK)
            handle.write(piece)
    assert hash_file(dest) == meta.sha256
    assert dest.read_bytes() == plain
    first = (tmp_path / "cipher" / meta.file_id.hex() / "0").read_bytes()
    raw = pack_blob_frame("U", "a" * 32, meta.file_id.hex(), 0, first)
    assert len(raw) > MAX_WS_MESSAGE
    assert len(raw) <= MAX_BLOB_FRAME
