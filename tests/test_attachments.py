"""分块 AES-256-GCM：对调、篡改、摘要和 32MiB 上限。"""

from src.attachments import (
    FILE_PLAIN_CHUNK,
    MAX_FILE_BYTES,
    AttachmentError,
    history_body,
    meta_from_dict,
    meta_to_dict,
    open_bytes,
    parse_history_body,
    preview_text,
    seal_bytes,
)


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


def test_over_32mib_is_rejected() -> None:
    assert MAX_FILE_BYTES == 32 * 1024 * 1024
    try:
        seal_bytes(b"x" * (MAX_FILE_BYTES + 1), "big.bin")
    except AttachmentError as exc:
        assert "32MiB" in str(exc)
    else:
        raise AssertionError("超过 32MiB 仍被加密")
