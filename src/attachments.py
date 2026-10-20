"""文件分块 AES-256-GCM。

文件钥匙和明文摘要只放进双棘轮信封的内层 JSON。
这一层自己生成 32 字节钥匙，不碰网络、数据库和棘轮状态。
"""

from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FILE_BYTES = 32 * 1024 * 1024
FILE_PLAIN_CHUNK = 24 * 1024
FILE_KEY_LEN = 32
FILE_ID_LEN = 16
NONCE_PREFIX_LEN = 8
GCM_TAG_LEN = 16
MAX_NAME_LEN = 120
_MIME_RE = re.compile(r"^[\w.+-]+/[\w.+-]+$")


class AttachmentError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class FileMeta:
    file_id: bytes
    key: bytes
    nonce_prefix: bytes
    sha256: bytes
    size: int
    chunks: int
    name: str
    mime: str


@dataclass
class SealedFile:
    meta: FileMeta
    chunks: list[bytes]


def expected_chunks(size: int) -> int:
    if isinstance(size, bool) or not isinstance(size, int):
        raise AttachmentError("文件大小无效")
    if size < 0 or size > MAX_FILE_BYTES:
        raise AttachmentError("文件超过 32MiB")
    if size == 0:
        return 1
    return (size + FILE_PLAIN_CHUNK - 1) // FILE_PLAIN_CHUNK


def plaintext_len(size: int, chunks: int, index: int) -> int:
    if index < 0 or index >= chunks:
        raise AttachmentError("分片序号无效")
    if index < chunks - 1:
        return FILE_PLAIN_CHUNK
    return size - FILE_PLAIN_CHUNK * (chunks - 1)


def cipher_len(size: int, chunks: int, index: int) -> int:
    return plaintext_len(size, chunks, index) + GCM_TAG_LEN


def chunk_nonce(prefix: bytes, index: int) -> bytes:
    if len(prefix) != NONCE_PREFIX_LEN or not 0 <= index <= 0xFFFFFFFF:
        raise AttachmentError("nonce 无效")
    return prefix + index.to_bytes(4, "big")


def chunk_aad(file_id: bytes, index: int, total: int) -> bytes:
    if len(file_id) != FILE_ID_LEN or not 0 <= index <= 0xFFFFFFFF or not 0 <= total <= 0xFFFFFFFF:
        raise AttachmentError("附加数据无效")
    return file_id + index.to_bytes(4, "big") + total.to_bytes(4, "big")


def clean_name(name: str) -> str:
    base = Path(str(name or "")).name.replace("\x00", "").replace("/", "_").replace("\\", "_")
    base = base.strip()
    if base in {"", ".", ".."}:
        base = "file"
    if len(base) > MAX_NAME_LEN:
        stem, dot, ext = base.rpartition(".")
        if dot and 0 < len(ext) <= 16:
            keep = MAX_NAME_LEN - len(ext) - 1
            base = f"{stem[:keep]}.{ext}"
        else:
            base = base[:MAX_NAME_LEN]
    return base


def guess_mime(name: str) -> str:
    mime, _enc = mimetypes.guess_type(clean_name(name))
    if mime and _MIME_RE.fullmatch(mime):
        return mime[:80]
    return "application/octet-stream"


def media_kind(mime: str) -> str:
    value = (mime or "").lower()
    if value.startswith("image/"):
        return "image"
    if value.startswith("video/"):
        return "video"
    return "file"


def format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: object, length: int, label: str) -> bytes:
    if not isinstance(data, str):
        raise AttachmentError(f"{label} 无效")
    try:
        raw = base64.b64decode(data, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AttachmentError(f"{label} 无效") from exc
    if len(raw) != length:
        raise AttachmentError(f"{label} 长度不对")
    return raw


def seal_bytes(data: bytes, name: str, mime: str | None = None) -> SealedFile:
    if not isinstance(data, (bytes, bytearray)):
        raise AttachmentError("文件内容无效")
    raw = bytes(data)
    chunks_n = expected_chunks(len(raw))
    file_id = os.urandom(FILE_ID_LEN)
    key = os.urandom(FILE_KEY_LEN)
    prefix = os.urandom(NONCE_PREFIX_LEN)
    aes = AESGCM(key)
    chunks: list[bytes] = []
    for index in range(chunks_n):
        start = index * FILE_PLAIN_CHUNK
        piece = raw[start : start + plaintext_len(len(raw), chunks_n, index)]
        chunks.append(
            aes.encrypt(
                chunk_nonce(prefix, index),
                piece,
                chunk_aad(file_id, index, chunks_n),
            )
        )
    safe_name = clean_name(name)
    safe_mime = mime if isinstance(mime, str) and _MIME_RE.fullmatch(mime) else guess_mime(safe_name)
    meta = FileMeta(
        file_id=file_id,
        key=key,
        nonce_prefix=prefix,
        sha256=hashlib.sha256(raw).digest(),
        size=len(raw),
        chunks=chunks_n,
        name=safe_name,
        mime=safe_mime[:80],
    )
    return SealedFile(meta=meta, chunks=chunks)


def open_bytes(meta: FileMeta, chunks: list[bytes]) -> bytes:
    if len(chunks) != meta.chunks:
        raise AttachmentError("GCM 失败")
    aes = AESGCM(meta.key)
    parts: list[bytes] = []
    for index, ciphertext in enumerate(chunks):
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise AttachmentError("GCM 失败")
        if len(ciphertext) != cipher_len(meta.size, meta.chunks, index):
            raise AttachmentError("GCM 失败")
        try:
            piece = aes.decrypt(
                chunk_nonce(meta.nonce_prefix, index),
                bytes(ciphertext),
                chunk_aad(meta.file_id, index, meta.chunks),
            )
        except (InvalidTag, ValueError) as exc:
            raise AttachmentError("GCM 失败") from exc
        parts.append(piece)
    plain = b"".join(parts)
    if len(plain) != meta.size or hashlib.sha256(plain).digest() != meta.sha256:
        raise AttachmentError("摘要不一致")
    return plain


def meta_to_dict(meta: FileMeta) -> dict:
    return {
        "id": meta.file_id.hex(),
        "key": _b64e(meta.key),
        "nonce": _b64e(meta.nonce_prefix),
        "sha256": _b64e(meta.sha256),
        "size": meta.size,
        "chunks": meta.chunks,
        "name": meta.name,
        "mime": meta.mime,
    }


def meta_from_dict(data: object) -> FileMeta:
    if not isinstance(data, dict):
        raise AttachmentError("文件说明无效")
    file_id_hex = data.get("id")
    if not isinstance(file_id_hex, str) or not re.fullmatch(r"[0-9a-f]{32}", file_id_hex):
        raise AttachmentError("文件编号无效")
    size = data.get("size")
    chunks = data.get("chunks")
    if isinstance(size, bool) or not isinstance(size, int) or isinstance(chunks, bool) or not isinstance(chunks, int):
        raise AttachmentError("文件大小无效")
    if chunks != expected_chunks(size):
        raise AttachmentError("分片数量不对")
    name = data.get("name")
    mime = data.get("mime")
    if not isinstance(name, str) or not isinstance(mime, str):
        raise AttachmentError("文件说明无效")
    safe_mime = mime if _MIME_RE.fullmatch(mime) else "application/octet-stream"
    return FileMeta(
        file_id=bytes.fromhex(file_id_hex),
        key=_b64d(data.get("key"), FILE_KEY_LEN, "文件钥匙"),
        nonce_prefix=_b64d(data.get("nonce"), NONCE_PREFIX_LEN, "nonce 前缀"),
        sha256=_b64d(data.get("sha256"), 32, "摘要"),
        size=size,
        chunks=chunks,
        name=clean_name(name),
        mime=safe_mime[:80],
    )


def attachment_root(db_path: str | Path) -> Path:
    path = Path(db_path)
    return path.parent / f"{path.stem}.attachments"


def history_body(
    *,
    name: str,
    mime: str,
    size: int,
    sha256: bytes,
    rel_path: str,
    caption: str,
) -> str:
    return json.dumps(
        {
            "v": 1,
            "kind": "file",
            "name": name,
            "mime": mime,
            "size": size,
            "sha256": sha256.hex(),
            "path": rel_path,
            "caption": caption,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def parse_history_body(body: str) -> dict | None:
    if not isinstance(body, str) or not body.startswith('{"v":1,"kind":"file"'):
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("v") != 1 or data.get("kind") != "file":
        return None
    name = data.get("name")
    mime = data.get("mime")
    size = data.get("size")
    digest = data.get("sha256")
    rel = data.get("path")
    caption = data.get("caption", "")
    if (
        not isinstance(name, str)
        or not isinstance(mime, str)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(rel, str)
        or rel.startswith("/")
        or ".." in Path(rel).parts
        or not isinstance(caption, str)
    ):
        return None
    return {
        "name": name,
        "mime": mime,
        "size": size,
        "sha256": digest,
        "path": rel,
        "caption": caption,
    }


def resolve_rel(db_path: str | Path, rel_path: str) -> Path:
    root = attachment_root(db_path).resolve()
    dest = (root / rel_path).resolve()
    if dest != root and root not in dest.parents:
        raise AttachmentError("附件路径越界")
    return dest


def attachment_view(db_path: str | Path, body: str) -> dict | None:
    record = parse_history_body(body)
    if record is None:
        return None
    try:
        path = resolve_rel(db_path, record["path"])
    except AttachmentError:
        return None
    return {
        "name": record["name"],
        "mime": record["mime"],
        "size": record["size"],
        "sha256": record["sha256"],
        "path": str(path),
        "rel": record["path"],
        "media": media_kind(record["mime"]),
        "caption": record["caption"],
    }


def _label(mime: str) -> str:
    return {"image": "图片", "video": "视频"}.get(media_kind(mime), "文件")


def display_text(body: str, db_path: str | Path | None = None) -> str:
    record = parse_history_body(body)
    if record is None:
        return body
    shown = record["path"]
    if db_path is not None:
        try:
            shown = str(resolve_rel(db_path, record["path"]))
        except AttachmentError:
            shown = record["path"]
    line = f"[{_label(record['mime'])}] {record['name']}（{format_size(record['size'])}） {shown}"
    caption = record["caption"].strip()
    if caption:
        return f"{caption}\n{line}"
    return line


def preview_text(body: str) -> str:
    record = parse_history_body(body)
    if record is None:
        return " ".join((body or "").split())
    base = f"[{_label(record['mime'])}] {record['name']}"
    caption = " ".join(record["caption"].split())
    if caption:
        return f"{caption} {base}"
    return base
