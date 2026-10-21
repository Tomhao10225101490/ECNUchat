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
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.voice import format_duration, read_voice

MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
FILE_PLAIN_CHUNK = 8 * 1024 * 1024
FILE_LIMIT_LABEL = "8GiB"
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
        raise AttachmentError(f"文件超过 {FILE_LIMIT_LABEL}")
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


def new_file_meta(size: int, name: str, mime: str | None = None) -> FileMeta:
    """只生成钥匙和编号。摘要在上传时边读边算，避免先把整份视频加密一遍。"""
    chunks_n = expected_chunks(size)
    safe_name = clean_name(name)
    safe_mime = mime if isinstance(mime, str) and _MIME_RE.fullmatch(mime) else guess_mime(safe_name)
    return FileMeta(
        file_id=os.urandom(FILE_ID_LEN),
        key=os.urandom(FILE_KEY_LEN),
        nonce_prefix=os.urandom(NONCE_PREFIX_LEN),
        sha256=b"\x00" * 32,
        size=size,
        chunks=chunks_n,
        name=safe_name,
        mime=safe_mime[:80],
    )


def encrypt_chunk(meta: FileMeta, index: int, piece: bytes) -> bytes:
    if not isinstance(piece, (bytes, bytearray)):
        raise AttachmentError("分片长度不对")
    if len(piece) != plaintext_len(meta.size, meta.chunks, index):
        raise AttachmentError("分片长度不对")
    return AESGCM(meta.key).encrypt(
        chunk_nonce(meta.nonce_prefix, index),
        bytes(piece),
        chunk_aad(meta.file_id, index, meta.chunks),
    )


def read_plain_chunk(fd: int, meta: FileMeta, index: int) -> bytes:
    want = plaintext_len(meta.size, meta.chunks, index)
    piece = os.pread(fd, want, index * FILE_PLAIN_CHUNK)
    if len(piece) != want:
        raise AttachmentError("文件读取中断")
    return piece


def decrypt_chunk(meta: FileMeta, index: int, ciphertext: bytes) -> bytes:
    if index < 0 or index >= meta.chunks:
        raise AttachmentError("GCM 失败")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise AttachmentError("GCM 失败")
    if len(ciphertext) != cipher_len(meta.size, meta.chunks, index):
        raise AttachmentError("GCM 失败")
    try:
        piece = AESGCM(meta.key).decrypt(
            chunk_nonce(meta.nonce_prefix, index),
            bytes(ciphertext),
            chunk_aad(meta.file_id, index, meta.chunks),
        )
    except (InvalidTag, ValueError) as exc:
        raise AttachmentError("GCM 失败") from exc
    if len(piece) != plaintext_len(meta.size, meta.chunks, index):
        raise AttachmentError("GCM 失败")
    return piece


def hash_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(FILE_PLAIN_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.digest()


def seal_path(
    src: Path,
    cipher_root: Path,
    name: str,
    mime: str | None = None,
    on_plain: Any = None,
) -> FileMeta:
    """按块从磁盘加密。明文不进内存列表，密文写到 cipher_root/<文件编号>/<序号>。"""
    if not src.is_file():
        raise AttachmentError("文件不存在")
    size = src.stat().st_size
    chunks_n = expected_chunks(size)
    file_id = os.urandom(FILE_ID_LEN)
    key = os.urandom(FILE_KEY_LEN)
    prefix = os.urandom(NONCE_PREFIX_LEN)
    aes = AESGCM(key)
    folder = cipher_root / file_id.hex()
    folder.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    sealed = 0
    try:
        with src.open("rb") as handle:
            for index in range(chunks_n):
                want = plaintext_len(size, chunks_n, index)
                piece = handle.read(want)
                if len(piece) != want:
                    raise AttachmentError("文件读取中断")
                digest.update(piece)
                sealed += len(piece)
                if on_plain is not None:
                    on_plain(sealed)
                ciphertext = aes.encrypt(
                    chunk_nonce(prefix, index),
                    piece,
                    chunk_aad(file_id, index, chunks_n),
                )
                (folder / str(index)).write_bytes(ciphertext)
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    safe_name = clean_name(name)
    safe_mime = mime if isinstance(mime, str) and _MIME_RE.fullmatch(mime) else guess_mime(safe_name)
    return FileMeta(
        file_id=file_id,
        key=key,
        nonce_prefix=prefix,
        sha256=digest.digest(),
        size=size,
        chunks=chunks_n,
        name=safe_name,
        mime=safe_mime[:80],
    )


def cache_rel(file_id: bytes) -> str:
    return f"cache/{file_id.hex()}"


def materialize_plain(meta: FileMeta, cache_dir: Path, dest: Path) -> None:
    """把加密缓存解开成临时明文，供播放器读取。摘要不对就删掉临时文件。"""
    digest = hashlib.sha256()
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    try:
        with partial.open("wb") as handle:
            for index in range(meta.chunks):
                ciphertext = (cache_dir / str(index)).read_bytes()
                piece = decrypt_chunk(meta, index, ciphertext)
                digest.update(piece)
                handle.write(piece)
        if digest.digest() != meta.sha256 or partial.stat().st_size != meta.size:
            raise AttachmentError("摘要不一致")
        os.chmod(partial, 0o600)
        partial.replace(dest)
    except Exception:
        partial.unlink(missing_ok=True)
        dest.unlink(missing_ok=True)
        raise


def export_cipher_pack(cache_dir: Path, meta: FileMeta, dest: Path) -> None:
    """另存一份加密副本。文件里没有钥匙，只有分片密文。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    try:
        with partial.open("wb") as handle:
            handle.write(b"ECV1")
            handle.write(meta.file_id)
            handle.write(meta.chunks.to_bytes(4, "big"))
            for index in range(meta.chunks):
                blob = (cache_dir / str(index)).read_bytes()
                if len(blob) != cipher_len(meta.size, meta.chunks, index):
                    raise AttachmentError("加密缓存损坏")
                handle.write(len(blob).to_bytes(8, "big"))
                handle.write(blob)
        os.chmod(partial, 0o600)
        partial.replace(dest)
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def clear_playback_files(db_path: str | Path) -> None:
    play = attachment_root(db_path) / "play"
    if not play.is_dir():
        return
    for child in play.iterdir():
        if child.is_file():
            child.unlink(missing_ok=True)


def place_local_copy(src: Path, dest: Path) -> None:
    """发送方留下一份明文。同一文件系统上用硬链接，避免再读一遍大视频。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    try:
        os.link(src, dest)
    except OSError:
        shutil.copyfile(src, dest)


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
    if size < 1024 * 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} MB"
    return f"{size / 1024 / 1024 / 1024:.1f} GB"


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
    parts = [decrypt_chunk(meta, index, ciphertext) for index, ciphertext in enumerate(chunks)]
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
    store: str = "plain",
    blob_id: str | None = None,
    saved: bool = True,
    voice: dict | None = None,
) -> str:
    payload: dict[str, Any] = {
        "v": 1,
        "kind": "file",
        "name": name,
        "mime": mime,
        "size": size,
        "sha256": sha256.hex(),
        "caption": caption,
    }
    checked = read_voice(voice, mime) if voice is not None else None
    if voice is not None and checked is None:
        raise AttachmentError("语音无效")
    if checked is not None:
        payload["voice"] = {"ms": checked["ms"], "peaks": checked["peaks"]}
    if blob_id:
        payload["id"] = blob_id
        payload["path"] = ""
        payload["saved"] = bool(saved)
    else:
        payload["path"] = rel_path
        if store != "plain":
            payload["store"] = store
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


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
    store = data.get("store", "plain")
    blob_id = data.get("id")
    saved = data.get("saved", True)
    if (
        not isinstance(name, str)
        or not isinstance(mime, str)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(caption, str)
        or store not in {"plain", "cipher"}
        or not isinstance(saved, bool)
    ):
        return None
    if blob_id is not None:
        if not isinstance(blob_id, str) or not re.fullmatch(r"[0-9a-f]{32}", blob_id):
            return None
        if rel not in (None, ""):
            return None
        rel = ""
        store = "plain"
    else:
        if (
            not isinstance(rel, str)
            or rel.startswith("/")
            or ".." in Path(rel).parts
        ):
            return None
        if store == "cipher":
            parts = Path(rel).parts
            if len(parts) != 2 or parts[0] != "cache" or not re.fullmatch(r"[0-9a-f]{32}", parts[1]):
                return None
    voice = read_voice(data.get("voice"), mime) if "voice" in data else None
    parsed = {
        "name": name,
        "mime": mime,
        "size": size,
        "sha256": digest,
        "path": rel,
        "caption": caption,
        "store": store,
        "id": blob_id,
        "saved": saved,
    }
    if voice is not None:
        parsed["voice"] = voice
    return parsed


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
    kind = media_kind(record["mime"])
    voice = record.get("voice")
    if record.get("id"):
        view = {
            "name": record["name"],
            "mime": record["mime"],
            "size": record["size"],
            "sha256": record["sha256"],
            "id": record["id"],
            "saved": record["saved"],
            "path": "",
            "rel": "",
            "media": kind,
            "caption": record["caption"],
            "encrypted": kind in {"image", "video"},
            "file_id": record["id"] if kind == "video" else "",
        }
        return _with_voice(view, voice)
    try:
        path = resolve_rel(db_path, record["path"])
    except AttachmentError:
        return None
    encrypted = record.get("store") == "cipher"
    file_id = Path(record["path"]).name if encrypted else ""
    view = {
        "name": record["name"],
        "mime": record["mime"],
        "size": record["size"],
        "sha256": record["sha256"],
        "path": str(path),
        "rel": record["path"],
        "media": kind,
        "caption": record["caption"],
        "encrypted": encrypted,
        "file_id": file_id,
        "id": "",
        "saved": True,
    }
    return _with_voice(view, voice)


def _with_voice(view: dict, voice: dict | None) -> dict:
    if not voice:
        return view
    view["media"] = "voice"
    view["encrypted"] = True
    view["file_id"] = str(view.get("id") or view.get("file_id") or "")
    view["duration_ms"] = voice["ms"]
    view["peaks"] = list(voice["peaks"])
    return view


def _label(mime: str) -> str:
    return {"image": "图片", "video": "视频"}.get(media_kind(mime), "文件")


def display_text(body: str, db_path: str | Path | None = None) -> str:
    record = parse_history_body(body)
    if record is None:
        return body
    voice = record.get("voice")
    if voice:
        line = f"[语音] {format_duration(voice['ms'])} · 加密缓存"
        caption = record["caption"].strip()
        if caption:
            return f"{caption}\n{line}"
        return line
    shown = ""
    if record.get("id"):
        cache = " · 加密缓存"
    else:
        shown = record["path"]
        if db_path is not None and shown:
            try:
                shown = str(resolve_rel(db_path, record["path"]))
            except AttachmentError:
                shown = record["path"]
        cache = " · 加密缓存" if record.get("store") == "cipher" else ""
    line = f"[{_label(record['mime'])}] {record['name']}（{format_size(record['size'])}）{cache}"
    if shown:
        line += f" {shown}"
    caption = record["caption"].strip()
    if caption:
        return f"{caption}\n{line}"
    return line


def preview_text(body: str) -> str:
    record = parse_history_body(body)
    if record is None:
        return " ".join((body or "").split())
    voice = record.get("voice")
    if voice:
        base = f"语音 {format_duration(voice['ms'])}"
        caption = " ".join(record["caption"].split())
        if caption:
            return f"{caption} {base}"
        return base
    base = f"[{_label(record['mime'])}] {record['name']}"
    caption = " ".join(record["caption"].split())
    if caption:
        return f"{caption} {base}"
    return base
