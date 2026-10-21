"""一对一语音通话。

信令走双棘轮信封，通话钥匙只出现在内层 JSON 里。
接通之后的声音不逐步推进棘轮：每帧用这把通话钥匙做 AES-256-GCM。
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.protocol import ProtocolError, validate_username

CALL_MAGIC = b"ECC1"
CALL_ID_LEN = 16
CALL_KEY_LEN = 32
MAX_CALL_CIPHER = 2048
SAMPLE_RATE = 16000
FRAME_MS = 40
FRAME_BYTES = SAMPLE_RATE * 2 * FRAME_MS // 1000
INVITE_TTL = 45
RING_TIMEOUT = 45
CALLEE_TIMEOUT = 50
CALL_OPS = frozenset({"invite", "accept", "reject", "cancel", "hangup", "busy"})


@dataclass
class CallSession:
    call_id: bytes
    peer: str
    key: bytes
    role: str
    phase: str
    direction: int
    started: float | None = None
    send_seq: int = 0
    recv_seen: set[int] = field(default_factory=set)


def format_call_clock(seconds: int) -> str:
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def elapsed_seconds(started: float | None, now: float | None = None) -> int:
    if not started:
        return 0
    current = time.time() if now is None else now
    return max(0, int(current - started))


def invite_is_fresh(ts: int, now: float | None = None) -> bool:
    current = time.time() if now is None else now
    delta = current - ts
    return -30 <= delta <= INVITE_TTL


def parse_call_body(raw: object) -> dict[str, object]:
    """棘轮内层已经解开之后，再核对通话信令的形状。"""
    if not isinstance(raw, dict):
        raise ValueError
    op = raw.get("op")
    if op not in CALL_OPS:
        raise ValueError
    call_id = raw.get("id")
    if (
        not isinstance(call_id, str)
        or len(call_id) != 32
        or any(ch not in "0123456789abcdef" for ch in call_id)
    ):
        raise ValueError
    ts = raw.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int) or not 0 <= ts <= 4_000_000_000:
        raise ValueError
    key = None
    if op == "invite":
        encoded = raw.get("key")
        if not isinstance(encoded, str):
            raise ValueError
        try:
            key = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError from exc
        if len(key) != CALL_KEY_LEN:
            raise ValueError
    elif "key" in raw:
        raise ValueError
    return {"op": op, "id": bytes.fromhex(call_id), "ts": ts, "key": key}


def pack_call_frame(
    sender: str,
    recipient: str,
    call_id: bytes,
    direction: int,
    seq: int,
    ciphertext: bytes,
) -> bytes:
    validate_username(sender)
    validate_username(recipient)
    if (
        not isinstance(call_id, (bytes, bytearray))
        or len(call_id) != CALL_ID_LEN
        or direction not in (0, 1)
        or isinstance(seq, bool)
        or not isinstance(seq, int)
        or not 0 <= seq <= 0xFFFFFFFF
        or not isinstance(ciphertext, (bytes, bytearray))
        or not 16 <= len(ciphertext) <= MAX_CALL_CIPHER
    ):
        raise ProtocolError("通话帧无效")
    left = sender.encode("ascii")
    right = recipient.encode("ascii")
    return b"".join(
        (
            CALL_MAGIC,
            bytes([len(left)]),
            left,
            bytes([len(right)]),
            right,
            bytes(call_id),
            bytes([direction]),
            seq.to_bytes(4, "big"),
            bytes(ciphertext),
        )
    )


def unpack_call_frame(
    raw: bytes | bytearray,
) -> tuple[str, str, bytes, int, int, bytes] | None:
    """魔数对不上就返回 None，让附件帧继续走原来的 ECB1。"""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 4 or bytes(raw[:4]) != CALL_MAGIC:
        return None
    data = bytes(raw)
    pos = 4

    def take(n: int) -> bytes | None:
        nonlocal pos
        if n < 0 or pos + n > len(data):
            return None
        chunk = data[pos : pos + n]
        pos += n
        return chunk

    first = take(1)
    if first is None or not 3 <= first[0] <= 20:
        return None
    sender_b = take(first[0])
    second = take(1)
    if sender_b is None or second is None or not 3 <= second[0] <= 20:
        return None
    recipient_b = take(second[0])
    call_id = take(CALL_ID_LEN)
    direction_b = take(1)
    seq_b = take(4)
    if recipient_b is None or call_id is None or direction_b is None or seq_b is None:
        return None
    ciphertext = data[pos:]
    if not 16 <= len(ciphertext) <= MAX_CALL_CIPHER:
        return None
    try:
        sender = sender_b.decode("ascii")
        recipient = recipient_b.decode("ascii")
        validate_username(sender)
        validate_username(recipient)
    except (UnicodeDecodeError, ProtocolError):
        return None
    direction = direction_b[0]
    if direction not in (0, 1):
        return None
    return sender, recipient, call_id, direction, int.from_bytes(seq_b, "big"), ciphertext


def _nonce(direction: int, seq: int) -> bytes:
    return bytes([direction]) + seq.to_bytes(11, "big")


def _aad(call_id: bytes, direction: int, seq: int) -> bytes:
    return call_id + bytes([direction]) + seq.to_bytes(4, "big")


def seal_frame(key: bytes, call_id: bytes, direction: int, seq: int, pcm: bytes) -> bytes:
    if (
        len(key) != CALL_KEY_LEN
        or len(call_id) != CALL_ID_LEN
        or direction not in (0, 1)
        or isinstance(seq, bool)
        or not isinstance(seq, int)
        or not 0 <= seq <= 0xFFFFFFFF
        or not isinstance(pcm, (bytes, bytearray))
        or len(pcm) > FRAME_BYTES
        or len(pcm) % 2
    ):
        raise ProtocolError("通话音频帧无效")
    return AESGCM(key).encrypt(_nonce(direction, seq), bytes(pcm), _aad(call_id, direction, seq))


def open_frame(key: bytes, call_id: bytes, direction: int, seq: int, ciphertext: bytes) -> bytes:
    if (
        len(key) != CALL_KEY_LEN
        or len(call_id) != CALL_ID_LEN
        or direction not in (0, 1)
        or isinstance(seq, bool)
        or not isinstance(seq, int)
        or not 0 <= seq <= 0xFFFFFFFF
        or not isinstance(ciphertext, (bytes, bytearray))
    ):
        raise ProtocolError("通话帧校验失败")
    try:
        return AESGCM(key).decrypt(
            _nonce(direction, seq), bytes(ciphertext), _aad(call_id, direction, seq)
        )
    except Exception as exc:
        raise ProtocolError("通话帧校验失败") from exc
