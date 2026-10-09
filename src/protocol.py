"""JSON 信封编解码、用户名规则、指纹与报文类型。

服务器只转发头和密文的 base64，不解析明文。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from src.double_ratchet import Header, RatchetMessage
from src.x3dh import InitialMessage

PROJECT_NAME = "基于ECDH与AES-GCM的端到端加密聊天室"
PROJECT_ABSTRACT = (
    "利用椭圆曲线Diffie-Hellman协商会话密钥，采用AES-GCM加密消息并校验完整性，"
    "结合数字签名认证身份，实现防窃听、防篡改的安全即时通讯。"
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MAX_WS_MESSAGE = 64 * 1024
MAX_GROUP_MEMBERS = 8
PROTOCOL_TYPES = (
    "register",
    "login_challenge",
    "login",
    "upload_prekeys",
    "fetch_bundle",
    "envelope",
    "error",
)


class ProtocolError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def b64e(data: bytes | None) -> str | None:
    if data is None:
        return None
    return base64.b64encode(data).decode("ascii")


def b64d(data: str | None) -> bytes | None:
    if data is None:
        return None
    return base64.b64decode(data)


def validate_username(username: str) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise ProtocolError("用户名只允许 3 到 20 位字母数字下划线")


def validate_group_name(name: str) -> None:
    if not name or len(name) > 32 or name.startswith("/"):
        raise ProtocolError("群名长度须为 1 到 32，且不能以 / 开头")


def fingerprint(ik_sign_pub: bytes) -> str:
    """IK_sign 公钥 SHA-256，16 组、每组 4 个大写十六进制。"""
    digest = hashlib.sha256(ik_sign_pub).hexdigest().upper()
    return " ".join(digest[i : i + 4] for i in range(0, 64, 4))


def fingerprint_short(ik_sign_pub: bytes) -> str:
    return " ".join(fingerprint(ik_sign_pub).split()[:8])


def dumps(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def loads(raw: str | bytes) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict) or "type" not in data:
        raise ProtocolError("报文必须是带 type 的 JSON")
    return data


def check_size(raw: str | bytes) -> None:
    n = len(raw.encode("utf-8") if isinstance(raw, str) else raw)
    if n > MAX_WS_MESSAGE:
        raise ProtocolError("单条 WebSocket 消息超过 64KB")


def encode_x3dh(init: InitialMessage) -> dict[str, Any]:
    return {
        "ik_dh_pub": b64e(init.ik_dh_pub),
        "ek_pub": b64e(init.ek_pub),
        "opk_pub": b64e(init.opk_pub),
        "signature": b64e(init.signature),
    }


def decode_x3dh(data: dict[str, Any] | None) -> InitialMessage | None:
    if not data:
        return None
    return InitialMessage(
        ik_dh_pub=b64d(data["ik_dh_pub"]) or b"",
        ek_pub=b64d(data["ek_pub"]) or b"",
        opk_pub=b64d(data.get("opk_pub")),
        signature=b64d(data["signature"]) or b"",
    )


def encode_ratchet_payload(
    message: RatchetMessage,
    *,
    x3dh: InitialMessage | None = None,
    group: str | None = None,
    kind: str = "chat",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "dh_pub": b64e(message.header.dh_pub),
        "n": message.header.n,
        "pn": message.header.pn,
        "nonce": b64e(message.nonce),
        "ciphertext": b64e(message.ciphertext),
        "kind": kind,
    }
    if x3dh is not None:
        payload["x3dh"] = encode_x3dh(x3dh)
    if group:
        payload["group"] = group
    return payload


def decode_ratchet_payload(payload: dict[str, Any]) -> tuple[RatchetMessage, InitialMessage | None]:
    header = Header(
        dh_pub=b64d(payload["dh_pub"]) or b"",
        n=int(payload["n"]),
        pn=int(payload["pn"]),
    )
    msg = RatchetMessage(
        header=header,
        nonce=b64d(payload["nonce"]) or b"",
        ciphertext=b64d(payload["ciphertext"]) or b"",
    )
    return msg, decode_x3dh(payload.get("x3dh"))


def error_msg(message: str) -> dict[str, Any]:
    return {"type": "error", "message": message}
