"""好友、资料、隐私、朋友圈和投递箱的字段边界。

单聊和群聊仍然走双棘轮。朋友圈、资料和好友关系存在服务器上，
这样点赞、评论和申请状态才能对每个好友保持一致。
投递箱里的文件内容仍放进双棘轮信封，服务器只看见密文。
"""

from __future__ import annotations

import base64
import re

from src.protocol import ProtocolError, validate_username

MOMENT_VISIBILITIES = ("friends", "three_days", "none")
POST_VISIBILITIES = ("friends", "private")
AVATAR_PRESETS = tuple(f"preset:{index}" for index in range(8))
MAX_AVATAR_CHARS = 1200
MAX_MOMENT_IMAGE_CHARS = 18000
MAX_DISPLAY_NAME = 24
MAX_BIO = 80
MAX_GREETING = 60
MAX_MOMENT_BODY = 500
MAX_COMMENT = 200
MAX_FILE_BYTES = 24 * 1024
THREE_DAYS = 3 * 24 * 60 * 60
_FILE_NAME = re.compile(r"[^\w.\-\u4e00-\u9fff]+", re.UNICODE)


def clean_display_name(value: object, username: str) -> str:
    text = str(value or "").strip()
    if not text:
        text = username
    if len(text) > MAX_DISPLAY_NAME:
        raise ProtocolError(f"昵称最多 {MAX_DISPLAY_NAME} 个字")
    return text


def clean_bio(value: object) -> str:
    text = str(value or "").strip()
    if len(text) > MAX_BIO:
        raise ProtocolError(f"简介最多 {MAX_BIO} 个字")
    return text


def clean_avatar(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text in AVATAR_PRESETS:
        return text
    if not text.startswith("jpeg:"):
        raise ProtocolError("头像只能是内置样式或 jpeg: 小图")
    payload = text[5:]
    if len(text) > MAX_AVATAR_CHARS:
        raise ProtocolError("头像太大，请换一张更小的图")
    try:
        raw = base64.b64decode(payload, validate=True)
    except Exception as exc:
        raise ProtocolError("头像数据无效") from exc
    if not raw.startswith(b"\xff\xd8"):
        raise ProtocolError("头像需要 JPEG")
    return text


def clean_account_visibility(value: object) -> str:
    text = str(value or "friends")
    if text not in MOMENT_VISIBILITIES:
        raise ProtocolError("朋友圈可见范围无效")
    return text


def clean_post_visibility(value: object) -> str:
    text = str(value or "friends")
    if text not in POST_VISIBILITIES:
        raise ProtocolError("这条朋友圈的可见范围无效")
    return text


def clean_greeting(value: object) -> str:
    text = str(value or "").strip()
    if len(text) > MAX_GREETING:
        raise ProtocolError(f"验证消息最多 {MAX_GREETING} 个字")
    return text


def clean_moment_body(value: object) -> str:
    text = str(value or "").strip()
    if len(text) > MAX_MOMENT_BODY:
        raise ProtocolError(f"朋友圈最多 {MAX_MOMENT_BODY} 个字")
    return text


def clean_moment_image(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > MAX_MOMENT_IMAGE_CHARS:
        raise ProtocolError("朋友圈图片请先缩小到 18KB 以内")
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ProtocolError("朋友圈图片无效") from exc
    if not raw.startswith(b"\xff\xd8"):
        raise ProtocolError("朋友圈图片需要 JPEG")
    return text


def clean_comment(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProtocolError("评论不能为空")
    if len(text) > MAX_COMMENT:
        raise ProtocolError(f"评论最多 {MAX_COMMENT} 个字")
    return text


def clean_filename(value: object) -> str:
    name = str(value or "").replace("\\", "/").split("/")[-1].strip()
    name = _FILE_NAME.sub("_", name).strip("._") or "file"
    return name[:80]


def clean_file_payload(file: object) -> dict[str, str] | None:
    if file is None:
        return None
    if not isinstance(file, dict):
        raise ProtocolError("附件格式无效")
    name = clean_filename(file.get("name"))
    data = file.get("data")
    if not isinstance(data, str) or not data:
        raise ProtocolError("附件内容无效")
    try:
        raw = base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ProtocolError("附件内容无效") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise ProtocolError("投递箱单文件不超过 24KB")
    if len(raw) == 0:
        raise ProtocolError("不能投递空文件")
    return {"name": name, "data": data}


def other_of(user_lo: str, user_hi: str, username: str) -> str:
    return user_hi if username == user_lo else user_lo


def pair_key(left: str, right: str) -> tuple[str, str]:
    validate_username(left)
    validate_username(right)
    if left == right:
        raise ProtocolError("不能添加自己")
    return (left, right) if left < right else (right, left)
