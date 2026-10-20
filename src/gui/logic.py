"""与 Qt 无关的界面规则：分组、输入框、日期和安全提示。"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass


GROUP_GAP_SEC = 300.0
MAX_COMPOSER_LINES = 6

_REPLY = re.compile(r"^回复 ([^：\n]+)：「(.*?)」\n(.*)\Z", re.S)

SECURITY_RULES: tuple[tuple[str, str], ...] = (
    ("验签失败", "签名对不上，这条消息已丢弃"),
    ("重放被拒", "这条消息已经处理过，已拒绝重放"),
    ("重放拒绝", "这条消息已经处理过，已拒绝重放"),
    ("GCM 失败", "密文被改过，或密钥对不上"),
    ("跳过超限", "中间缺了太多条消息"),
    ("对方预密钥签名无效", "预密钥签名无效，未建立会话"),
)


@dataclass
class ChatItem:
    sender: str = ""
    mine: bool = False
    ts: float = 0.0
    kind: str = "message"
    body: str = ""
    raw: str = ""
    state: str = "accepted"
    local_id: str = ""
    reply_author: str = ""
    reply_text: str = ""
    hint: str = ""
    show_avatar: bool = True
    show_name: bool = True
    is_head: bool = True
    is_tail: bool = True
    anim: float = 1.0
    key: str = ""
    attachment: dict | None = None
    progress: float = -1.0


def security_hint(text: str) -> str | None:
    for key, hint in SECURITY_RULES:
        if key in (text or ""):
            return hint
    return None


def classify_row(sender: str, body: str, kind: str = "") -> str:
    if kind == "error" or security_hint(body):
        return "security"
    if sender == "系统" or kind in {"sys", "group_meta", "presence"}:
        return "system"
    return "message"


def day_label(ts: float, now: float | None = None) -> str:
    moment = time.localtime(ts)
    current = time.localtime(time.time() if now is None else now)
    if moment[:3] == current[:3]:
        return "今天"
    yesterday = time.localtime((time.time() if now is None else now) - 86400)
    if moment[:3] == yesterday[:3]:
        return "昨天"
    if moment.tm_year == current.tm_year:
        return time.strftime("%m月%d日", moment)
    return time.strftime("%Y年%m月%d日", moment)


def list_clock(ts: float, now: float | None = None) -> str:
    if not ts:
        return ""
    moment = time.localtime(ts)
    current = time.localtime(time.time() if now is None else now)
    if moment[:3] == current[:3]:
        return time.strftime("%H:%M", moment)
    yesterday = time.localtime((time.time() if now is None else now) - 86400)
    if moment[:3] == yesterday[:3]:
        return "昨天"
    if moment.tm_year == current.tm_year:
        return time.strftime("%m/%d", moment)
    return time.strftime("%Y/%m/%d", moment)


def message_clock(ts: float) -> str:
    if not ts:
        return ""
    return time.strftime("%H:%M", time.localtime(ts))


def encode_reply(author: str, quote: str, text: str) -> str:
    flat = " ".join(quote.split())
    if len(flat) > 80:
        flat = flat[:80] + "…"
    return f"回复 {author}：「{flat}」\n{text}"


def decode_reply(body: str) -> tuple[str, str, str]:
    matched = _REPLY.match(body or "")
    if not matched:
        return "", "", body or ""
    return matched.group(1), matched.group(2), matched.group(3)


def apply_message_groups(items: list[ChatItem], gap: float = GROUP_GAP_SEC) -> None:
    """连续、同一发送者、间隔不超过 gap 的消息合并成一组。"""
    previous: ChatItem | None = None
    for item in items:
        if item.kind != "message":
            if previous is not None:
                previous.is_tail = True
            previous = None
            item.show_avatar = False
            item.show_name = False
            item.is_head = False
            item.is_tail = False
            continue
        item.is_head = True
        item.is_tail = True
        item.show_avatar = True
        item.show_name = not item.mine
        if (
            previous is not None
            and previous.sender == item.sender
            and previous.mine == item.mine
            and not item.reply_author
            and 0 <= item.ts - previous.ts <= gap
        ):
            previous.is_tail = False
            item.is_head = False
            item.show_avatar = False
            item.show_name = False
        previous = item


def finalize_groups(
    items: list[ChatItem], *, is_group: bool, gap: float = GROUP_GAP_SEC
) -> None:
    apply_message_groups(items, gap=gap)
    for item in items:
        if item.kind != "message":
            item.show_avatar = False
            item.show_name = False
            continue
        if not is_group:
            item.show_name = False
            if item.mine:
                item.show_avatar = False
        elif item.mine:
            item.show_name = False


def drop_orphan_dates(items: list[ChatItem]) -> list[ChatItem]:
    kept: list[ChatItem] = []
    for index, item in enumerate(items):
        if item.kind == "date":
            rest = items[index + 1 :]
            if not any(other.kind != "date" for other in rest[:1]) and (
                not rest or rest[0].kind == "date"
            ):
                continue
            if index + 1 >= len(items) or items[index + 1].kind == "date":
                continue
        kept.append(item)
    return kept


def composer_enter_action(
    *,
    shift: bool,
    preedit: str,
    swallow_until: float,
    now: float,
) -> str:
    """返回 newline / compose / send。组字或刚上屏时不能把 Enter 当成发送。"""
    if preedit:
        return "compose"
    if shift:
        return "newline"
    if swallow_until and now < swallow_until:
        return "compose"
    return "send"


def composer_target_height(
    doc_height: float,
    line_height: int,
    *,
    pad: int = 16,
    max_lines: int = MAX_COMPOSER_LINES,
) -> tuple[int, bool]:
    """输入框高度。超过 max_lines 后不再长高，改为内部滚动。"""
    line = max(1, int(line_height))
    minimum = line + pad
    maximum = line * max_lines + pad
    natural = int(doc_height + 0.999) + pad
    return max(minimum, min(natural, maximum)), natural > maximum + 1


def hidden_key(conv: str, sender: str, ts: float, body: str) -> str:
    return f"{conv}\n{sender}\n{ts:.3f}\n{body}"
