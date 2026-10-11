"""输入框规则和消息分组，不依赖窗口。"""

import time

from src.gui.logic import (
    ChatItem,
    composer_enter_action,
    composer_target_height,
    day_label,
    decode_reply,
    encode_reply,
    finalize_groups,
    security_hint,
)


def test_enter_action_respects_shift_and_composition() -> None:
    assert composer_enter_action(shift=False, preedit="", swallow_until=0, now=10) == "send"
    assert composer_enter_action(shift=True, preedit="", swallow_until=0, now=10) == "newline"
    assert composer_enter_action(shift=False, preedit="ni", swallow_until=0, now=10) == "compose"
    assert composer_enter_action(shift=True, preedit="ni", swallow_until=0, now=10) == "compose"
    assert composer_enter_action(shift=False, preedit="", swallow_until=10.05, now=10.02) == "compose"
    assert composer_enter_action(shift=False, preedit="", swallow_until=10.05, now=10.2) == "send"


def test_composer_height_caps_at_six_lines() -> None:
    short, scroll = composer_target_height(20, 20, pad=16, max_lines=6)
    assert short == 36 and scroll is False
    mid, scroll = composer_target_height(20 * 3, 20, pad=16, max_lines=6)
    assert mid == 76 and scroll is False
    capped, scroll = composer_target_height(20 * 10, 20, pad=16, max_lines=6)
    assert capped == 20 * 6 + 16 and scroll is True


def test_consecutive_messages_share_one_avatar() -> None:
    items = [
        ChatItem(sender="bob", mine=False, ts=1_000, kind="message", body="一"),
        ChatItem(sender="bob", mine=False, ts=1_010, kind="message", body="二"),
        ChatItem(sender="bob", mine=False, ts=1_020, kind="message", body="三"),
        ChatItem(sender="alice", mine=True, ts=1_030, kind="message", body="四"),
        ChatItem(sender="alice", mine=True, ts=2_000, kind="message", body="五"),
    ]
    finalize_groups(items, is_group=True)
    assert items[0].show_avatar and items[0].show_name and not items[0].is_tail
    assert not items[1].show_avatar and not items[1].show_name and not items[1].is_tail
    assert not items[2].show_avatar and items[2].is_tail
    assert items[3].show_avatar and items[3].is_tail and not items[3].show_name
    assert items[4].show_avatar and items[4].is_tail


def test_thousand_messages_still_group() -> None:
    items = [
        ChatItem(sender="bob", mine=False, ts=float(i), kind="message", body=str(i))
        for i in range(1000)
    ]
    finalize_groups(items, is_group=False)
    assert items[0].show_avatar
    assert not any(item.show_avatar for item in items[1:])
    assert items[-1].is_tail
    assert not items[0].show_name


def test_day_reply_and_security_copy() -> None:
    now = time.time()
    assert day_label(now, now=now) == "今天"
    assert day_label(now - 86400, now=now) == "昨天"
    encoded = encode_reply("bob", "你好\n爱丽丝", "收到")
    author, quote, text = decode_reply(encoded)
    assert author == "bob" and "你好" in quote and text == "收到"
    assert security_hint("GCM 失败")
    assert security_hint("重放拒绝")
    assert security_hint("验签失败：身份协商公钥与服务器登记不一致")
