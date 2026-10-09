"""Telegram 深色双栏终端界面。

左侧是会话列表（头像、预览、时间、未读），右侧是气泡对话。
自己的消息靠右，对方靠左。项目全名留在顶栏。
"""

from __future__ import annotations

import asyncio
import os
import sys
import termios
import time
import tty
from dataclasses import dataclass, field

from rich.cells import cell_len
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

from src import PROJECT_NAME
from src.client import ChatEngine, CommandResult, Incoming, handle_line, legacy_command_loop
from src.double_ratchet import RatchetError
from src.protocol import ProtocolError, fingerprint_short
from src.x3dh import X3DHError

BG = "on #0e1621"
SIDE_BG = "on #17212b"
SELECTED = "on #2b5278"
OUT = "on #2b5278"
IN = "on #182533"
COMPOSER = "on #242f3d"
NAME = "#6ab3f3"
MUTED = "#8b9bb4"
TIME = "#9eb2c6"
RED = "#ff6b6b"
ONLINE = "#4dcd5e"
BADGE = "bold white on #3390ec"
AVATARS = ("#e17076", "#faa774", "#a695e7", "#7bc862", "#6ec9cb", "#65aadd", "#ee7aae")

THEMES = {
    "telegram": {
        "selected": "on #2b5278",
        "out": "on #2b5278",
        "badge": "bold white on #3390ec",
        "name": "#6ab3f3",
    },
    "wechat": {
        "selected": "on #244238",
        "out": "on #95ec69",
        "badge": "bold #10210f on #07c160",
        "name": "#07c160",
    },
}


def apply_theme(name: str) -> None:
    global SELECTED, OUT, BADGE, NAME
    palette = THEMES.get(name, THEMES["telegram"])
    SELECTED = palette["selected"]
    OUT = palette["out"]
    BADGE = palette["badge"]
    NAME = palette["name"]

HELP_TEXT = """命令
  /chat 名字              打开单聊
  /fingerprint 名字       16 组身份指纹，线下核对
  /group create 群名 成员…
  /group add 群名 新成员
  /group 群名             打开群
  /users                  在线列表
  /history                当前会话记录
  /theme telegram|wechat  切换蓝色/微信绿色风格
  /help                   本页
  /quit                   退出

按键
  Enter 发送    Esc 关闭浮层
  Tab / ↑↓      切换会话（输入框为空时 ↑↓ 也切换）
  Ctrl-U        清空输入
"""

SECURITY = ("验签失败", "重放拒绝", "GCM 失败", "跳过超限", "对方预密钥签名无效")


def avatar_color(name: str) -> str:
    total = sum(name.encode("utf-8"))
    return AVATARS[total % len(AVATARS)]


def clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    out = ""
    for ch in text.replace("\n", " "):
        if cell_len(out + ch) > width:
            if width == 1:
                return "…"
            trimmed = out
            while trimmed and cell_len(trimmed + "…") > width:
                trimmed = trimmed[:-1]
            return trimmed + "…"
        out += ch
    return out


def wrap_cells(text: str, width: int) -> list[str]:
    if width < 1:
        return [text]
    lines: list[str] = []
    cur = ""
    for ch in text:
        if ch == "\n":
            lines.append(cur)
            cur = ""
            continue
        if cell_len(cur + ch) > width and cur:
            lines.append(cur)
            cur = ch
        else:
            cur += ch
    lines.append(cur)
    return lines or [""]


def short_clock(ts: float) -> str:
    if not ts:
        return ""
    dt = time.localtime(ts)
    now = time.localtime()
    if dt[:3] == now[:3]:
        return time.strftime("%H:%M", dt)
    return time.strftime("%m-%d", dt)


def day_label(ts: float) -> str:
    dt = time.localtime(ts)
    now = time.localtime()
    if dt[:3] == now[:3]:
        return "今天"
    yesterday = time.localtime(time.time() - 86400)
    if dt[:3] == yesterday[:3]:
        return "昨天"
    return time.strftime("%Y-%m-%d", dt)


def _utf8_len(lead: int) -> int:
    if lead < 0x80:
        return 1
    if lead & 0xE0 == 0xC0:
        return 2
    if lead & 0xF0 == 0xE0:
        return 3
    if lead & 0xF8 == 0xF0:
        return 4
    return 1


def _esc_pending(buf: bytearray) -> bool:
    if not buf or buf[0] != 0x1B:
        return False
    if len(buf) == 1:
        return True
    if len(buf) >= 2 and buf[1] == ord("["):
        return not any(0x40 <= value <= 0x7E for value in buf[2:])
    return len(buf) == 1


def drain_keys(buf: bytearray, *, flush: bool = False) -> list[str]:
    """把终端字节切成按键。不完整的 UTF-8 或方向键留在 buf 里。

    flush=True 时，把单独的 Esc（或没写完的 Esc [）当成退出键，避免卡片关不掉。
    """
    keys: list[str] = []
    while buf:
        b0 = buf[0]
        if b0 == 0x1B:
            if len(buf) >= 3 and buf[1] == ord("["):
                end = next(
                    (i for i, value in enumerate(buf[2:], 2) if 0x40 <= value <= 0x7E),
                    None,
                )
                if end is not None:
                    sequence = bytes(buf[: end + 1])
                    mapping = {
                        b"\x1b[A": "up",
                        b"\x1b[B": "down",
                        b"\x1b[C": "right",
                        b"\x1b[D": "left",
                        b"\x1b[H": "home",
                        b"\x1b[F": "end",
                        b"\x1b[1~": "home",
                        b"\x1b[4~": "end",
                        b"\x1b[3~": "delete",
                        b"\x1b[5~": "page-up",
                        b"\x1b[6~": "page-down",
                        b"\x1b[200~": "paste-start",
                        b"\x1b[201~": "paste-end",
                    }
                    keys.append(mapping.get(sequence, "ignore"))
                    del buf[: end + 1]
                    continue
            if _esc_pending(buf) and not flush:
                break
            if len(buf) >= 2 and buf[1] == ord("["):
                del buf[:2]
            else:
                del buf[:1]
            keys.append("esc")
            continue
        if b0 in (10, 13):
            keys.append("enter")
            del buf[:1]
            continue
        if b0 in (127, 8):
            keys.append("backspace")
            del buf[:1]
            continue
        if b0 == 9:
            keys.append("tab")
            del buf[:1]
            continue
        if b0 == 3:
            keys.append("ctrl-c")
            del buf[:1]
            continue
        if b0 == 4:
            keys.append("ctrl-d")
            del buf[:1]
            continue
        if b0 == 21:
            keys.append("ctrl-u")
            del buf[:1]
            continue
        if b0 == 14:
            keys.append("ctrl-n")
            del buf[:1]
            continue
        if b0 == 16:
            keys.append("ctrl-p")
            del buf[:1]
            continue
        if b0 < 32:
            del buf[:1]
            continue
        need = _utf8_len(b0)
        if len(buf) < need:
            break
        try:
            keys.append(buf[:need].decode("utf-8"))
        except UnicodeDecodeError:
            keys.append("?")
        del buf[:need]
    return keys


@dataclass
class ConvItem:
    key: str
    title: str
    kind: str
    preview: str = ""
    ts: float = 0.0
    unread: int = 0


@dataclass
class UIState:
    composer: str = ""
    cursor: int = 0
    overlay: str | None = None
    toast: str = ""
    unread: dict[str, int] = field(default_factory=dict)
    overlay_offset: int = 0
    paste_mode: bool = False


def current_key(engine: ChatEngine) -> str | None:
    if engine.current_group:
        return f"group:{engine.current_group}"
    if engine.current_peer:
        return f"dm:{engine.current_peer}"
    return None


def list_conversations(engine: ChatEngine, ui: UIState) -> list[ConvItem]:
    found: dict[str, ConvItem] = {}
    for conv, sender, body, ts in engine.store.recent_messages():
        if conv.startswith("dm:"):
            title, kind = conv[3:], "dm"
        elif conv.startswith("group:"):
            title, kind = conv[6:], "group"
        else:
            continue
        preview = body if sender in {engine.username, "系统"} else f"{sender}: {body}"
        found[conv] = ConvItem(conv, title, kind, preview, ts, ui.unread.get(conv, 0))
    for name in engine.groups:
        found.setdefault(f"group:{name}", ConvItem(f"group:{name}", name, "group", unread=ui.unread.get(f"group:{name}", 0)))
    names = set(engine.sessions)
    if engine.current_peer:
        names.add(engine.current_peer)
    for name in names:
        if name == engine.username or name.startswith("__"):
            continue
        key = f"dm:{name}"
        found.setdefault(key, ConvItem(key, name, "dm", unread=ui.unread.get(key, 0)))
    return sorted(found.values(), key=lambda item: (item.ts == 0, -item.ts, item.title))


def note_incoming(engine: ChatEngine, ui: UIState, item: Incoming) -> None:
    if item.kind in {"presence", "sys"} or not (item.text or item.error):
        return
    if item.group:
        key = f"group:{item.group}"
    elif item.sender and item.sender != engine.username:
        key = f"dm:{item.sender}"
    else:
        return
    if key == current_key(engine):
        ui.unread[key] = 0
        engine.store.save_unread(ui.unread)
        return
    ui.unread[key] = ui.unread.get(key, 0) + 1
    engine.store.save_unread(ui.unread)


def _line(segments: list[tuple[str, str]], width: int, bg: str, *, divide: bool = False) -> Text:
    text = Text()
    limit = width - 1 if divide else width
    used = 0
    for chunk, style in segments:
        for ch in chunk:
            w = cell_len(ch)
            if used + w > limit:
                break
            text.append(ch, style=style)
            used += w
        else:
            continue
        break
    if used < limit:
        text.append(" " * (limit - used), style=bg)
    if divide:
        text.append("│", style="#243447 on #0e1621")
    return text


def _bubble_lines(body: str, clock: str, mine: bool, inner: int) -> list[str]:
    rows = wrap_cells(body, inner)
    mark = f"{clock} ✓" if mine else clock
    if rows and cell_len(rows[-1] + "  " + mark) <= inner:
        gap = inner - cell_len(rows[-1] + mark)
        rows[-1] = rows[-1] + (" " * max(gap, 2)) + mark
    else:
        rows.append(mark.rjust(inner) if cell_len(mark) <= inner else mark)
    return rows


class Frame:
    def __init__(self, engine: ChatEngine, ui: UIState) -> None:
        self.engine = engine
        self.ui = ui

    def __rich_console__(self, console: Console, options):
        yield self.build(options.max_width)

    def build(self, width: int = 100) -> Layout:
        apply_theme(getattr(self.engine, "ui_theme", "telegram"))
        layout = Layout()
        layout.split_column(
            Layout(name="top", size=2),
            Layout(name="mid"),
        )
        layout["top"].update(TopBar(self.engine))
        if width < 70:
            layout["mid"].split_column(
                Layout(name="main"),
                Layout(name="composer", size=3),
            )
        else:
            side = min(34, max(26, width // 3))
            layout["mid"].split_row(
                Layout(name="side", size=side),
                Layout(name="right"),
            )
            layout["right"].split_column(
                Layout(name="main"),
                Layout(name="composer", size=3),
            )
            layout["side"].update(SideBar(self.engine, self.ui))
        layout["main"].update(ChatPane(self.engine, self.ui))
        layout["composer"].update(Composer(self.ui))
        return layout


class TopBar:
    def __init__(self, engine: ChatEngine) -> None:
        self.engine = engine

    def __rich_console__(self, console: Console, options):
        width = options.max_width
        err = self.engine.last_error
        connection = "在线" if getattr(self.engine, "connected", True) else "已断线"
        right = f" {err} " if err else f" {connection} · {self.engine.username} "
        right_style = f"bold {RED} {BG}" if err else f"{NAME} {BG}"
        left = " " + PROJECT_NAME
        gap = max(1, width - cell_len(left) - cell_len(right))
        yield _line([(left, f"bold {NAME} {BG}"), (" " * gap, BG), (right, right_style)], width, BG)
        hint = " X25519 协商  ·  AES-256-GCM  ·  Ed25519 签名    Tab 切换会话  ·  /help"
        yield _line([(clip(hint, width), f"{MUTED} {BG}")], width, BG)


class SideBar:
    def __init__(self, engine: ChatEngine, ui: UIState) -> None:
        self.engine = engine
        self.ui = ui

    def __rich_console__(self, console: Console, options):
        width = options.max_width
        height = options.height or options.max_height or 20
        items = list_conversations(self.engine, self.ui)
        active = current_key(self.engine)
        def line(segs: list[tuple[str, str]], bg: str = SIDE_BG) -> Text:
            return _line(segs, width, bg, divide=True)

        lines = [
            line([(" 聊天", f"bold white {SIDE_BG}")]),
            line([(f" {self.engine.username}", f"bold {NAME} {SIDE_BG}"), ("  本机", f"{MUTED} {SIDE_BG}")]),
        ]
        if not items:
            lines.append(line([(" 还没有会话", f"{MUTED} {SIDE_BG}")]))
        capacity = max(0, (height - len(lines)) // 2)
        active_index = next(
            (i for i, item in enumerate(items) if item.key == active), 0
        )
        start = max(0, active_index - capacity // 2)
        start = min(start, max(0, len(items) - capacity))
        visible = items[start : start + capacity]
        if start:
            lines.append(line([(" ↑ 更多会话", f"{MUTED} {SIDE_BG}")]))
        for item in visible:
            lines.extend(self._row(item, item.key == active, width))
        if start + capacity < len(items):
            lines.append(line([(" ↓ 更多会话", f"{MUTED} {SIDE_BG}")]))
        blank = line([("", SIDE_BG)])
        if len(lines) < height:
            lines.extend([blank] * (height - len(lines)))
        else:
            lines = lines[:height]
        for line in lines:
            yield line

    def _row(self, item: ConvItem, selected: bool, width: int) -> list[Text]:
        bg = SELECTED if selected else SIDE_BG
        color = "#d2a8ff" if item.kind == "group" else avatar_color(item.title)
        initial = "群" if item.kind == "group" else (item.title[:1].upper() or "?")
        online = item.kind == "dm" and item.title in self.engine.online_users
        dot = "●" if online else " "
        dot_style = f"{ONLINE} {bg}" if online else bg
        clock = short_clock(item.ts)
        name_w = max(4, width - cell_len(initial) - cell_len(clock) - 6)
        name = clip(item.title, name_w)
        badge = ""
        if item.unread:
            badge = f" {'99+' if item.unread > 99 else item.unread} "
        preview_w = max(4, width - 6 - cell_len(badge))
        preview = clip(item.preview or " ", preview_w)
        first = _line(
            [
                (" ", bg),
                (f" {initial} ", f"bold white on {color}"),
                (" ", bg),
                (dot, dot_style),
                (name, f"bold white {bg}" if selected else f"white {bg}"),
                (" ", bg),
                (clock, f"{TIME} {bg}"),
            ],
            width,
            bg,
            divide=True,
        )
        second_segs: list[tuple[str, str]] = [("    " + preview, f"{MUTED} {bg}")]
        if badge:
            second_segs.append((" ", bg))
            second_segs.append((badge, BADGE))
        return [first, _line(second_segs, width, bg, divide=True)]


class ChatPane:
    def __init__(self, engine: ChatEngine, ui: UIState) -> None:
        self.engine = engine
        self.ui = ui

    def __rich_console__(self, console: Console, options):
        width = options.max_width
        height = options.height or options.max_height or 16
        head = self._header(width)
        if self.ui.overlay:
            body = self._overlay(width)
        else:
            body = self._messages(width)
        blank = _line([("", BG)], width, BG)
        room = max(0, height - len(head))
        if len(body) < room:
            body = [blank] * (room - len(body)) + body
        else:
            body = body[-room:]
        for line in (head + body)[:height]:
            yield line

    def _header(self, width: int) -> list[Text]:
        engine = self.engine
        if engine.current_group:
            title = engine.current_group
            members = engine.groups.get(title) or []
            gens = []
            for member in members:
                state = engine.sessions.get(member)
                if member != engine.username and state is not None:
                    gens.append(f"{member}:{state.dh_ratchet_count}")
            sub = f"{len(members)} 人 · 棘轮代数 {', '.join(gens) if gens else '-'}"
        elif engine.current_peer:
            title = engine.current_peer
            online = "在线" if title in engine.online_users else "离线"
            keys = engine.peer_keys.get(title)
            fp = fingerprint_short(keys[0]) if keys else "指纹待获取"
            state = engine.sessions.get(title)
            gen = state.dh_ratchet_count if state is not None else 0
            sub = _peer_subtitle(online, fp, gen, width)
        else:
            title = "选择一个聊天"
            sub = "Tab 切换，或 /chat 名字"
        return [
            _line([("  " + title, f"bold white {BG}")], width, BG),
            _line([("  " + clip(sub, width - 2), f"{MUTED} {BG}")], width, BG),
        ]

    def _overlay(self, width: int) -> list[Text]:
        lines = [_line([("", BG)], width, BG)]
        inner = max(8, min(56, width - 6))
        body = self.ui.overlay or ""
        wrapped: list[str] = []
        for para in body.splitlines() or [""]:
            wrapped.extend(wrap_cells(para, inner) or [""])
        lines.append(_line([("  ┌" + "─" * (inner + 2) + "┐", f"{NAME} {BG}")], width, BG))
        room = 12
        start = min(self.ui.overlay_offset, max(0, len(wrapped) - room))
        for row in wrapped[start : start + room]:
            pad = inner - cell_len(row)
            lines.append(
                _line(
                    [("  │ ", f"{NAME} {BG}"), (row + " " * pad, f"white {SIDE_BG}"), (" │", f"{NAME} {BG}")],
                    width,
                    BG,
                )
            )
        lines.append(_line([("  └" + "─" * (inner + 2) + "┘", f"{NAME} {BG}")], width, BG))
        scroll = " · PgUp/PgDn 滚动" if len(wrapped) > room else ""
        lines.append(
            _line([("  Esc 关闭" + scroll, f"{MUTED} {BG}")], width, BG)
        )
        return lines

    def _messages(self, width: int) -> list[Text]:
        engine = self.engine
        key = current_key(engine)
        lines: list[Text] = []
        if engine.last_error:
            err = engine.last_error
            style = f"bold {RED} {BG}"
            lines.append(_line([("  " + err, style)], width, BG))
        if not key:
            lines.append(_line([("", BG)], width, BG))
            lines.append(_line([("  从左侧选一个对话，或输入 /chat 用户名", f"{MUTED} {BG}")], width, BG))
            lines.append(_line([("  消息用 AES-256-GCM 加密，服务器只能看到 base64", f"{MUTED} {BG}")], width, BG))
            return lines
        history = engine.store.get_history(key, limit=60)
        if not history:
            lines.append(_line([("  还没有消息。写一句，回车发送。", f"{MUTED} {BG}")], width, BG))
            return lines
        prev_day = ""
        inner = max(4, min(42, width - 8))
        for sender, body, ts in history:
            label = day_label(ts) if ts else ""
            if label and label != prev_day:
                prev_day = label
                lines.append(_line([(f" {label} ", f"{MUTED} {SIDE_BG}")], width, BG))
            if sender == "系统":
                hot = any(flag in body for flag in SECURITY)
                style = f"bold {RED} {BG}" if hot else f"{MUTED} {BG}"
                lines.append(_line([(f" {body} ", style)], width, BG))
                continue
            mine = sender == engine.username
            rows = _bubble_lines(body, short_clock(ts), mine, inner)
            if engine.current_group and not mine:
                lines.append(_line([("  " + sender, f"bold {avatar_color(sender)} {BG}")], width, BG))
            bubble = OUT if mine else IN
            fg_color = (
                "#10210f"
                if getattr(self.engine, "ui_theme", "telegram") == "wechat" and mine
                else "white"
            )
            fg = f"{fg_color} {bubble}"
            for row in rows:
                # 时间在行尾，用较淡的颜色画最后的时钟片段
                content = row
                pad = inner - cell_len(content)
                chunk = content + (" " * max(pad, 0))
                if mine:
                    gap = max(0, width - cell_len(chunk) - 4)
                    segs = [(" " * gap, BG), (" " + chunk + " ", fg)]
                else:
                    segs = [("  " + chunk + " ", fg)]
                lines.append(_line(segs, width, BG))
            lines.append(_line([("", BG)], width, BG))
        return lines


class Composer:
    def __init__(self, ui: UIState) -> None:
        self.ui = ui

    def __rich_console__(self, console: Console, options):
        width = options.max_width
        shown, caret_at = _composer_window(self.ui.composer, self.ui.cursor, max(4, width - 6))
        yield _line([("", BG)], width, BG)
        if shown:
            left, right = shown[:caret_at], shown[caret_at:]
            segs: list[tuple[str, str]] = [
                ("  ", BG),
                (" ", COMPOSER),
                (left, f"white {COMPOSER}"),
                ("▏", f"bold {NAME} {COMPOSER}"),
                (right, f"white {COMPOSER}"),
                (" ", COMPOSER),
            ]
        else:
            segs = [("  ", BG), (" 写一条消息… ", f"{MUTED} {COMPOSER}"), ("▏", f"bold {NAME} {COMPOSER}")]
        yield _line(segs, width, BG)
        hint = self.ui.toast or " Enter 发送   /fingerprint 核对身份   验签失败 / 重放拒绝 / GCM 失败 会标红"
        yield _line([(" " + clip(hint, width - 1), f"{MUTED} {BG}")], width, BG)


def _peer_subtitle(online: str, fp: str, gen: int, width: int) -> str:
    """窄窗口优先保留棘轮代数，指纹组数不够就少显示几组。"""
    full = f"{online} · 指纹 {fp} · 棘轮代数 {gen}"
    if cell_len(full) <= width - 2:
        return full
    groups = fp.split()
    for n in range(len(groups), 0, -1):
        short = " ".join(groups[:n]) + (" …" if n < len(groups) else "")
        compact = f"{online} · 指纹 {short} · 棘轮代数 {gen}"
        if cell_len(compact) <= width - 2:
            return compact
    return clip(f"{online} · 棘轮代数 {gen}", width - 2)


def _composer_window(text: str, cursor: int, width: int) -> tuple[str, int]:
    cursor = max(0, min(cursor, len(text)))
    if cell_len(text) <= width:
        return text, cursor
    left = text[:cursor]
    while cell_len(left) > width // 2 and left:
        left = left[1:]
    start = cursor - len(left)
    window = text[start:]
    shown = ""
    for ch in window:
        if cell_len(shown + ch) > width:
            break
        shown += ch
    return shown, len(left)


def edit(ui: UIState, key: str) -> str | None:
    """处理一个按键。返回 submit / next / prev / close / stop。"""
    if key == "ctrl-c" or key == "ctrl-d":
        return "stop"
    if key == "esc":
        ui.overlay = None
        ui.overlay_offset = 0
        return "close"
    if key == "page-up" and ui.overlay:
        ui.overlay_offset = max(0, ui.overlay_offset - 10)
        return None
    if key == "page-down" and ui.overlay:
        ui.overlay_offset += 10
        return None
    if not ui.composer and key in {"up", "ctrl-p"}:
        return "prev"
    if not ui.composer and key in {"down", "ctrl-n", "tab"}:
        return "next"
    if key == "backspace":
        if ui.cursor > 0:
            ui.composer = ui.composer[: ui.cursor - 1] + ui.composer[ui.cursor :]
            ui.cursor -= 1
        return None
    if key == "delete":
        if ui.cursor < len(ui.composer):
            ui.composer = ui.composer[: ui.cursor] + ui.composer[ui.cursor + 1 :]
        return None
    if key == "ctrl-u":
        ui.composer = ""
        ui.cursor = 0
        return None
    if key == "left":
        ui.cursor = max(0, ui.cursor - 1)
        return None
    if key == "right":
        ui.cursor = min(len(ui.composer), ui.cursor + 1)
        return None
    if key == "home":
        ui.cursor = 0
        return None
    if key == "end":
        ui.cursor = len(ui.composer)
        return None
    if key == "enter":
        return "submit"
    if key.startswith("ctrl-") or key in {
        "up",
        "down",
        "esc",
        "ignore",
        "paste-start",
        "paste-end",
        "page-up",
        "page-down",
    }:
        return None
    if len(key) == 1 or (len(key) > 1 and not key.startswith("esc")):
        ui.composer = ui.composer[: ui.cursor] + key + ui.composer[ui.cursor :]
        ui.cursor += len(key)
    return None


async def _activate(engine: ChatEngine, ui: UIState, item: ConvItem) -> None:
    ui.unread[item.key] = 0
    engine.store.save_unread(ui.unread)
    ui.overlay = None
    if item.kind == "group":
        engine.current_group = item.title
        engine.current_peer = None
        return
    engine.current_group = None
    engine.current_peer = item.title
    try:
        await engine.fetch_user(item.title)
    except ProtocolError:
        pass


async def _cycle(engine: ChatEngine, ui: UIState, delta: int) -> None:
    items = list_conversations(engine, ui)
    if not items:
        ui.toast = "还没有会话，用 /chat 名字 开始"
        return
    active = current_key(engine)
    idx = next((i for i, item in enumerate(items) if item.key == active), -1)
    await _activate(engine, ui, items[(idx + delta) % len(items)])


async def _submit(engine: ChatEngine, ui: UIState) -> None:
    original = ui.composer
    line = original if not original.startswith("/") else original.strip()
    ui.composer = ""
    ui.cursor = 0
    if not line.strip():
        if ui.overlay:
            ui.overlay = None
        return
    ui.overlay = None
    try:
        result: CommandResult = await handle_line(engine, line)
    except SystemExit:
        raise
    except (ProtocolError, X3DHError, RatchetError) as exc:
        engine.last_error = str(exc)
        ui.toast = str(exc)
        return
    except Exception as exc:
        engine.last_error = str(exc)
        ui.toast = str(exc)
        return
    if result.overlay:
        ui.overlay = result.overlay
        ui.overlay_offset = 0
    if result.notice:
        ui.toast = result.notice
    key = current_key(engine)
    if key:
        ui.unread[key] = 0


async def _refresh_directory(engine: ChatEngine) -> None:
    try:
        info = await engine.list_users()
    except Exception:
        return
    engine.directory = [u for u in info.get("users") or [] if not str(u).startswith("__")]
    engine.online_users = set(info.get("online") or [])


def render_app(engine: ChatEngine, ui: UIState) -> Frame:
    return Frame(engine, ui)


def _set_dark_chrome() -> None:
    sys.stdout.write("\033]11;#0e1621\a\033]10;#dbe7f3\a")
    sys.stdout.flush()


def _reset_dark_chrome() -> None:
    sys.stdout.write("\033]111\a\033]110\a")
    sys.stdout.flush()


async def telegram_loop(engine: ChatEngine) -> None:
    ui = UIState(toast="已连接", unread=engine.store.load_unread())
    await _refresh_directory(engine)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    old_no_color = os.environ.get("NO_COLOR")
    loop = asyncio.get_running_loop()
    keys: asyncio.Queue[bytes] = asyncio.Queue()
    pending = bytearray()

    def on_readable() -> None:
        try:
            chunk = os.read(fd, 1024)
        except BlockingIOError:
            return
        if chunk:
            keys.put_nowait(chunk)


    inbox_task: asyncio.Task | None = None
    key_task: asyncio.Task | None = None
    tick_task: asyncio.Task | None = None
    reader_added = False
    try:
        tty.setcbreak(fd)
        loop.add_reader(fd, on_readable)
        reader_added = True
        inbox_task = asyncio.create_task(engine.inbox.get())
        key_task = asyncio.create_task(keys.get())
        tick_task = asyncio.create_task(asyncio.sleep(0.25))
        # 云环境会设 NO_COLOR，rich 会因此丢掉背景色，界面就变成白底。
        os.environ.pop("NO_COLOR", None)
        console = Console(force_terminal=True, color_system="truecolor")
        _set_dark_chrome()
        # 不用后台刷新线程。在这个终端里线程刷新会停住，只有改窗口大小才重画。
        with Live(render_app(engine, ui), console=console, screen=True, auto_refresh=False) as live:
            while True:
                live.update(render_app(engine, ui), refresh=True)
                done, _pending = await asyncio.wait(
                    {inbox_task, key_task, tick_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if tick_task in done:
                    tick_task = asyncio.create_task(asyncio.sleep(0.25))
                if inbox_task in done:
                    note_incoming(engine, ui, inbox_task.result())
                    inbox_task = asyncio.create_task(engine.inbox.get())
                if key_task in done:
                    chunk = key_task.result()
                    key_task = asyncio.create_task(keys.get())
                    if not chunk:
                        break
                    pending.extend(chunk)
                    flush = True
                    if _esc_pending(pending):
                        try:
                            extra = await asyncio.wait_for(asyncio.shield(key_task), 0.04)
                        except TimeoutError:
                            flush = True
                        else:
                            key_task = asyncio.create_task(keys.get())
                            if extra:
                                pending.extend(extra)
                            flush = not _esc_pending(pending)
                    for key in drain_keys(pending, flush=flush):
                        if key == "paste-start":
                            ui.paste_mode = True
                            continue
                        if key == "paste-end":
                            ui.paste_mode = False
                            continue
                        if ui.paste_mode and key == "enter":
                            key = " "
                        action = edit(ui, key)
                        if action == "stop":
                            raise SystemExit(0)
                        if action == "next":
                            await _cycle(engine, ui, 1)
                        elif action == "prev":
                            await _cycle(engine, ui, -1)
                        elif action == "submit":
                            await _submit(engine, ui)
    finally:
        for task in (inbox_task, key_task, tick_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(task for task in (inbox_task, key_task, tick_task) if task is not None),
            return_exceptions=True,
        )
        if reader_added:
            loop.remove_reader(fd)
        try:
            _reset_dark_chrome()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            if old_no_color is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = old_no_color
            await engine.close()


async def run_interface(engine: ChatEngine) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        await legacy_command_loop(engine)
        return
    await telegram_loop(engine)

