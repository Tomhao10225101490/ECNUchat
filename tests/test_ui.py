"""界面：按键解析，以及 Telegram 式双栏里能看见项目名、气泡和安全提示。"""

import os
import pty
import re
import select
import subprocess
import sys
import time
from types import SimpleNamespace

from rich.console import Console

from src import PROJECT_NAME
from src.ui import UIState, drain_keys, edit, list_conversations, render_app


class MemStore:
    def __init__(self) -> None:
        now = time.time()
        self.rows = {
            "dm:bob": [
                ("bob", "你好鲍勃", now),
                ("alice", "收到", now),
                ("系统", "GCM 失败", now),
            ]
        }

    def get_history(self, conv: str, limit: int = 80):
        return self.rows.get(conv, [])[-limit:]

    def recent_messages(self):
        out = []
        for conv, rows in self.rows.items():
            sender, body, ts = rows[-1]
            out.append((conv, sender, body, ts))
        return out


def _engine():
    return SimpleNamespace(
        username="alice",
        current_peer="bob",
        current_group=None,
        groups={"三人组": ["alice", "bob", "carol"]},
        sessions={"bob": SimpleNamespace(dh_ratchet_count=2)},
        peer_keys={"bob": (bytes(range(32)), bytes(range(32)))},
        online_users={"bob"},
        directory=["alice", "bob", "carol"],
        last_error="重放拒绝",
        store=MemStore(),
    )


def test_drain_keys_utf8_and_arrows() -> None:
    buf = bytearray("你好".encode())
    assert drain_keys(buf) == ["你", "好"]
    assert buf == bytearray()
    buf = bytearray(b"\x1b[A\x1b")
    assert drain_keys(buf) == ["up"]
    assert bytes(buf) == b"\x1b"
    assert drain_keys(buf) == []
    assert drain_keys(buf, flush=True) == ["esc"]
    buf = bytearray(b"\x1b[")
    assert drain_keys(buf, flush=True) == ["esc"]
    assert buf == bytearray()
    buf = bytearray(b"\x7f\r")
    assert drain_keys(buf) == ["backspace", "enter"]
    buf = bytearray(b"\x1b[3~\x1b[H\x1b[F\x1b[5~\x1b[6~")
    assert drain_keys(buf) == ["delete", "home", "end", "page-up", "page-down"]
    buf = bytearray(b"\x1b[200~hello\x1b[201~")
    assert drain_keys(buf) == [
        "paste-start",
        "h",
        "e",
        "l",
        "l",
        "o",
        "paste-end",
    ]


def test_edit_composer_and_chat_switch() -> None:
    ui = UIState()
    assert edit(ui, "你") is None
    assert ui.composer == "你"
    assert edit(ui, "backspace") is None
    assert ui.composer == ""
    assert edit(ui, "tab") == "next"
    ui.composer = "/fingerprint bob"
    ui.cursor = len(ui.composer)
    assert edit(ui, "tab") is None
    assert edit(ui, "enter") == "submit"


def test_sidebar_orders_recent_chat_first() -> None:
    engine = _engine()
    ui = UIState(unread={"dm:carol": 2})
    items = list_conversations(engine, ui)
    assert items[0].title == "bob"
    titles = [item.title for item in items]
    assert "carol" not in titles  # 用户目录不应挤进真实会话列表
    assert "三人组" in titles
    assert "alice" not in titles


def test_render_shows_project_bubbles_and_security() -> None:
    engine = _engine()
    ui = UIState(toast="已连接")
    console = Console(width=110, height=36, force_terminal=True, color_system="truecolor", record=True)
    console.print(render_app(engine, ui))
    text = console.export_text()
    assert PROJECT_NAME in text
    assert "你好鲍勃" in text
    assert "收到" in text
    assert "重放拒绝" in text
    assert "GCM 失败" in text
    assert "棘轮代数" in text
    assert "指纹" in text
    assert "bob" in text


def test_narrow_layout_hides_sidebar_but_keeps_chat() -> None:
    engine = _engine()
    engine.ui_theme = "wechat"
    engine.connected = True
    console = Console(
        width=52, height=24, force_terminal=True, color_system="truecolor", record=True
    )
    console.print(render_app(engine, UIState()))
    text = console.export_text()
    assert PROJECT_NAME in text
    assert "你好鲍勃" in text
    assert "棘轮代数" in text


def test_tty_boots_project_name(tmp_path) -> None:
    port = 8791
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "src.server",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--db",
            str(tmp_path / "server.db"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    master, slave = pty.openpty()
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLUMNS"] = "100"
    env["LINES"] = "30"
    client = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "src.client",
            "--user",
            "alice",
            "--password",
            "password123",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--db",
            str(tmp_path / "alice.db"),
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
    )
    os.close(slave)
    buf = b""
    try:
        deadline = time.time() + 8
        while time.time() < deadline and PROJECT_NAME.encode() not in buf:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    buf += os.read(master, 8192)
                except OSError:
                    break
            if client.poll() is not None:
                break
        plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", buf)
        assert PROJECT_NAME.encode() in plain, plain[-400:]
    finally:
        client.terminate()
        server.terminate()
        client.wait(timeout=3)
        server.wait(timeout=3)
        os.close(master)
