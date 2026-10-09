"""PySide6 桌面界面的离屏交互回归测试。"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from src import PROJECT_NAME
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow


class FakeWorker(QObject):
    snapshot = Signal(object)
    incoming = Signal(object)
    historyReady = Signal(str, object)
    searchReady = Signal(object)
    messageState = Signal(str, str, str)
    actionResult = Signal(str, bool, object)
    connectionChanged = Signal(bool, str)
    fatalError = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.commands: list[tuple[str, dict]] = []

    def submit(self, action: str, **payload) -> None:
        self.commands.append((action, payload))

    def stop_async(self) -> None:
        pass

    def wait(self, _timeout: int) -> bool:
        return True


def app() -> QApplication:
    return QApplication.instance() or QApplication([])


def snapshot() -> dict:
    return {
        "username": "alice",
        "connected": True,
        "online": ["alice", "bob"],
        "groups": {"三人组": ["alice", "bob", "carol"]},
        "sessions": {"bob": 2},
        "fingerprints": {"bob": "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111"},
        "recent": [
            {
                "conv": "dm:bob",
                "sender": "bob",
                "body": "你好爱丽丝",
                "ts": time.time(),
            }
        ],
        "unread": {"dm:bob": 2},
        "pending": [
            {
                "local_id": "failed-1",
                "conv": "dm:bob",
                "body": "待重试",
                "state": "failed",
                "ts": time.time(),
            }
        ],
        "theme": "telegram",
        "reduce_motion": True,
        "current_conv": "",
    }


def test_login_and_modern_chat_window() -> None:
    qt = app()
    login = LoginDialog()
    assert PROJECT_NAME in login.windowTitle()
    assert login.username.text() == "alice"

    worker = FakeWorker()
    window = MainWindow(worker, snapshot())
    window.show()
    qt.processEvents()
    assert window.conversations.count() == 2

    window.open_conversation("dm:bob")
    window.show_history(
        "dm:bob",
        [{"sender": "bob", "body": "你好爱丽丝", "ts": time.time()}],
    )
    qt.processEvents()
    assert "双棘轮代数 2" in window.chat_subtitle.text()
    assert "AAAA BBBB" in window.chat_subtitle.text()
    assert "failed-1" in window.bubbles

    window.composer.setPlainText("快速乐观发送")
    window.send_current()
    action, payload = worker.commands[-1]
    assert action == "send"
    assert payload["text"] == "快速乐观发送"
    assert payload["local_id"] in window.bubbles
    assert window.bubbles[payload["local_id"]].status_label.text() == "发送中"
    window.on_message_state(payload["local_id"], "accepted", "")
    assert window.bubbles[payload["local_id"]].status_label.text() == "已发送"

    window.apply_theme("wechat", animate=False)
    assert window.theme == "wechat"
    window.search.setText("爱丽丝")
    window.show_search_results(
        [
            {
                "id": 1,
                "conv": "dm:bob",
                "sender": "bob",
                "body": "你好爱丽丝",
                "ts": time.time(),
            }
        ]
    )
    assert window.conversations.count() == 1
    window.hide()
    login.close()

