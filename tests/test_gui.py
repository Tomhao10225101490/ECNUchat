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
    fileProgress = Signal(str, int, int)
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


def test_composer_enter_shift_and_ime() -> None:
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QInputMethodEvent, QKeyEvent

    from src.gui.widgets import ComposerEdit

    qt = app()
    edit = ComposerEdit()
    edit.resize(320, 40)
    sent: list[int] = []
    edit.sendRequested.connect(lambda: sent.append(1))
    edit.setPlainText("你好")
    edit.keyPressEvent(
        QKeyEvent(
            QEvent.Type.KeyPress,
            Qt.Key.Key_Return,
            Qt.KeyboardModifier.ShiftModifier,
        )
    )
    assert sent == []
    assert "\n" in edit.toPlainText()

    edit.keyPressEvent(
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    )
    assert sent == [1]

    composing = ComposerEdit()
    held: list[int] = []
    composing.sendRequested.connect(lambda: held.append(1))
    composing.inputMethodEvent(QInputMethodEvent("nihao", []))
    assert composing.preedit_text() == "nihao"
    composing.keyPressEvent(
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    )
    assert held == []

    commit = QInputMethodEvent()
    commit.setCommitString("你")
    composing.inputMethodEvent(commit)
    composing.keyPressEvent(
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    )
    assert held == []
    composing._swallow_until = 0
    composing.setPlainText("你")
    composing.keyPressEvent(
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    )
    assert held == [1]
    cursor = composing.inputMethodQuery(Qt.InputMethodQuery.ImCursorRectangle)
    assert cursor.isValid()
    edit.hide()
    composing.hide()
    qt.processEvents()


def test_composer_grows_then_caps_at_six_lines() -> None:
    from src.gui.widgets import ComposerEdit

    qt = app()
    edit = ComposerEdit()
    edit.resize(360, 40)
    edit.show()
    qt.processEvents()
    edit.setPlainText("甲")
    qt.processEvents()
    one = edit.height()
    edit.setPlainText("\n".join("甲" for _ in range(3)))
    qt.processEvents()
    three = edit.height()
    edit.setPlainText("\n".join("甲" for _ in range(6)))
    qt.processEvents()
    six = edit.height()
    edit.setPlainText("\n".join("甲" for _ in range(12)))
    qt.processEvents()
    twelve = edit.height()
    assert three > one
    assert six >= three
    assert abs(twelve - six) <= 2
    edit.hide()


def test_message_groups_only_show_avatar_on_the_first() -> None:
    qt = app()
    worker = FakeWorker()
    window = MainWindow(worker, snapshot())
    window.open_conversation("dm:bob")
    now = time.time()
    window.show_history(
        "dm:bob",
        [
            {"sender": "bob", "body": "一", "ts": now},
            {"sender": "bob", "body": "二", "ts": now + 5},
            {"sender": "alice", "body": "三", "ts": now + 10},
            {"sender": "alice", "body": "四", "ts": now + 20},
        ],
    )
    flags = [item for item in window.message_group_flags() if item[3] == "message"]
    assert flags[0][0] is True
    assert flags[1][0] is False
    assert flags[1][2] is True
    assert flags[2][0] is False  # 自己的消息在单聊里不占头像
    assert flags[3][0] is False
    assert flags[2][1] is False and flags[3][1] is False
    window.show_history(
        "group:三人组",
        [],
    )
    window.current_conv = "group:三人组"
    window.show_history(
        "group:三人组",
        [
            {"sender": "bob", "body": "群一", "ts": now},
            {"sender": "bob", "body": "群二", "ts": now + 3},
        ],
    )
    group_flags = [item for item in window.message_group_flags() if item[3] == "message"]
    assert group_flags[0][0] is True and group_flags[0][1] is True
    assert group_flags[1][0] is False and group_flags[1][1] is False
    window.hide()
    qt.processEvents()


def test_stage_send_and_paint_file_bubble(tmp_path) -> None:
    from PySide6.QtGui import QImage

    qt = app()
    worker = FakeWorker()
    window = MainWindow(worker, snapshot())
    window.show()
    window.open_conversation("dm:bob")
    note = tmp_path / "课堂笔记.txt"
    note.write_text("只在本机看到的字", encoding="utf-8")
    window._stage_path(str(note))
    qt.processEvents()
    assert window.file_preview.isVisible()
    assert "课堂笔记.txt" in window.file_preview.title.text()
    window.file_preview.cleared.emit()
    qt.processEvents()
    assert window._staged is None
    assert not window.file_preview.isVisible()

    window._stage_path(str(note))
    window.composer.setPlainText("看看附件")
    window.send_current()
    action, payload = worker.commands[-1]
    assert action == "send_file"
    assert payload["path"] == str(note)
    assert payload["caption"] == "看看附件"
    assert payload["local_id"] in window.bubbles
    window._retry(payload["local_id"])
    assert worker.commands[-1][0] == "send_file"
    assert worker.commands[-1][1]["local_id"] == payload["local_id"]

    image_path = tmp_path / "dot.png"
    image = QImage(8, 8, QImage.Format.Format_RGB32)
    image.fill(0xFF2266AA)
    assert image.save(str(image_path))
    window.show_history(
        "dm:bob",
        [
            {
                "sender": "alice",
                "body": "看看",
                "ts": time.time(),
                "attachment": {
                    "name": "dot.png",
                    "mime": "image/png",
                    "size": 12,
                    "path": str(image_path),
                    "media": "image",
                    "caption": "看看",
                    "sha256": "ab",
                },
            },
            {
                "sender": "bob",
                "body": "",
                "ts": time.time(),
                "attachment": {
                    "name": "clip.mp4",
                    "mime": "video/mp4",
                    "size": 4096,
                    "path": str(tmp_path / "missing.mp4"),
                    "media": "video",
                    "caption": "",
                    "sha256": "cd",
                },
            },
            {
                "sender": "bob",
                "body": "",
                "ts": time.time(),
                "attachment": {
                    "name": "spec.pdf",
                    "mime": "application/pdf",
                    "size": 99,
                    "path": str(note),
                    "media": "file",
                    "caption": "",
                    "sha256": "ef",
                },
            },
        ],
    )
    qt.processEvents()
    painted = [item for item in window.messages.items() if item.attachment]
    assert [item.attachment["media"] for item in painted] == ["image", "video", "file"]
    window.messages.viewport().repaint()
    qt.processEvents()
    window.hide()

