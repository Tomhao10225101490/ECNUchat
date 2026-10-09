"""现代桌面聊天主窗口。"""

from __future__ import annotations

import time
import uuid
from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer, Qt
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QInputDialog,
)

from src import PROJECT_NAME
from src.gui.engine_worker import EngineWorker
from src.gui.styles import stylesheet
from src.gui.widgets import ComposerEdit, ConversationRow, MessageBubble, MessageRow


class MainWindow(QMainWindow):
    def __init__(self, worker: EngineWorker, initial: dict[str, Any]) -> None:
        super().__init__()
        self.worker = worker
        self.username = str(initial["username"])
        self.current_conv: str | None = None
        self.snapshot_data = initial
        self.unread: dict[str, int] = dict(initial.get("unread", {}))
        self.bubbles: dict[str, MessageBubble] = {}
        self.theme = str(initial.get("theme", "telegram"))
        self._reduce_motion = bool(initial.get("reduce_motion", False))
        self._theme_animation: QPropertyAnimation | None = None
        self._toast_animation: QPropertyAnimation | None = None
        self.setWindowTitle(f"{PROJECT_NAME} — {self.username}")
        self.resize(1180, 760)
        self.setMinimumSize(820, 560)
        self._build()
        self._connect_worker()
        self.apply_theme(self.theme, persist=False, animate=False)
        self.update_snapshot(initial)
        saved_conv = str(initial.get("current_conv") or "")
        if saved_conv:
            QTimer.singleShot(0, lambda: self.open_conversation(saved_conv))

    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.connection_banner = QLabel("端到端加密连接已建立")
        self.connection_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connection_banner.setStyleSheet(
            "background:#173e31;color:#7ee2a8;padding:5px;font-size:12px"
        )
        outer.addWidget(self.connection_banner)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        outer.addWidget(splitter, 1)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(275)
        sidebar.setMaximumWidth(380)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(12, 14, 12, 12)
        brand_row = QHBoxLayout()
        brand = QLabel("安全聊天")
        brand.setObjectName("brand")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        self.theme_button = QPushButton("微信绿")
        self.theme_button.setObjectName("icon")
        self.theme_button.setToolTip("切换 Telegram / WeChat 主题")
        self.theme_button.clicked.connect(self.toggle_theme)
        brand_row.addWidget(self.theme_button)
        settings = QPushButton("⚙")
        settings.setObjectName("icon")
        settings.setToolTip("外观设置")
        menu = QMenu(settings)
        telegram_action = menu.addAction("Telegram 蓝")
        telegram_action.triggered.connect(
            lambda: self.apply_theme("telegram")
        )
        wechat_action = menu.addAction("WeChat 绿")
        wechat_action.triggered.connect(lambda: self.apply_theme("wechat"))
        menu.addSeparator()
        self.motion_action = menu.addAction("减少动态效果")
        self.motion_action.setCheckable(True)
        self.motion_action.setChecked(self._reduce_motion)
        self.motion_action.toggled.connect(self.set_reduce_motion)
        settings.setMenu(menu)
        brand_row.addWidget(settings)
        side.addLayout(brand_row)
        me = QLabel(f"当前用户  {self.username}")
        me.setObjectName("muted")
        side.addWidget(me)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索本地消息…")
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(260)
        self.search_timer.timeout.connect(self.perform_search)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        side.addWidget(self.search)

        actions = QHBoxLayout()
        new_chat = QPushButton("新建聊天")
        new_chat.clicked.connect(self.new_chat)
        new_group = QPushButton("创建群聊")
        new_group.clicked.connect(self.new_group)
        actions.addWidget(new_chat)
        actions.addWidget(new_group)
        side.addLayout(actions)

        self.conversations = QListWidget()
        self.conversations.itemActivated.connect(self.activate_item)
        self.conversations.itemClicked.connect(self.activate_item)
        side.addWidget(self.conversations, 1)
        splitter.addWidget(sidebar)

        chat = QWidget()
        chat_layout = QVBoxLayout(chat)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)
        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 12, 16, 12)
        titles = QVBoxLayout()
        self.chat_title = QLabel("选择一个会话")
        self.chat_title.setStyleSheet("font-size:17px;font-weight:700")
        self.chat_subtitle = QLabel("消息只在本机解密")
        self.chat_subtitle.setObjectName("muted")
        titles.addWidget(self.chat_title)
        titles.addWidget(self.chat_subtitle)
        header_layout.addLayout(titles)
        header_layout.addStretch()
        self.info_button = QPushButton("身份指纹")
        self.info_button.setEnabled(False)
        self.info_button.clicked.connect(self.show_fingerprint)
        header_layout.addWidget(self.info_button)
        chat_layout.addWidget(header)

        self.message_scroll = QScrollArea()
        self.message_scroll.setWidgetResizable(True)
        self.message_host = QWidget()
        self.messages = QVBoxLayout(self.message_host)
        self.messages.setContentsMargins(14, 18, 14, 18)
        self.messages.setSpacing(1)
        self.messages.addStretch(1)
        self.message_scroll.setWidget(self.message_host)
        chat_layout.addWidget(self.message_scroll, 1)

        composer_frame = QFrame()
        composer_frame.setObjectName("composer")
        composer_layout = QHBoxLayout(composer_frame)
        composer_layout.setContentsMargins(16, 11, 16, 11)
        self.composer = ComposerEdit()
        self.composer.setPlaceholderText("输入消息；Enter 发送，Shift+Enter 换行")
        self.composer.setMaximumHeight(100)
        self.composer.sendRequested.connect(self.send_current)
        composer_layout.addWidget(self.composer, 1)
        self.send_button = QPushButton("发送")
        self.send_button.setObjectName("primary")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_current)
        composer_layout.addWidget(self.send_button)
        chat_layout.addWidget(composer_frame)
        splitter.addWidget(chat)
        splitter.setSizes([320, 860])

        self.toast = QLabel("", self)
        self.toast.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.toast.setStyleSheet(
            "background:#253444;border:1px solid #43576b;border-radius:12px;"
            "padding:9px 16px"
        )
        self.toast.hide()
        self.toast_timer = QTimer(self)
        self.toast_timer.setSingleShot(True)
        self.toast_timer.timeout.connect(self.toast.hide)

        search_shortcut = QAction(self)
        search_shortcut.setShortcut(QKeySequence.StandardKey.Find)
        search_shortcut.triggered.connect(self.search.setFocus)
        self.addAction(search_shortcut)

    def _connect_worker(self) -> None:
        self.worker.snapshot.connect(self.update_snapshot)
        self.worker.incoming.connect(self.on_incoming)
        self.worker.historyReady.connect(self.show_history)
        self.worker.searchReady.connect(self.show_search_results)
        self.worker.messageState.connect(self.on_message_state)
        self.worker.actionResult.connect(self.on_action_result)
        self.worker.connectionChanged.connect(self.on_connection)
        self.worker.fatalError.connect(self.on_fatal)

    def apply_theme(
        self, theme: str, *, persist: bool = True, animate: bool = True
    ) -> None:
        self.theme = theme
        if persist:
            self.worker.submit("set_ui", theme=theme)
        if not animate or self._reduce_motion:
            self._apply_theme_style(theme)
            return
        effect = QGraphicsOpacityEffect(self.centralWidget())
        self.centralWidget().setGraphicsEffect(effect)
        fade = QPropertyAnimation(effect, b"opacity", self)
        fade.setDuration(110)
        fade.setStartValue(1.0)
        fade.setEndValue(0.35)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)

        def finish() -> None:
            self._apply_theme_style(theme)
            fade_in = QPropertyAnimation(effect, b"opacity", self)
            fade_in.setDuration(150)
            fade_in.setStartValue(0.35)
            fade_in.setEndValue(1.0)
            fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
            fade_in.finished.connect(
                lambda: self.centralWidget().setGraphicsEffect(None)
            )
            self._theme_animation = fade_in
            fade_in.start()

        fade.finished.connect(finish)
        self._theme_animation = fade
        fade.start()

    def _apply_theme_style(self, theme: str) -> None:
        self.setStyleSheet(stylesheet(theme))
        self.theme_button.setText("Telegram 蓝" if theme == "wechat" else "微信绿")

    def toggle_theme(self) -> None:
        self.apply_theme("wechat" if self.theme == "telegram" else "telegram")
        self.show_toast("已切换界面主题")

    def set_reduce_motion(self, enabled: bool) -> None:
        self._reduce_motion = enabled
        self.worker.submit("set_ui", reduce_motion="1" if enabled else "0")
        self.show_toast("已减少动态效果" if enabled else "已启用动态效果")

    def update_snapshot(self, data: dict[str, Any]) -> None:
        self.snapshot_data = data
        if not self.search.text().strip():
            self.rebuild_conversations()
        if self.current_conv:
            self.update_header()

    def rebuild_conversations(self) -> None:
        current = self.current_conv
        recent = {row["conv"]: row for row in self.snapshot_data.get("recent", [])}
        keys = set(recent)
        keys.update(f"group:{name}" for name in self.snapshot_data.get("groups", {}))
        keys.update(f"dm:{name}" for name in self.snapshot_data.get("sessions", {}))
        if current:
            keys.add(current)
        ordered = sorted(
            keys,
            key=lambda key: (
                -(recent.get(key, {}).get("ts", 0)),
                key,
            ),
        )
        self.conversations.clear()
        online = set(self.snapshot_data.get("online", []))
        for conv in ordered:
            row = recent.get(conv, {})
            title = self.conv_title(conv)
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, conv)
            widget = ConversationRow(
                title=title,
                preview=str(row.get("body", "")),
                timestamp=float(row.get("ts", 0)),
                online=conv.startswith("dm:") and conv[3:] in online,
                unread=self.unread.get(conv, 0),
            )
            item.setSizeHint(widget.sizeHint())
            self.conversations.addItem(item)
            self.conversations.setItemWidget(item, widget)
            if conv == current:
                self.conversations.setCurrentItem(item)

    @staticmethod
    def conv_title(conv: str) -> str:
        return ("# " + conv[6:]) if conv.startswith("group:") else conv[3:]

    def activate_item(self, item: QListWidgetItem) -> None:
        conv = str(item.data(Qt.ItemDataRole.UserRole))
        if conv.startswith("search:"):
            conv = conv.split(":", 2)[2]
            self.search.clear()
        self.open_conversation(conv)

    def open_conversation(self, conv: str) -> None:
        self.current_conv = conv
        self.unread[conv] = 0
        self.worker.submit("mark_read", unread=self.unread)
        self.worker.submit("set_ui", current_conv=conv)
        self.send_button.setEnabled(True)
        self.info_button.setEnabled(conv.startswith("dm:"))
        self.update_header()
        self.worker.submit("history", conv=conv)
        self.rebuild_conversations()

    def update_header(self) -> None:
        if not self.current_conv:
            return
        conv = self.current_conv
        self.chat_title.setText(self.conv_title(conv))
        if conv.startswith("dm:"):
            peer = conv[3:]
            online = peer in set(self.snapshot_data.get("online", []))
            generation = self.snapshot_data.get("sessions", {}).get(peer, 0)
            short_fp = self.snapshot_data.get("fingerprints", {}).get(peer, "")
            fp_text = f" · 指纹 {short_fp}" if short_fp else ""
            self.chat_subtitle.setText(
                f"{'在线' if online else '离线'} · 双棘轮代数 {generation}{fp_text}"
            )
        else:
            members = self.snapshot_data.get("groups", {}).get(conv[6:], [])
            self.chat_subtitle.setText(f"{len(members)} 位成员 · 逐成员双棘轮加密")

    def clear_messages(self) -> None:
        while self.messages.count() > 1:
            item = self.messages.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.bubbles.clear()

    def show_history(self, conv: str, rows: list[dict[str, Any]]) -> None:
        if conv != self.current_conv:
            return
        self.clear_messages()
        for row in rows:
            sender = str(row["sender"])
            kind = "sys" if sender == "系统" else "chat"
            self.append_message(
                sender,
                str(row["body"]),
                float(row["ts"]),
                mine=sender == self.username,
                kind=kind,
                animate=False,
            )
        for pending in self.snapshot_data.get("pending", []):
            if pending.get("conv") != conv:
                continue
            local_id = str(pending["local_id"])
            if local_id in self.bubbles:
                continue
            self.append_message(
                self.username,
                str(pending["body"]),
                float(pending["ts"]),
                mine=True,
                state=str(pending["state"]),
                local_id=local_id,
                animate=False,
            )
        self.scroll_to_bottom()

    def append_message(
        self,
        sender: str,
        body: str,
        timestamp: float,
        mine: bool,
        state: str = "accepted",
        kind: str = "chat",
        local_id: str | None = None,
        animate: bool = True,
    ) -> MessageBubble:
        bubble = MessageBubble(
            sender, body, timestamp, mine, state, kind, animate and not self._reduce_motion
        )
        row = MessageRow(
            bubble,
            mine,
            centered=kind in {"sys", "group_meta", "presence", "error"},
        )
        self.messages.insertWidget(self.messages.count() - 1, row)
        if local_id:
            self.bubbles[local_id] = bubble
        QTimer.singleShot(0, self.scroll_to_bottom)
        return bubble

    def send_current(self) -> None:
        text = self.composer.toPlainText()
        if not self.current_conv or not text.strip():
            return
        if len(text.encode("utf-8")) > 48 * 1024:
            self.show_toast("消息过长；加密信封必须小于 64KB", error=True)
            return
        self.composer.clear()
        local_id = uuid.uuid4().hex
        self.append_message(
            self.username,
            text,
            time.time(),
            mine=True,
            state="sending",
            local_id=local_id,
        )
        self.worker.submit(
            "send", local_id=local_id, conv=self.current_conv, text=text
        )

    def on_message_state(self, local_id: str, state: str, error: str) -> None:
        bubble = self.bubbles.get(local_id)
        if bubble:
            bubble.set_state(state)
        if state == "failed":
            self.show_toast(f"发送失败：{error}", error=True)

    def on_incoming(self, item: dict[str, Any]) -> None:
        group = item.get("group")
        sender = str(item.get("sender", ""))
        conv = f"group:{group}" if group else (f"dm:{sender}" if sender and sender != "系统" else "")
        if item.get("kind") in {"presence"}:
            return
        if conv and conv == self.current_conv:
            self.append_message(
                sender,
                str(item.get("text") or item.get("error") or ""),
                time.time(),
                mine=False,
                kind="error" if item.get("error") else str(item.get("kind", "chat")),
            )
        elif conv:
            self.unread[conv] = self.unread.get(conv, 0) + 1
            self.worker.submit("mark_read", unread=self.unread)
            self.rebuild_conversations()
        if item.get("error"):
            self.show_toast(str(item["error"]), error=True)

    def perform_search(self) -> None:
        query = self.search.text().strip()
        if not query:
            self.rebuild_conversations()
            return
        self.worker.submit("search", query=query)

    def show_search_results(self, rows: list[dict[str, Any]]) -> None:
        if not self.search.text().strip():
            return
        self.conversations.clear()
        for row in rows:
            conv = str(row["conv"])
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, f"search:{row['id']}:{conv}")
            widget = ConversationRow(
                self.conv_title(conv),
                str(row["body"]),
                float(row["ts"]),
            )
            item.setSizeHint(widget.sizeHint())
            self.conversations.addItem(item)
            self.conversations.setItemWidget(item, widget)

    def new_chat(self) -> None:
        name, ok = QInputDialog.getText(self, "新建聊天", "对方用户名")
        if ok and name.strip():
            self.worker.submit("open_chat", username=name.strip())

    def new_group(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("创建加密群聊")
        form = QFormLayout(dialog)
        name = QLineEdit()
        members = QLineEdit()
        members.setPlaceholderText("bob, carol")
        form.addRow("群名", name)
        form.addRow("成员", members)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            member_list = [
                value.strip() for value in members.text().split(",") if value.strip()
            ]
            self.worker.submit(
                "create_group", name=name.text().strip(), members=member_list
            )

    def show_fingerprint(self) -> None:
        if self.current_conv and self.current_conv.startswith("dm:"):
            self.worker.submit("fingerprint", username=self.current_conv[3:])

    def on_action_result(self, action: str, ok: bool, data: object) -> None:
        if not ok:
            self.show_toast(str(data), error=True)
            return
        if action == "open_chat":
            conv = f"dm:{data}"
            self.open_conversation(conv)
        elif action == "create_group":
            self.open_conversation(f"group:{data}")
        elif action == "fingerprint" and isinstance(data, dict):
            groups = str(data["fingerprint"]).split()
            formatted = "\n".join(
                "  ".join(groups[index : index + 4])
                for index in range(0, len(groups), 4)
            )
            QMessageBox.information(
                self,
                f"{data['username']} 的身份指纹",
                "请通过线下渠道核对以下 16 组：\n\n" + formatted,
            )

    def on_connection(self, connected: bool, text: str) -> None:
        color = "#173e31;color:#7ee2a8" if connected else "#4a3020;color:#ffc47a"
        self.connection_banner.setStyleSheet(
            f"background:{color};padding:5px;font-size:12px"
        )
        self.connection_banner.setText(text)
        self.send_button.setEnabled(bool(connected and self.current_conv))

    def on_fatal(self, text: str) -> None:
        self.show_toast(text, error=True)

    def show_toast(self, text: str, error: bool = False) -> None:
        self.toast.setText(text)
        self.toast.setStyleSheet(
            (
                "background:#4a2228;border:1px solid #ff6b6b;"
                if error
                else "background:#253444;border:1px solid #43576b;"
            )
            + "border-radius:12px;padding:9px 16px"
        )
        self.toast.adjustSize()
        self.toast.move(
            max(20, self.width() - self.toast.width() - 28),
            max(20, self.height() - self.toast.height() - 92),
        )
        self.toast.show()
        self.toast.raise_()
        if not self._reduce_motion:
            effect = QGraphicsOpacityEffect(self.toast)
            self.toast.setGraphicsEffect(effect)
            animation = QPropertyAnimation(effect, b"opacity", self)
            animation.setDuration(160)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._toast_animation = animation
            animation.start()
        self.toast_timer.start(3500)

    def scroll_to_bottom(self) -> None:
        bar = self.message_scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(
                max(20, self.width() - self.toast.width() - 28),
                max(20, self.height() - self.toast.height() - 92),
            )

    def closeEvent(self, event: QCloseEvent) -> None:
        self.worker.stop_async()
        self.worker.wait(3000)
        event.accept()

