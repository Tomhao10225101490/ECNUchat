"""可复用桌面控件。"""

from __future__ import annotations

import time

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class ComposerEdit(QTextEdit):
    sendRequested = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if (
            event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and not event.modifiers() & Qt.KeyboardModifier.ShiftModifier
        ):
            self.sendRequested.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class ConversationRow(QWidget):
    def __init__(
        self,
        title: str,
        preview: str = "",
        timestamp: float = 0,
        online: bool = False,
        unread: int = 0,
    ) -> None:
        super().__init__()
        root = QHBoxLayout(self)
        root.setContentsMargins(6, 4, 6, 4)
        avatar = QLabel(("群" if title.startswith("#") else title[:1]).upper())
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar.setFixedSize(42, 42)
        avatar.setStyleSheet(
            "background:#657a92;border-radius:21px;font-weight:700;color:white"
        )
        root.addWidget(avatar)

        text = QVBoxLayout()
        top = QHBoxLayout()
        name = QLabel(title)
        name.setStyleSheet("font-weight:700")
        top.addWidget(name)
        top.addStretch()
        stamp = QLabel(time.strftime("%H:%M", time.localtime(timestamp)) if timestamp else "")
        stamp.setObjectName("timestamp")
        top.addWidget(stamp)
        text.addLayout(top)
        sub = QHBoxLayout()
        preview_label = QLabel(preview)
        preview_label.setObjectName("muted")
        preview_label.setMaximumWidth(190)
        sub.addWidget(preview_label, 1)
        if online:
            dot = QLabel("●")
            dot.setObjectName("online")
            dot.setToolTip("在线")
            sub.addWidget(dot)
        if unread:
            badge = QLabel("99+" if unread > 99 else str(unread))
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setStyleSheet(
                "background:#3390ec;color:white;border-radius:9px;"
                "font-size:11px;font-weight:700;min-width:18px"
            )
            sub.addWidget(badge)
        text.addLayout(sub)
        root.addLayout(text, 1)


class MessageBubble(QFrame):
    def __init__(
        self,
        sender: str,
        body: str,
        timestamp: float,
        mine: bool,
        state: str = "accepted",
        kind: str = "chat",
        animate: bool = True,
    ) -> None:
        security = kind == "error"
        system = kind in {"sys", "group_meta", "presence"}
        super().__init__()
        self.setObjectName("security" if security else ("system" if system else ("bubble_out" if mine else "bubble_in")))
        self.setMaximumWidth(560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 8, 13, 7)
        layout.setSpacing(3)
        if sender and not mine and not system:
            sender_label = QLabel(sender)
            sender_label.setStyleSheet("font-size:12px;font-weight:700;color:#6ab3f3")
            layout.addWidget(sender_label)
        body_label = QLabel(body)
        body_label.setObjectName("body")
        body_label.setWordWrap(True)
        body_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(body_label)
        footer = QHBoxLayout()
        footer.addStretch()
        self.status_label = QLabel()
        self.status_label.setObjectName("status")
        footer.addWidget(self.status_label)
        clock = QLabel(time.strftime("%H:%M", time.localtime(timestamp or time.time())))
        clock.setObjectName("timestamp")
        footer.addWidget(clock)
        layout.addLayout(footer)
        self.set_state(state)
        self._animation: QPropertyAnimation | None = None
        if animate:
            effect = QGraphicsOpacityEffect(self)
            self.setGraphicsEffect(effect)
            animation = QPropertyAnimation(effect, b"opacity", self)
            animation.setDuration(180)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.start()
            self._animation = animation

    def set_state(self, state: str) -> None:
        labels = {
            "sending": "发送中",
            "accepted": "已发送",
            "failed": "发送失败",
        }
        self.status_label.setText(labels.get(state, ""))
        if state == "failed":
            self.status_label.setStyleSheet("color:#ff6b6b")
        else:
            self.status_label.setStyleSheet("")


class MessageRow(QWidget):
    def __init__(self, bubble: MessageBubble, mine: bool, centered: bool = False) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 3, 18, 3)
        if centered:
            layout.addStretch()
            layout.addWidget(bubble)
            layout.addStretch()
        elif mine:
            layout.addStretch(1)
            layout.addWidget(bubble)
        else:
            layout.addWidget(bubble)
            layout.addStretch(1)

