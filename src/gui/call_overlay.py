"""语音通话浮层：去电、来电接听或挂断、通话中的时长和静音。"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QRectF, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QAbstractButton, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from src.call import elapsed_seconds, format_call_clock
from src.gui.icons import paint_icon
from src.gui.theme import Palette
from src.gui.widgets import AvatarWidget, ui_font

_ANSWER = "#2FCB6A"


class CallRoundButton(QAbstractButton):
    def __init__(
        self,
        object_name: str,
        label: str,
        icon: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName(object_name)
        self.setText(label)
        self.setFixedSize(88, 112)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setStyleSheet("background:transparent; border:none;")
        self._icon = icon
        self._fill = "#FF5A5F"
        self._icon_color = "#FFFFFF"
        self._text = "#F2F6FA"
        self._rotation = 0
        self._hover = False

    def set_label(self, label: str) -> None:
        self.setText(label)
        self.update()

    def set_icon(self, icon: str) -> None:
        self._icon = icon
        self.update()

    def set_colors(self, fill: str, text: str, icon: str = "#FFFFFF", rotation: int = 0) -> None:
        self._fill = fill
        self._text = text
        self._icon_color = icon
        self._rotation = rotation
        self.update()

    def enterEvent(self, event) -> None:
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(self._fill)
        if self._hover:
            color = color.lighter(112)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(QRectF(12, 2, 64, 64))
        painter.save()
        painter.translate(44, 34)
        painter.rotate(self._rotation)
        paint_icon(painter, self._icon, QRectF(-14, -14, 28, 28), self._icon_color, self.devicePixelRatioF())
        painter.restore()
        painter.setPen(QColor(self._text))
        painter.setFont(ui_font(13))
        painter.drawText(
            QRectF(0, 74, 88, 28),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            self.text(),
        )


class CallOverlay(QWidget):
    acceptClicked = Signal()
    rejectClicked = Signal()
    hangupClicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("callOverlay")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._palette: Palette | None = None
        self._phase = "idle"
        self._started: float | None = None
        self._muted = False
        self._peer = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 36, 24, 28)
        layout.setSpacing(8)
        layout.addStretch(2)

        self.avatar = AvatarWidget(96, self)
        layout.addWidget(self.avatar, alignment=Qt.AlignmentFlag.AlignHCenter)
        self.name_label = QLabel("")
        self.name_label.setObjectName("callPeer")
        self.name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label = QLabel("")
        self.status_label.setObjectName("callStatus")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.secure_label = QLabel("端到端加密")
        self.secure_label.setObjectName("callSecure")
        self.secure_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.name_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.secure_label)
        layout.addStretch(3)

        buttons = QHBoxLayout()
        buttons.setSpacing(28)
        buttons.addStretch(1)
        self.accept_button = CallRoundButton("callAccept", "接听", "phone")
        self.reject_button = CallRoundButton("callReject", "挂断", "phone")
        self.mute_button = CallRoundButton("callMute", "静音", "mic")
        self.hangup_button = CallRoundButton("callHangup", "挂断", "phone")
        self.accept_button.clicked.connect(lambda _checked=False: self.acceptClicked.emit())
        self.reject_button.clicked.connect(lambda _checked=False: self.rejectClicked.emit())
        self.mute_button.clicked.connect(self._toggle_mute)
        self.hangup_button.clicked.connect(lambda _checked=False: self.hangupClicked.emit())
        buttons.addWidget(self.accept_button)
        buttons.addWidget(self.mute_button)
        buttons.addWidget(self.reject_button)
        buttons.addWidget(self.hangup_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addStretch(1)

        self._clock = QTimer(self)
        self._clock.setInterval(200)
        self._clock.timeout.connect(self._tick)
        self.hide()

    @property
    def muted(self) -> bool:
        return self._muted

    def set_muted(self, muted: bool) -> None:
        self._muted = bool(muted)
        self._paint_buttons()

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.avatar.online_color = palette.online
        self.avatar.ring = palette.bg
        self.setStyleSheet(
            f"QWidget#callOverlay {{ background:{palette.bg}; }}"
            "QLabel { background:transparent; }"
        )
        self.name_label.setFont(ui_font(22, QFont.Weight.DemiBold))
        self.name_label.setStyleSheet(f"color:{palette.text}; background:transparent;")
        self.status_label.setFont(ui_font(16))
        self.status_label.setStyleSheet(f"color:{palette.text_secondary}; background:transparent;")
        self.secure_label.setFont(ui_font(13))
        self.secure_label.setStyleSheet(f"color:{palette.text_tertiary}; background:transparent;")
        self._paint_buttons()

    def set_call(self, state: dict, palette: Palette, title: str, online: bool) -> None:
        self.apply_palette(palette)
        phase = str(state.get("phase") or "idle")
        if phase != "active":
            self._muted = False
        self._phase = phase
        self._started = state.get("started")
        self._peer = str(state.get("peer") or "")
        self.name_label.setText(title or self._peer)
        self.avatar.set_person(self._peer or title, online=online)
        self.secure_label.setVisible(phase != "idle")
        self.accept_button.setVisible(phase == "incoming")
        self.reject_button.setVisible(phase == "incoming")
        self.mute_button.setVisible(phase == "active")
        self.hangup_button.setVisible(phase in {"outgoing", "active"})
        self._paint_buttons()
        self._tick()
        if phase == "active":
            self._clock.start()
        else:
            self._clock.stop()
        if phase == "idle":
            self.hide()
            return
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
        self.show()
        self.raise_()

    def _paint_buttons(self) -> None:
        palette = self._palette
        text = palette.text if palette is not None else "#F2F6FA"
        danger = palette.danger if palette is not None else "#FF5A5F"
        mute_fill = palette.bg_input if palette is not None else "#242F3D"
        icon = text
        if self._muted:
            mute_fill = palette.danger_bg if palette is not None else "#3F1E24"
            icon = danger
        self.accept_button.set_colors(_ANSWER, text, "#FFFFFF", 0)
        self.reject_button.set_colors(danger, text, "#FFFFFF", 135)
        self.hangup_button.set_colors(danger, text, "#FFFFFF", 135)
        self.mute_button.set_colors(mute_fill, text, icon, 0)
        self.mute_button.set_icon("mic-off" if self._muted else "mic")
        self.mute_button.set_label("取消静音" if self._muted else "静音")

    def _toggle_mute(self, _checked: bool = False) -> None:
        self._muted = not self._muted
        self._paint_buttons()

    def _tick(self) -> None:
        if self._phase == "outgoing":
            self.status_label.setText("正在等待对方接听…")
        elif self._phase == "incoming":
            self.status_label.setText("邀请你语音通话")
        elif self._phase == "active":
            self.status_label.setText(format_call_clock(elapsed_seconds(self._started, time.time())))
        else:
            self.status_label.setText("")
