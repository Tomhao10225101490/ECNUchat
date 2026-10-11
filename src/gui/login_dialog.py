"""登录与本地保险库解锁。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPaintEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from src import PROJECT_ABSTRACT, PROJECT_NAME
from src.gui.engine_worker import ConnectionConfig
from src.gui.icons import paint_icon
from src.gui.theme import PALETTES, RADIUS_CARD
from src.gui.widgets import ui_font


class _Logo(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(64, 64)

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QLinearGradient(0, 0, 64, 64)
        gradient.setColorAt(0, QColor("#4BA0F5"))
        gradient.setColorAt(1, QColor("#2B5278"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawRoundedRect(0, 0, 64, 64, RADIUS_CARD, RADIUS_CARD)
        from PySide6.QtCore import QRectF

        paint_icon(painter, "lock", QRectF(18, 18, 28, 28), "#FFFFFF", self.devicePixelRatioF())


class LoginDialog(QDialog):
    connectRequested = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(PROJECT_NAME)
        self.setMinimumSize(520, 640)
        self.resize(560, 680)
        palette = PALETTES["telegram"]
        self._accent = palette.accent

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 32, 36, 28)
        root.setSpacing(0)

        card = QWidget()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 28, 28, 24)
        card_layout.setSpacing(14)

        card_layout.addWidget(_Logo(), alignment=Qt.AlignmentFlag.AlignHCenter)

        title = QLabel(PROJECT_NAME)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)
        title.setObjectName("title")
        from PySide6.QtGui import QFont

        title.setFont(ui_font(17, QFont.Weight.DemiBold))
        card_layout.addWidget(title)
        abstract = QLabel(PROJECT_ABSTRACT)
        abstract.setWordWrap(True)
        abstract.setAlignment(Qt.AlignmentFlag.AlignCenter)
        abstract.setObjectName("secondary")
        card_layout.addWidget(abstract)

        def field(caption: str, widget: QWidget) -> None:
            label = QLabel(caption)
            label.setObjectName("caption")
            card_layout.addWidget(label)
            card_layout.addWidget(widget)

        self.username = QLineEdit("alice")
        self.username.setPlaceholderText("3–20 位字母、数字或下划线")
        self.password = QLineEdit("password123")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("只用来解开本机保险库")
        self.host = QLineEdit("127.0.0.1")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(8765)
        endpoint = QWidget()
        endpoint_row = QHBoxLayout(endpoint)
        endpoint_row.setContentsMargins(0, 0, 0, 0)
        endpoint_row.setSpacing(8)
        endpoint_row.addWidget(self.host, 1)
        endpoint_row.addWidget(self.port)
        self.show_password = QCheckBox("显示口令")
        self.show_password.toggled.connect(
            lambda checked: self.password.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        field("用户名", self.username)
        field("本地口令", self.password)
        card_layout.addWidget(self.show_password)
        field("服务器", endpoint)

        self.status = QLabel("身份私钥只保存在本机，加密后落盘")
        self.status.setObjectName("secondary")
        self.status.setWordWrap(True)
        card_layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        card_layout.addWidget(self.progress)
        self.connect_button = QPushButton("进入安全聊天室")
        self.connect_button.setObjectName("primary")
        self.connect_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_button.setFixedHeight(44)
        self.connect_button.clicked.connect(self._submit)
        card_layout.addWidget(self.connect_button)
        self.password.returnPressed.connect(self._submit)
        self.username.returnPressed.connect(self.password.setFocus)
        root.addWidget(card)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor("#0E1621"))
        gradient.setColorAt(1, QColor("#17212B"))
        painter.fillRect(self.rect(), gradient)
        painter.end()
        super().paintEvent(event)

    def _submit(self) -> None:
        username = self.username.text().strip()
        password = self.password.text()
        if not username or not password:
            self.set_error("请输入用户名和本地口令")
            return
        config = ConnectionConfig(
            username=username,
            password=password,
            host=self.host.text().strip() or "127.0.0.1",
            port=self.port.value(),
            db_path=f"data/{username}.db",
        )
        self.set_busy(True, "正在派生保险库密钥并连接…")
        self.connectRequested.emit(config)

    def set_busy(self, busy: bool, text: str = "") -> None:
        self.connect_button.setEnabled(not busy)
        self.progress.setVisible(busy)
        if text:
            self.status.setText(text)
            self.status.setStyleSheet("")

    def set_error(self, text: str) -> None:
        self.set_busy(False)
        self.status.setText(text)
        self.status.setStyleSheet("color:#ff6b6b")
