"""登录与本地保险库解锁。"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPaintEvent
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

from src import PROJECT_NAME
from src.gui.engine_worker import ConnectionConfig
from src.gui.icons import paint_icon
from src.gui.widgets import ui_font


class _Logo(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(72, 72)

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#3390EC"))
        painter.drawEllipse(0, 0, 72, 72)
        paint_icon(painter, "send", QRectF(22, 22, 28, 28), "#FFFFFF", self.devicePixelRatioF())


class LoginDialog(QDialog):
    connectRequested = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(PROJECT_NAME)
        self.setMinimumSize(420, 560)
        self.resize(480, 640)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addStretch(1)
        column = QWidget()
        column.setFixedWidth(320)
        card_layout = QVBoxLayout(column)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(10)

        card_layout.addWidget(_Logo(), alignment=Qt.AlignmentFlag.AlignHCenter)

        title = QLabel(PROJECT_NAME)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)
        title.setObjectName("title")
        from PySide6.QtGui import QFont

        title.setFont(ui_font(20, QFont.Weight.DemiBold))
        card_layout.addWidget(title)
        card_layout.addSpacing(12)

        def field(caption: str, widget: QWidget) -> None:
            label = QLabel(caption)
            label.setObjectName("caption")
            card_layout.addWidget(label)
            card_layout.addWidget(widget)

        self.username = QLineEdit("alice")
        self.username.setPlaceholderText("用户名")
        self.password = QLineEdit("password123")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("口令")
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

        self.status = QLabel("")
        self.status.setObjectName("secondary")
        self.status.setWordWrap(True)
        card_layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        card_layout.addWidget(self.progress)
        self.connect_button = QPushButton("登录")
        self.connect_button.setObjectName("primary")
        self.connect_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_button.setFixedHeight(42)
        self.connect_button.clicked.connect(self._submit)
        card_layout.addWidget(self.connect_button)
        self.password.returnPressed.connect(self._submit)
        self.username.returnPressed.connect(self.password.setFocus)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(column)
        row.addStretch(1)
        root.addLayout(row)
        root.addStretch(1)

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#17212B"))
        painter.end()

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
        self.set_busy(True, "正在连接…")
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
