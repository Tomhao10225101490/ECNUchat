"""登录与本地保险库解锁窗口。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from src import PROJECT_ABSTRACT, PROJECT_NAME
from src.gui.engine_worker import ConnectionConfig


class LoginDialog(QDialog):
    connectRequested = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(PROJECT_NAME)
        self.setMinimumSize(500, 520)
        root = QVBoxLayout(self)
        root.setContentsMargins(52, 42, 52, 42)
        root.setSpacing(18)

        logo = QLabel("🔐")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size:48px")
        root.addWidget(logo)
        title = QLabel(PROJECT_NAME)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size:21px;font-weight:800;color:#6ab3f3")
        root.addWidget(title)
        abstract = QLabel(PROJECT_ABSTRACT)
        abstract.setWordWrap(True)
        abstract.setAlignment(Qt.AlignmentFlag.AlignCenter)
        abstract.setObjectName("muted")
        root.addWidget(abstract)

        form = QFormLayout()
        form.setSpacing(13)
        self.username = QLineEdit("alice")
        self.username.setPlaceholderText("3–20 位字母、数字或下划线")
        self.password = QLineEdit("password123")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.host = QLineEdit("127.0.0.1")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(8765)
        endpoint = QHBoxLayout()
        endpoint.addWidget(self.host, 1)
        endpoint.addWidget(self.port)
        self.show_password = QCheckBox("显示口令")
        self.show_password.toggled.connect(
            lambda checked: self.password.setEchoMode(
                QLineEdit.EchoMode.Normal
                if checked
                else QLineEdit.EchoMode.Password
            )
        )
        form.addRow("用户名", self.username)
        form.addRow("本地口令", self.password)
        form.addRow("", self.show_password)
        form.addRow("服务器", endpoint)
        root.addLayout(form)

        self.status = QLabel("身份私钥只保存在本机，加密后落盘")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        root.addWidget(self.progress)
        root.addStretch()
        self.connect_button = QPushButton("进入安全聊天室")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self._submit)
        root.addWidget(self.connect_button)
        self.password.returnPressed.connect(self._submit)

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

    def set_error(self, text: str) -> None:
        self.set_busy(False)
        self.status.setText(text)
        self.status.setStyleSheet("color:#ff6b6b")

