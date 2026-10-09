"""桌面应用生命周期。"""

from __future__ import annotations

import sys

from PySide6.QtCore import QObject
from PySide6.QtWidgets import QApplication

from src import PROJECT_NAME
from src.gui.engine_worker import ConnectionConfig, EngineWorker
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow
from src.gui.styles import stylesheet


class AppController(QObject):
    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self.app = app
        self.login = LoginDialog()
        self.worker: EngineWorker | None = None
        self.window: MainWindow | None = None
        self.login.connectRequested.connect(self.connect)

    def show(self) -> None:
        self.login.show()

    def connect(self, config: ConnectionConfig) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        worker = EngineWorker(config)
        self.worker = worker
        worker.connectionChanged.connect(
            lambda _connected, text: self.login.set_busy(True, text)
            if self.window is None
            else None
        )
        worker.fatalError.connect(self._fatal)
        worker.ready.connect(self._ready)
        worker.start()

    def _ready(self, snapshot: dict) -> None:
        assert self.worker is not None
        self.window = MainWindow(self.worker, snapshot)
        self.window.show()
        self.login.accept()

    def _fatal(self, text: str) -> None:
        if self.window is None:
            self.login.set_error(text)


def run() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(PROJECT_NAME)
    app.setOrganizationName("ECDHChat")
    app.setStyle("Fusion")
    app.setStyleSheet(stylesheet("telegram"))
    controller = AppController(app)
    controller.show()
    # controller 必须保持强引用。
    app._chat_controller = controller  # type: ignore[attr-defined]
    return app.exec()

