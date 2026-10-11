"""桌面应用生命周期。"""

from __future__ import annotations

import argparse
import re
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from src import PROJECT_NAME
from src.gui.engine_worker import ConnectionConfig, EngineWorker
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow
from src.gui.theme import FONT_FAMILIES, stylesheet


class AppController:
    def __init__(self, app: QApplication, geometry: tuple[int, int, int, int] | None = None) -> None:
        self.app = app
        self.geometry = geometry
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
        worker.connectionChanged.connect(self._on_connection)
        worker.fatalError.connect(self._fatal)
        worker.ready.connect(self._ready)
        worker.start()

    def _on_connection(self, _connected: bool, text: str) -> None:
        if self.window is None and self.login.isVisible():
            self.login.set_busy(True, text)

    def _ready(self, snapshot: dict) -> None:
        assert self.worker is not None
        window = MainWindow(self.worker, snapshot)
        self.window = window
        if self.geometry is not None:
            x, y, width, height = self.geometry
            window.setGeometry(x, y, width, height)
        window.show()
        self.login.hide()
        self.login.accept()

    def _fatal(self, text: str) -> None:
        if self.window is None:
            self.login.set_error(text)
            self.login.show()


def _geometry(spec: str) -> tuple[int, int, int, int] | None:
    matched = re.fullmatch(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", spec.strip())
    if not matched:
        return None
    width, height, x, y = (int(part) for part in matched.groups())
    return x, y, width, height


def run(argv: list[str] | None = None) -> int:
    raw = list(sys.argv if argv is None else argv)
    parser = argparse.ArgumentParser(description=PROJECT_NAME)
    parser.add_argument("--user", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="")
    parser.add_argument("--geometry", default="")
    args, unknown = parser.parse_known_args(raw[1:])
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication([raw[0], *unknown])
    app.setApplicationName(PROJECT_NAME)
    app.setOrganizationName("ECDHChat")
    app.setStyle("Fusion")
    font = QFont()
    font.setFamilies(list(FONT_FAMILIES))
    font.setPixelSize(15)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)
    app.setStyleSheet(stylesheet("telegram"))
    controller = AppController(app, _geometry(args.geometry) if args.geometry else None)
    app._chat_controller = controller  # type: ignore[attr-defined]
    if args.user and args.password:
        controller.connect(
            ConnectionConfig(
                username=args.user.strip(),
                password=args.password,
                host=args.host,
                port=args.port,
                db_path=args.db or f"data/{args.user.strip()}.db",
            )
        )
    else:
        controller.show()
    return app.exec()
