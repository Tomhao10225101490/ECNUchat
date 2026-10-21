"""Windows 测试环境的兼容处理。

PySide6 在 Windows 上会在测试进程退出阶段访问违例，测试本身是通过的。
默认跳过 Qt GUI 测试，避免每次跑测试都弹出系统崩溃窗口；需要时设置
ECNUCHAT_RUN_GUI_TESTS=1 再显式运行。终端 pty 测试只在 Unix 上有意义。
"""

from __future__ import annotations

import os
import sys

import pytest


def pytest_ignore_collect(collection_path, config) -> bool | None:
    del config
    if sys.platform == "win32" and collection_path.name == "test_ui.py":
        return True
    return None


def pytest_collection_modifyitems(config, items) -> None:
    del config
    if sys.platform != "win32" or os.environ.get("ECNUCHAT_RUN_GUI_TESTS") == "1":
        return
    for item in items:
        if item.module.__name__.endswith("test_gui"):
            item.add_marker(
                pytest.mark.skip(
                    reason="PySide6 在 Windows 退出阶段崩溃；"
                    "设置 ECNUCHAT_RUN_GUI_TESTS=1 可显式运行"
                )
            )
