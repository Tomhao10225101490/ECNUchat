"""把用户选中的图片压成能放进协议限制的 JPEG。"""

from __future__ import annotations

import base64

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QImage


def jpeg_token(path: str, *, max_edge: int, max_chars: int, prefix: str = "") -> str:
    image = QImage(path)
    if image.isNull():
        raise ValueError("这张图打不开")
    image = image.convertToFormat(QImage.Format.Format_RGB32)
    edge = max(32, max_edge)
    quality = 55
    for _ in range(8):
        scaled = image.scaled(
            edge,
            edge,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        for q in (quality, max(18, quality - 15), max(15, quality - 28)):
            buffer = QBuffer()
            buffer.open(QIODevice.OpenModeFlag.WriteOnly)
            if not scaled.save(buffer, "JPEG", q):
                continue
            raw = bytes(buffer.data())
            if not raw.startswith(b"\xff\xd8"):
                continue
            token = prefix + base64.b64encode(raw).decode("ascii")
            if len(token) <= max_chars:
                return token
        edge = max(32, int(edge * 0.72))
        quality = max(18, quality - 8)
    raise ValueError("图片压不到限制以内")
