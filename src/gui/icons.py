"""全部界面图标都从 SVG 绘制，并按设备像素比缓存。"""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_PATHS: dict[str, str] = {
    "chat": (
        '<path d="M21 12a8.5 8.5 0 0 1-8.5 8.5c-1.2 0-2.3-.2-3.4-.7L4 21l1.3-4.6A8.5 8.5 0 1 1 21 12z"/>'
    ),
    "contacts": (
        '<path d="M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2"/>'
        '<circle cx="9.5" cy="7" r="3"/>'
        '<path d="M22 21v-2a4 4 0 0 0-3-3.87"/>'
        '<path d="M16 3.13a3 3 0 0 1 0 5.75"/>'
    ),
    "settings": (
        '<circle cx="12" cy="12" r="3"/>'
        '<path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9c.3.6.9 1 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'
    ),
    "emoji": (
        '<circle cx="12" cy="12" r="9"/>'
        '<path d="M8 14s1.5 2 4 2 4-2 4-2"/>'
        '<path d="M9 9h.01M15 9h.01"/>'
    ),
    "paperclip": (
        '<path d="m21.4 11.1-8.5 8.5a5.5 5.5 0 0 1-7.8-7.8l8.5-8.5a3.7 3.7 0 0 1 5.2 5.2l-8.5 8.5a1.8 1.8 0 0 1-2.6-2.6l7.8-7.8"/>'
    ),
    "send": '<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9L2 9l20-7z"/>',
    "mic": (
        '<rect x="9" y="3" width="6" height="11" rx="3"/>'
        '<path d="M6 11a6 6 0 0 0 12 0"/>'
        '<path d="M12 17v4M8 21h8"/>'
    ),
    "mic-off": (
        '<rect x="9" y="3" width="6" height="11" rx="3"/>'
        '<path d="M6 11a6 6 0 0 0 12 0"/>'
        '<path d="M12 17v4M8 21h8"/>'
        '<path d="m3 3 18 18"/>'
    ),
    "phone": (
        '<path d="M22 16.9v2.6a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h2.6a2 2 0 0 1 2 1.7c.1.9.3 1.8.6 2.6a2 2 0 0 1-.5 2.1L7.7 9.5a16 16 0 0 0 6 6l1.1-1.1a2 2 0 0 1 2.1-.5c.8.3 1.7.5 2.6.6a2 2 0 0 1 1.5 2.4z"/>'
    ),
    "pin": (
        '<path d="m14 4 6 6-3 1-4 8-2-2-4 1 3-5-2-2 8-4 1-3z"/>'
        '<path d="m5 19 5-5"/>'
    ),
    "mute": (
        '<path d="M9 9v6"/>'
        '<path d="M5 10v4"/>'
        '<path d="m15 9 5-4v14l-5-4"/>'
        '<path d="m2 2 20 20"/>'
    ),
    "fingerprint": (
        '<path d="M12 11a2 2 0 0 0-2 2c0 2.5.5 4 1 6"/>'
        '<path d="M8 12a4 4 0 0 1 7.5-2"/>'
        '<path d="M6 14c.4 2 1 4.2 1.2 6"/>'
        '<path d="M16 13c.2 1.6.2 3.2 0 5"/>'
        '<path d="M9 7.5A6 6 0 0 1 18 13c0 1.5-.2 3-.5 4.5"/>'
        '<path d="M12 3a9 9 0 0 0-9 9c0 2 .4 3.8.8 5.5"/>'
    ),
    "more": '<circle cx="6" cy="12" r="1.2" fill="current"/><circle cx="12" cy="12" r="1.2" fill="current"/><circle cx="18" cy="12" r="1.2" fill="current"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="m20 20-3.5-3.5"/>',
    "back": '<path d="M15 5 8 12l7 7"/>',
    "check": '<path d="M5 12.5 9.2 17 19 7"/>',
    "checks": '<path d="M2.5 12.5 6.5 16.5 15 8"/><path d="m8 13 3.2 3.2L21 7"/>',
    "clock": '<circle cx="12" cy="12" r="8"/><path d="M12 8v5l3 2"/>',
    "alert": (
        '<circle cx="12" cy="12" r="9"/>'
        '<path d="M12 8v5"/>'
        '<path d="M12 16h.01"/>'
    ),
    "copy": (
        '<rect x="8" y="8" width="12" height="12" rx="2"/>'
        '<path d="M4 16V6a2 2 0 0 1 2-2h10"/>'
    ),
    "reply": '<path d="M9 14 4 9l5-5"/><path d="M4 9h9a7 7 0 0 1 7 7v3"/>',
    "trash": (
        '<path d="M4 7h16"/>'
        '<path d="M9 7V5h6v2"/>'
        '<path d="M7 7l1 13h8l1-13"/>'
    ),
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "lock": (
        '<rect x="5" y="11" width="14" height="9" rx="2"/>'
        '<path d="M8 11V8a4 4 0 0 1 8 0v3"/>'
    ),
    "down": '<path d="m6 9 6 6 6-6"/>',
    "group": (
        '<path d="M17 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>'
        '<circle cx="9.5" cy="7" r="3"/>'
        '<path d="M22 21v-2a4 4 0 0 0-3-3.8"/>'
        '<path d="M16 4.1a3 3 0 0 1 0 5.8"/>'
    ),
    "moments": (
        '<rect x="4" y="5" width="16" height="14" rx="2"/>'
        '<circle cx="12" cy="12" r="3.2"/>'
        '<path d="M8 5.2 9.2 3h5.6L16 5.2"/>'
    ),
    "box": (
        '<path d="M3 8h18v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8z"/>'
        '<path d="M3 8 5.5 4h13L21 8"/>'
        '<path d="M3 12h6a3 3 0 0 0 6 0h6"/>'
    ),
    "heart": (
        '<path d="M12 20s-7-4.4-7-9a4 4 0 0 1 7-2 4 4 0 0 1 7 2c0 4.6-7 9-7 9z"/>'
    ),
}

_cache: dict[tuple[str, str, int, float], QPixmap] = {}
_renderers: dict[tuple[str, str], QSvgRenderer] = {}


def svg_source(name: str, color: str) -> str:
    body = _PATHS[name].replace('fill="current"', f'fill="{color}" stroke="none"')
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        'viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round">{body}</svg>'
    )


def renderer(name: str, color: str) -> QSvgRenderer:
    key = (name, color)
    found = _renderers.get(key)
    if found is None:
        found = QSvgRenderer(QByteArray(svg_source(name, color).encode("utf-8")))
        _renderers[key] = found
    return found


def pixmap(name: str, color: str, size: int, dpr: float = 1.0) -> QPixmap:
    ratio = dpr if dpr > 0 else 1.0
    key = (name, color, size, ratio)
    found = _cache.get(key)
    if found is not None:
        return found
    image = QPixmap(max(1, int(size * ratio)), max(1, int(size * ratio)))
    image.fill(Qt.GlobalColor.transparent)
    image.setDevicePixelRatio(ratio)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer(name, color).render(painter, QRectF(0, 0, size, size))
    painter.end()
    _cache[key] = image
    return image


def icon(name: str, color: str, size: int = 24, dpr: float = 1.0) -> QIcon:
    result = QIcon()
    result.addPixmap(pixmap(name, color, size, dpr))
    return result


def paint_icon(painter: QPainter, name: str, rect: QRectF, color: str, dpr: float = 1.0) -> None:
    size = max(1, int(min(rect.width(), rect.height())))
    image = pixmap(name, color, size, dpr)
    x = rect.x() + (rect.width() - size) / 2
    y = rect.y() + (rect.height() - size) / 2
    painter.drawPixmap(int(x), int(y), image)
