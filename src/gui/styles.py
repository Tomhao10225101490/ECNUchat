"""兼容入口。新的颜色和样式表在 theme.py。"""

from src.gui.theme import PALETTES, stylesheet

THEMES = PALETTES

__all__ = ["PALETTES", "THEMES", "stylesheet"]
