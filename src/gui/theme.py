"""设计规范：颜色、圆角、间距、字体，以及三套可插值的主题。"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace


RADIUS_BUBBLE = 18
RADIUS_CARD = 12
RADIUS_BUTTON = 10
SPACE = (4, 8, 12, 16, 20, 24, 32)
FONT_SIZES = (12, 13, 15, 17)
FONT_FAMILIES = (
    "PingFang SC",
    "Microsoft YaHei",
    "Noto Sans SC",
    "Noto Sans CJK SC",
    "WenQuanYi Micro Hei",
)
FONT_QSS = ", ".join(f'"{name}"' for name in FONT_FAMILIES) + ", sans-serif"


@dataclass(frozen=True)
class Palette:
    name: str
    light: bool
    bg: str
    bg_nav: str
    bg_side: str
    bg_chat: str
    bg_header: str
    bg_composer: str
    bg_input: str
    bg_hover: str
    bg_selected: str
    bg_card: str
    bg_menu: str
    bubble_out: str
    bubble_in: str
    text: str
    text_out: str
    text_selected: str
    text_secondary: str
    text_tertiary: str
    meta_out: str
    meta_in: str
    accent: str
    accent_hover: str
    accent_soft: str
    accent_text: str
    online: str
    danger: str
    warning: str
    warning_bg: str
    warning_text: str
    danger_bg: str
    danger_text: str
    unread: str
    border: str
    hairline: str
    system_bg: str
    system_text: str
    security_bg: str
    scroll: str
    overlay: str


def _p(**kwargs: str | bool) -> Palette:
    return Palette(**kwargs)  # type: ignore[arg-type]


PALETTES: dict[str, Palette] = {
    "telegram": _p(
        name="telegram",
        light=False,
        bg="#0E1621",
        bg_nav="#17212B",
        bg_side="#17212B",
        bg_chat="#0E1621",
        bg_header="#17212B",
        bg_composer="#17212B",
        bg_input="#242F3D",
        bg_hover="#202B36",
        bg_selected="#2B5278",
        bg_card="#17212B",
        bg_menu="#1E2C3A",
        bubble_out="#2B5278",
        bubble_in="#182533",
        text="#F2F6FA",
        text_out="#FFFFFF",
        text_selected="#FFFFFF",
        text_secondary="#708499",
        text_tertiary="#5C6E80",
        meta_out="#C5D7EA",
        meta_in="#708499",
        accent="#3390EC",
        accent_hover="#4BA0F5",
        accent_soft="#1A3C5C",
        accent_text="#FFFFFF",
        online="#31D158",
        danger="#FF5A5F",
        warning="#E3A008",
        warning_bg="#3D3114",
        warning_text="#FFD27A",
        danger_bg="#3F1E24",
        danger_text="#FFB4B6",
        unread="#3390EC",
        border="#242F3D",
        hairline="#101921",
        system_bg="#182533",
        system_text="#708499",
        security_bg="#3A2228",
        scroll="#6A8298",
        overlay="#0E1621",
    ),
    "wechat": _p(
        name="wechat",
        light=True,
        bg="#EDEDED",
        bg_nav="#F7F7F7",
        bg_side="#FFFFFF",
        bg_chat="#EDEDED",
        bg_header="#EDEDED",
        bg_composer="#F7F7F7",
        bg_input="#FFFFFF",
        bg_hover="#F3F3F3",
        bg_selected="#95EC69",
        bg_card="#FFFFFF",
        bg_menu="#FFFFFF",
        bubble_out="#95EC69",
        bubble_in="#FFFFFF",
        text="#111111",
        text_out="#111111",
        text_selected="#10210F",
        text_secondary="#888888",
        text_tertiary="#B2B2B2",
        meta_out="#3F7A34",
        meta_in="#A0A0A0",
        accent="#07C160",
        accent_hover="#06AD56",
        accent_soft="#E5F8EC",
        accent_text="#FFFFFF",
        online="#07C160",
        danger="#FA5151",
        warning="#FF8F1F",
        warning_bg="#FFF4E5",
        warning_text="#8A4B08",
        danger_bg="#FDECEC",
        danger_text="#A32020",
        unread="#FA5151",
        border="#E0E0E0",
        hairline="#E6E6E6",
        system_bg="#DADADA",
        system_text="#888888",
        security_bg="#FFF1F0",
        scroll="#C4C4C4",
        overlay="#EDEDED",
    ),
    "telegram_light": _p(
        name="telegram_light",
        light=True,
        bg="#FFFFFF",
        bg_nav="#FFFFFF",
        bg_side="#FFFFFF",
        bg_chat="#8EABCB",
        bg_header="#FFFFFF",
        bg_composer="#FFFFFF",
        bg_input="#F4F4F5",
        bg_hover="#F4F4F5",
        bg_selected="#3390EC",
        bg_card="#FFFFFF",
        bg_menu="#FFFFFF",
        bubble_out="#EEFFDE",
        bubble_in="#FFFFFF",
        text="#000000",
        text_out="#000000",
        text_selected="#FFFFFF",
        text_secondary="#707579",
        text_tertiary="#8A9499",
        meta_out="#5C9E55",
        meta_in="#8A9499",
        accent="#3390EC",
        accent_hover="#4BA0F5",
        accent_soft="#E5F2FF",
        accent_text="#FFFFFF",
        online="#31D158",
        danger="#FF3B30",
        warning="#E3A008",
        warning_bg="#FFF6DE",
        warning_text="#7A5A10",
        danger_bg="#FDECEC",
        danger_text="#A32020",
        unread="#3390EC",
        border="#E6E6E6",
        hairline="#E6E6E6",
        system_bg="#6E96B8",
        system_text="#FFFFFF",
        security_bg="#FDECEC",
        scroll="#B7C6D4",
        overlay="#F4F7FB",
    ),
}

THEME_ORDER = ("telegram", "wechat", "telegram_light")
THEME_LABELS = {
    "telegram": "夜间",
    "wechat": "微信",
    "telegram_light": "日间",
}


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    raw = value.lstrip("#")
    return int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02X}{:02X}{:02X}".format(*rgb)


def lerp_color(start: str, end: str, t: float) -> str:
    a = _hex_to_rgb(start)
    b = _hex_to_rgb(end)
    mixed = tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return _rgb_to_hex(mixed)  # type: ignore[arg-type]


def lerp_palette(start: Palette, end: Palette, t: float) -> Palette:
    ratio = max(0.0, min(1.0, t))
    values: dict[str, object] = {}
    for field in fields(Palette):
        left = getattr(start, field.name)
        right = getattr(end, field.name)
        if isinstance(left, str) and left.startswith("#") and isinstance(right, str) and right.startswith("#"):
            values[field.name] = lerp_color(left, right, ratio)
        elif field.name == "light":
            values[field.name] = end.light if ratio >= 0.5 else start.light
        elif field.name == "name":
            values[field.name] = end.name if ratio >= 1 else start.name
        else:
            values[field.name] = right if ratio >= 1 else left
    return replace(start, **values)  # type: ignore[arg-type]


def next_theme(name: str) -> str:
    try:
        index = THEME_ORDER.index(name)
    except ValueError:
        return THEME_ORDER[0]
    return THEME_ORDER[(index + 1) % len(THEME_ORDER)]


def stylesheet(theme: Palette | str = "telegram") -> str:
    palette = theme if isinstance(theme, Palette) else PALETTES.get(theme, PALETTES["telegram"])
    p = palette
    return f"""
    * {{
        font-family: {FONT_QSS};
        font-size: 15px;
        color: {p.text};
        outline: none;
    }}
    QWidget {{
        background: transparent;
        border: none;
    }}
    QMainWindow, QDialog, QWidget#root {{
        background: {p.bg};
    }}
    QWidget#nav {{
        background: {p.bg_nav};
        border-right: 1px solid {p.hairline};
    }}
    QWidget#sidebar {{
        background: {p.bg_side};
    }}
    QWidget#chat {{
        background: {p.bg_chat};
    }}
    QWidget#header, QWidget#composer {{
        background: {p.bg_header};
    }}
    QWidget#composer, QWidget#filePreview {{
        background: {p.bg_composer};
        border-top: 1px solid {p.hairline};
    }}
    QWidget#header {{
        border-bottom: 1px solid {p.hairline};
    }}
    QWidget#card, QFrame#card {{
        background: transparent;
        border: none;
    }}
    QFrame#row {{
        background: transparent;
        border: none;
        border-bottom: 1px solid {p.hairline};
    }}
    QFrame#hair {{
        background: {p.hairline};
        min-height: 1px;
        max-height: 1px;
        border: none;
    }}
    QFrame#popup {{
        background: {p.bg_menu};
        border: none;
        border-radius: 12px;
    }}
    QFrame#previewCard {{
        background: {p.bg_input};
        border: none;
        border-radius: 10px;
    }}
    QLabel#title {{
        font-size: 17px;
        font-weight: 600;
        color: {p.text};
        background: transparent;
    }}
    QLabel#name {{
        font-size: 15px;
        font-weight: 600;
        color: {p.text};
        background: transparent;
    }}
    QLabel#secondary {{
        font-size: 13px;
        color: {p.text_secondary};
        background: transparent;
    }}
    QLabel#caption {{
        font-size: 13px;
        color: {p.text_tertiary};
        background: transparent;
    }}
    QLabel#section {{
        font-size: 14px;
        font-weight: 600;
        color: {p.accent};
        background: transparent;
        padding-top: 12px;
    }}
    QLabel#link {{
        font-size: 15px;
        font-weight: 600;
        color: {p.accent};
        background: transparent;
    }}
    QLineEdit, QSpinBox, QTextEdit#search {{
        background: {p.bg_input};
        border: none;
        border-radius: 10px;
        padding: 8px 12px;
        selection-background-color: {p.accent};
        selection-color: {p.accent_text};
    }}
    QLineEdit#searchField {{
        background: {p.bg_input};
        border: none;
        border-radius: 18px;
        padding: 7px 14px;
        min-height: 20px;
    }}
    QLineEdit:focus, QSpinBox:focus, QLineEdit#searchField:focus {{
        border: none;
    }}
    QTextEdit#plain {{
        background: {p.bg_input};
        border: none;
        border-radius: 10px;
        padding: 8px 10px;
        color: {p.text};
    }}
    QTextEdit {{
        background: transparent;
        border: none;
        selection-background-color: {p.accent};
        selection-color: {p.accent_text};
    }}
    QListView {{
        background: transparent;
        border: none;
        outline: none;
    }}
    QListView::item {{
        background: transparent;
        border: none;
    }}
    QListView::item:selected, QListView::item:hover {{
        background: transparent;
        border: none;
    }}
    QPushButton {{
        background: transparent;
        color: {p.accent};
        border: none;
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 14px;
        font-weight: 500;
    }}
    QPushButton:hover {{
        background: {p.accent_soft};
    }}
    QPushButton#primary {{
        background: {p.accent};
        color: {p.accent_text};
        border-radius: 10px;
        padding: 8px 16px;
        font-size: 15px;
        font-weight: 600;
    }}
    QPushButton#primary:hover {{
        background: {p.accent_hover};
    }}
    QPushButton#primary:disabled {{
        background: {p.border};
        color: {p.text_tertiary};
    }}
    QPushButton#ghost {{
        background: transparent;
        color: {p.accent};
        border-radius: 6px;
        padding: 4px 8px;
    }}
    QPushButton#ghost:hover {{
        background: {p.accent_soft};
    }}
    QPushButton[kind="quiet"] {{
        color: {p.text_secondary};
        background: transparent;
    }}
    QPushButton[kind="quiet"]:hover {{
        color: {p.text};
        background: {p.bg_hover};
    }}
    QPushButton[kind="danger"] {{
        color: {p.danger};
        background: transparent;
    }}
    QPushButton[kind="danger"]:hover {{
        background: {p.danger_bg};
    }}
    QPushButton#chip {{
        background: {p.accent_soft};
        color: {p.accent};
        border-radius: 18px;
        padding: 0;
        min-width: 36px;
        max-width: 36px;
        min-height: 36px;
        max-height: 36px;
        font-size: 15px;
        font-weight: 600;
    }}
    QPushButton#chip:hover {{
        background: {p.accent};
        color: {p.accent_text};
    }}
    QLabel#letterFlash {{
        background: {p.bg_menu};
        color: {p.text};
        border: none;
        border-radius: 16px;
        font-size: 28px;
        font-weight: 600;
    }}
    QMenu {{
        background: {p.bg_menu};
        border: 1px solid {p.border};
        border-radius: {RADIUS_CARD}px;
        padding: 6px;
    }}
    QMenu::item {{
        background: transparent;
        color: {p.text};
        border-radius: 8px;
        padding: 8px 28px 8px 12px;
        font-size: 13px;
    }}
    QMenu::item:selected {{
        background: {p.accent_soft};
        color: {p.text};
    }}
    QMenu::separator {{
        height: 1px;
        background: {p.hairline};
        margin: 4px 8px;
    }}
    QScrollBar:vertical {{
        width: 8px;
        background: transparent;
        margin: 4px 2px 4px 0;
    }}
    QScrollBar::handle:vertical {{
        background: transparent;
        min-height: 28px;
        border-radius: 4px;
    }}
    QScrollBar:horizontal {{
        height: 0px;
    }}
    QScrollBar::add-line, QScrollBar::sub-line,
    QScrollBar::add-page, QScrollBar::sub-page {{
        background: transparent;
        height: 0px;
        width: 0px;
    }}
    QToolTip {{
        background: {p.bg_card};
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: 8px;
        padding: 6px 8px;
        font-size: 12px;
    }}
    QCheckBox {{
        font-size: 13px;
        color: {p.text_secondary};
        spacing: 8px;
    }}
    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border-radius: 4px;
        border: 1px solid {p.border};
        background: {p.bg_input};
    }}
    QCheckBox::indicator:checked {{
        background: {p.accent};
        border: 1px solid {p.accent};
    }}
    QProgressBar {{
        background: {p.border};
        border: none;
        border-radius: 2px;
        max-height: 4px;
    }}
    QProgressBar::chunk {{
        background: {p.accent};
        border-radius: 2px;
    }}
    QSplitter::handle {{
        background: {p.hairline};
        width: 1px;
    }}
    QComboBox {{
        background: {p.bg_input};
        border: none;
        border-radius: 10px;
        padding: 6px 10px;
        min-height: 28px;
    }}
    QComboBox QAbstractItemView {{
        background: {p.bg_menu};
        color: {p.text};
        selection-background-color: {p.accent_soft};
        border: 1px solid {p.border};
    }}
    QStackedWidget, QScrollArea {{
        background: transparent;
        border: none;
    }}
    QScrollArea > QWidget > QWidget {{
        background: transparent;
    }}
    """
