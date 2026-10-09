"""桌面客户端主题。"""

THEMES = {
    "telegram": {
        "accent": "#3390ec",
        "accent_hover": "#4ba0f5",
        "bubble_out": "#2b5278",
        "bubble_in": "#202b36",
        "bubble_out_text": "#ffffff",
        "selected": "#2b5278",
    },
    "wechat": {
        "accent": "#07c160",
        "accent_hover": "#18d16f",
        "bubble_out": "#95ec69",
        "bubble_in": "#202b36",
        "bubble_out_text": "#10210f",
        "selected": "#244238",
    },
}


def stylesheet(theme: str = "telegram") -> str:
    p = THEMES.get(theme, THEMES["telegram"])
    return f"""
    * {{
        font-family: "Noto Sans CJK SC", "Microsoft YaHei", "PingFang SC", sans-serif;
        font-size: 14px;
        color: #e8eef5;
    }}
    QMainWindow, QWidget#root, QDialog {{
        background: #0e1621;
    }}
    QWidget#sidebar {{
        background: #17212b;
        border-right: 1px solid #263645;
    }}
    QLabel#brand {{
        color: {p["accent"]};
        font-size: 17px;
        font-weight: 700;
    }}
    QLabel#muted, QLabel#timestamp, QLabel#status {{
        color: #8b9bb4;
        font-size: 12px;
    }}
    QLabel#online {{
        color: #45d366;
        font-size: 12px;
    }}
    QLineEdit, QTextEdit, QSpinBox {{
        background: #202b36;
        border: 1px solid #314252;
        border-radius: 12px;
        padding: 9px 12px;
        selection-background-color: {p["accent"]};
    }}
    QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {{
        border: 1px solid {p["accent"]};
    }}
    QListWidget {{
        background: transparent;
        border: none;
        outline: none;
    }}
    QListWidget::item {{
        border-radius: 10px;
        padding: 7px;
        margin: 2px 6px;
    }}
    QListWidget::item:selected {{
        background: {p["selected"]};
    }}
    QListWidget::item:hover:!selected {{
        background: #202f3d;
    }}
    QPushButton {{
        background: #253444;
        border: none;
        border-radius: 11px;
        padding: 9px 14px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        background: #31475b;
    }}
    QPushButton#primary {{
        background: {p["accent"]};
        color: white;
    }}
    QPushButton#primary:hover {{
        background: {p["accent_hover"]};
    }}
    QPushButton#icon {{
        background: transparent;
        font-size: 17px;
        min-width: 34px;
    }}
    QPushButton#icon:hover {{
        background: #253444;
    }}
    QFrame#header, QFrame#composer {{
        background: #17212b;
        border: none;
    }}
    QFrame#bubble_in {{
        background: {p["bubble_in"]};
        border-radius: 14px;
    }}
    QFrame#bubble_out {{
        background: {p["bubble_out"]};
        border-radius: 14px;
    }}
    QFrame#bubble_out QLabel#body {{
        color: {p["bubble_out_text"]};
    }}
    QFrame#system {{
        background: #182533;
        border: 1px solid #32465a;
        border-radius: 12px;
    }}
    QFrame#security {{
        background: #3a2228;
        border: 1px solid #ff6b6b;
        border-radius: 12px;
    }}
    QScrollArea#message_scroll {{
        border: none;
        background: #0e1621;
    }}
    QScrollArea#message_scroll > QWidget > QWidget,
    QWidget#message_host {{
        background: #0e1621;
    }}
    QScrollBar:vertical {{
        width: 9px;
        background: transparent;
    }}
    QScrollBar::handle:vertical {{
        background: #3a4b5d;
        border-radius: 4px;
        min-height: 30px;
    }}
    QToolTip {{
        background: #253444;
        border: 1px solid #43576b;
        padding: 6px;
    }}
    QMenu {{
        background: #202b36;
        border: 1px solid #3a4b5d;
        border-radius: 8px;
        padding: 6px;
    }}
    QMenu::item {{
        background: transparent;
        border-radius: 6px;
        padding: 8px 28px 8px 12px;
    }}
    QMenu::item:selected {{
        background: {p["selected"]};
    }}
    QMenu::separator {{
        background: #3a4b5d;
        height: 1px;
        margin: 5px 8px;
    }}
    QMessageBox, QInputDialog {{
        background: #17212b;
    }}
    QMessageBox QLabel, QInputDialog QLabel {{
        color: #e8eef5;
    }}
    """

