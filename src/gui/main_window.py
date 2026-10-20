"""三栏聊天主窗口。只负责呈现，加密仍走 ChatEngine。"""

from __future__ import annotations

import base64
import json
import time
import uuid
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEasingCurve, QEvent, QPoint, Qt, QTimer, QUrl, QVariantAnimation
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from src import PROJECT_ABSTRACT, PROJECT_NAME
from src.gui.app_pages import DropboxBoard, MomentBoard, MomentComposer, PeoplePanel, ProfileSettings
from src.gui.chat_view import ConvItem, ConversationList, MessageList, group_flags
from src.gui.engine_worker import EngineWorker
from src.gui.logic import (
    ChatItem,
    classify_row,
    day_label,
    decode_reply,
    encode_reply,
    finalize_groups,
    hidden_key,
    list_clock,
    security_hint,
)
from src.gui.theme import PALETTES, THEME_LABELS, THEME_ORDER, Palette, lerp_palette, next_theme, stylesheet
from src.gui.widgets import (
    ElideLabel,
    AvatarWidget,
    BlurDialog,
    EmptyState,
    EmojiPanel,
    IconButton,
    InputShell,
    MessageBubble,
    NavButton,
    NewMessageButton,
    SendButton,
    ToggleSwitch,
    TypingDots,
    ui_font,
)


class ConnectionBanner(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setMaximumHeight(0)
        self.label = QLabel()
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.addWidget(self.label)
        self._mode = "hidden"
        self._palette = PALETTES["telegram"]
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(200)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._set_height)

    def _set_height(self, value: object) -> None:
        self.setMaximumHeight(int(value))

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self._paint()

    def set_mode(self, mode: str, text: str) -> None:
        self._mode = mode
        self.label.setText(text)
        self._paint()
        target = 0 if mode == "hidden" else 28
        self._anim.stop()
        self._anim.setStartValue(self.maximumHeight())
        self._anim.setEndValue(target)
        self._anim.start()

    def _paint(self) -> None:
        palette = self._palette
        if self._mode == "warn":
            bg, fg = palette.warning_bg, palette.warning_text
        elif self._mode == "error":
            bg, fg = palette.danger_bg, palette.danger_text
        else:
            bg, fg = palette.bg, palette.text_secondary
        self.setStyleSheet(f"background:{bg};")
        self.label.setStyleSheet(f"color:{fg};font-size:12px;background:transparent;")


from PySide6.QtWidgets import QMainWindow  # noqa: E402


class MainWindow(QMainWindow):
    def __init__(self, worker: EngineWorker, initial: dict[str, Any]) -> None:
        super().__init__()
        self.worker = worker
        self.username = str(initial["username"])
        self.current_conv: str | None = None
        self.snapshot_data = initial
        self.unread: dict[str, int] = dict(initial.get("unread", {}))
        self.bubbles: dict[str, MessageBubble] = {}
        self.theme = str(initial.get("theme", "telegram"))
        if self.theme not in PALETTES:
            self.theme = "telegram"
        self._palette = PALETTES[self.theme]
        self._reduce_motion = bool(initial.get("reduce_motion", False))
        self._connected = bool(initial.get("connected", False))
        self._pane = "list"
        self._compact = False
        self._in_open = False
        self._search_mode = False
        self._typing = False
        self._pending_new = 0
        self._hidden = _load_set(initial.get("hidden", ""))
        self._pins = _load_set(initial.get("pins", ""))
        self._mutes = _load_set(initial.get("mutes", ""))
        self.directory: list[str] = []
        self._search_results: list[dict[str, Any]] = []
        self._social_open = False
        self._theme_anim: QVariantAnimation | None = None
        self._theme_from = self._palette
        self._fp: BlurDialog | None = None
        self._fp_value = ""
        self.setWindowTitle(f"{PROJECT_NAME} — {self.username}")
        self.resize(1180, 760)
        self.setMinimumSize(420, 560)
        self._build()
        self._connect_worker()
        self.apply_theme(self.theme, persist=False, animate=False)
        self.update_snapshot(initial)
        self.banner.set_mode("hidden" if self._connected else "error", "端到端加密连接已建立" if self._connected else "未连接")
        saved = str(initial.get("current_conv") or "")
        if saved:
            QTimer.singleShot(0, lambda: self.open_conversation(saved))
        QTimer.singleShot(0, lambda: self.worker.submit("users"))

    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        root.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.banner = ConnectionBanner()
        outer.addWidget(self.banner)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        outer.addLayout(body, 1)

        self.nav = QWidget()
        self.nav.setObjectName("nav")
        self.nav.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.nav.setFixedWidth(72)
        nav_layout = QVBoxLayout(self.nav)
        nav_layout.setContentsMargins(12, 16, 12, 16)
        nav_layout.setSpacing(8)
        self.nav_chat = NavButton("chat")
        self.nav_contacts = NavButton("contacts")
        self.nav_moments = NavButton("moments")
        self.nav_box = NavButton("box")
        self.nav_settings = NavButton("settings")
        self.nav_chat.setToolTip("聊天")
        self.nav_contacts.setToolTip("联系人")
        self.nav_moments.setToolTip("朋友圈")
        self.nav_box.setToolTip("投递箱")
        self.nav_settings.setToolTip("设置")
        self.nav_chat.clicked.connect(lambda: self._show_page(0))
        self.nav_contacts.clicked.connect(lambda: self._show_page(1))
        self.nav_moments.clicked.connect(lambda: self._show_page(2))
        self.nav_box.clicked.connect(lambda: self._show_page(3))
        self.nav_settings.clicked.connect(lambda: self._show_page(4))
        nav_layout.addWidget(self.nav_chat)
        nav_layout.addWidget(self.nav_contacts)
        nav_layout.addWidget(self.nav_moments)
        nav_layout.addWidget(self.nav_box)
        nav_layout.addWidget(self.nav_settings)
        nav_layout.addStretch(1)
        self.self_avatar = AvatarWidget(40)
        self.self_avatar.set_person(self.username, online=True)
        self.self_avatar.setToolTip(self.username)
        nav_layout.addWidget(self.self_avatar, alignment=Qt.AlignmentFlag.AlignHCenter)
        body.addWidget(self.nav)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(1)
        body.addWidget(self.splitter, 1)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.sidebar.setMinimumWidth(260)
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(12, 12, 8, 8)
        side.setSpacing(8)
        header = QHBoxLayout()
        self.side_title = QLabel("聊天")
        self.side_title.setObjectName("title")
        header.addWidget(self.side_title)
        header.addStretch(1)
        self.compose_button = IconButton("plus", 36, 18)
        self.compose_button.setToolTip("新建")
        self.compose_button.clicked.connect(self._compose_menu)
        header.addWidget(self.compose_button)
        side.addLayout(header)

        search_row = QHBoxLayout()
        self.search_icon = IconButton("search", 32, 16)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索")
        self.search.setClearButtonEnabled(True)
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(200)
        self.search_timer.timeout.connect(self.perform_search)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        search_row.addWidget(self.search_icon)
        search_row.addWidget(self.search, 1)
        side.addLayout(search_row)

        self.page_chat = QWidget()
        chat_page = QVBoxLayout(self.page_chat)
        chat_page.setContentsMargins(0, 0, 0, 0)
        self.conversations = ConversationList()
        self.conversations.activated_key.connect(self._activate_key)
        self.conversations.context_key.connect(self._conv_menu)
        chat_page.addWidget(self.conversations)

        self.page_contacts = QWidget()
        contacts_layout = QVBoxLayout(self.page_contacts)
        contacts_layout.setContentsMargins(0, 0, 0, 0)
        self.contacts = ConversationList()
        self.contacts.activated_key.connect(self._activate_contact)
        self.people_panel = PeoplePanel()
        self.people_panel.acceptClicked.connect(
            lambda name: self.worker.submit("friend_respond", username=name, accept=True)
        )
        self.people_panel.rejectClicked.connect(
            lambda name: self.worker.submit("friend_respond", username=name, accept=False)
        )
        self.people_panel.cancelClicked.connect(
            lambda name: self.worker.submit("friend_remove", username=name)
        )
        self.people_panel.removeClicked.connect(
            lambda name: self.worker.submit("friend_remove", username=name)
        )
        self.people_panel.blockClicked.connect(
            lambda name: self.worker.submit("friend_block", username=name)
        )
        self.people_panel.unblockClicked.connect(
            lambda name: self.worker.submit("friend_remove", username=name)
        )
        self.people_panel.messageClicked.connect(
            lambda name: self.worker.submit("open_chat", username=name)
        )
        self.people_panel.addClicked.connect(self._add_named)
        self.people_panel.hide()
        contacts_layout.addWidget(self.contacts, 1)
        contacts_layout.addWidget(self.people_panel, 1)

        self.page_moments = MomentComposer()
        self.page_moments.postRequested.connect(
            lambda body, image, visibility: self.worker.submit(
                "moment_post", body=body, image=image, visibility=visibility
            )
        )
        self.page_box = QWidget()
        box_layout = QVBoxLayout(self.page_box)
        box_layout.setContentsMargins(0, 8, 8, 8)
        box_hint = QLabel("先打开一个会话，再把不超过 24KB 的文件投进去。右边是本机已经解开的文件。")
        box_hint.setWordWrap(True)
        box_hint.setObjectName("secondary")
        box_button = QPushButton("投递到当前会话")
        box_button.setObjectName("primary")
        box_button.clicked.connect(self._attach)
        box_layout.addWidget(box_hint)
        box_layout.addWidget(box_button)
        box_layout.addStretch(1)

        self.page_settings = self._build_settings()

        self.pages = QWidget()
        pages_layout = QVBoxLayout(self.pages)
        pages_layout.setContentsMargins(0, 0, 0, 0)
        self._stack = [
            self.page_chat,
            self.page_contacts,
            self.page_moments,
            self.page_box,
            self.page_settings,
        ]
        for page in self._stack:
            pages_layout.addWidget(page)
        side.addWidget(self.pages, 1)
        self.page_contacts.hide()
        self.page_moments.hide()
        self.page_box.hide()
        self.page_settings.hide()
        self.splitter.addWidget(self.sidebar)

        self.chat = QWidget()
        self.chat.setObjectName("chat")
        self.chat.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        chat_layout = QVBoxLayout(self.chat)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)

        self.header = QWidget()
        self.header.setObjectName("header")
        self.header.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.header.setFixedHeight(64)
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        header_layout.setSpacing(10)
        self.back_button = IconButton("back", 36, 18)
        self.back_button.setToolTip("返回")
        self.back_button.clicked.connect(self._back)
        self.back_button.hide()
        header_layout.addWidget(self.back_button)
        self.header_avatar = AvatarWidget(40)
        header_layout.addWidget(self.header_avatar)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        self.chat_title = ElideLabel("选择一个会话")
        self.chat_title.setObjectName("title")
        self.chat_subtitle = ElideLabel("消息只在本机解密")
        self.chat_subtitle.setObjectName("secondary")
        typing_row = QHBoxLayout()
        typing_row.setSpacing(6)
        self.typing_dots = TypingDots()
        self.typing_label = QLabel("正在输入…")
        self.typing_label.setObjectName("secondary")
        self.typing_dots.hide()
        self.typing_label.hide()
        typing_row.addWidget(self.chat_subtitle, 1)
        typing_row.addWidget(self.typing_dots)
        typing_row.addWidget(self.typing_label)
        titles.addWidget(self.chat_title)
        titles.addLayout(typing_row)
        header_layout.addLayout(titles, 1)
        self.info_button = QPushButton("身份指纹")
        self.info_button.setObjectName("ghost")
        self.info_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.info_button.setEnabled(False)
        self.info_button.clicked.connect(self.show_fingerprint)
        header_layout.addWidget(self.info_button)
        self.more_button = IconButton("more", 36, 18)
        self.more_button.setToolTip("更多")
        self.more_button.clicked.connect(self._more_menu)
        header_layout.addWidget(self.more_button)
        chat_layout.addWidget(self.header)

        self.chat_body = QWidget()
        self.empty_state = EmptyState(self.chat_body)
        self.messages = MessageList(self.chat_body)
        self.messages.retryRequested.connect(self._retry)
        self.messages.copyRequested.connect(self._copy_item)
        self.messages.replyRequested.connect(self._reply_to)
        self.messages.deleteRequested.connect(self._delete_item)
        self.new_button = NewMessageButton(self.chat_body)
        self.new_button.clicked.connect(self._jump_bottom)
        chat_layout.addWidget(self.chat_body, 1)

        self.composer_bar = QWidget()
        self.composer_bar.setObjectName("composer")
        self.composer_bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        composer_layout = QHBoxLayout(self.composer_bar)
        composer_layout.setContentsMargins(12, 8, 12, 12)
        composer_layout.setSpacing(8)
        self.emoji_button = IconButton("emoji", 36, 20)
        self.emoji_button.setToolTip("表情")
        self.attach_button = IconButton("paperclip", 36, 20)
        self.attach_button.setToolTip("附件")
        self.input_shell = InputShell()
        self.composer = self.input_shell.edit
        self.reply_bar = self.input_shell.reply
        self.send_button = SendButton()
        self.send_button.setToolTip("发送")
        self.emoji_button.clicked.connect(self._toggle_emoji)
        self.attach_button.clicked.connect(self._attach)
        self.composer.sendRequested.connect(self.send_current)
        self.composer.textChanged.connect(self._refresh_send)
        self.send_button.clicked.connect(self._send_or_mic)
        composer_layout.addWidget(self.emoji_button, alignment=Qt.AlignmentFlag.AlignBottom)
        composer_layout.addWidget(self.attach_button, alignment=Qt.AlignmentFlag.AlignBottom)
        composer_layout.addWidget(self.input_shell, 1)
        composer_layout.addWidget(self.send_button, alignment=Qt.AlignmentFlag.AlignBottom)
        chat_layout.addWidget(self.composer_bar)
        self.moment_board = MomentBoard()
        self.moment_board.likeClicked.connect(
            lambda moment_id: self.worker.submit("moment_like", id=moment_id)
        )
        self.moment_board.commentClicked.connect(
            lambda moment_id, body: self.worker.submit(
                "moment_comment", id=moment_id, body=body
            )
        )
        self.moment_board.deleteClicked.connect(
            lambda moment_id: self.worker.submit("moment_delete", id=moment_id)
        )
        self.drop_board = DropboxBoard()
        self.drop_board.openRequested.connect(self._open_drop)
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.chat)
        self.main_stack.addWidget(self.moment_board)
        self.main_stack.addWidget(self.drop_board)
        self.splitter.addWidget(self.main_stack)
        self.splitter.setSizes([300, 860])
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)

        self.emoji_panel = EmojiPanel(self.chat)
        self.emoji_panel.chosen.connect(self._insert_emoji)

        self.toast = QLabel(self)
        self.toast.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.toast.hide()
        self.toast_timer = QTimer(self)
        self.toast_timer.setSingleShot(True)
        self.toast_timer.timeout.connect(self.toast.hide)
        self._toast_anim: QVariantAnimation | None = None

        find_action = QAction(self)
        find_action.setShortcut(QKeySequence.StandardKey.Find)
        find_action.triggered.connect(self._focus_search)
        self.addAction(find_action)
        for index, name in enumerate(THEME_ORDER, start=1):
            action = QAction(self)
            action.setShortcut(QKeySequence(f"Ctrl+{index}"))
            action.triggered.connect(lambda _checked=False, theme=name: self.apply_theme(theme))
            self.addAction(action)
        self._typing_anim = QVariantAnimation(self)
        self._typing_anim.setStartValue(0.0)
        self._typing_anim.setEndValue(1.0)
        self._typing_anim.setDuration(900)
        self._typing_anim.setLoopCount(-1)
        self._typing_anim.valueChanged.connect(self._on_typing_phase)
        self.chat_body.installEventFilter(self)
        self._show_page(0)

    def _build_settings(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 8, 8, 8)
        layout.setSpacing(12)
        hint = QLabel("主题")
        hint.setObjectName("secondary")
        layout.addWidget(hint)
        self.theme_buttons: dict[str, QPushButton] = {}
        for name in THEME_ORDER:
            button = QPushButton(THEME_LABELS[name])
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFixedHeight(40)
            button.clicked.connect(lambda _checked=False, theme=name: self.apply_theme(theme))
            self.theme_buttons[name] = button
            layout.addWidget(button)
        row = QHBoxLayout()
        label = QLabel("减少动态效果")
        label.setObjectName("secondary")
        self.motion_switch = ToggleSwitch()
        self.motion_switch.setChecked(self._reduce_motion)
        self.motion_switch.toggled.connect(self.set_reduce_motion)
        row.addWidget(label)
        row.addStretch(1)
        row.addWidget(self.motion_switch)
        layout.addLayout(row)
        about = QLabel(PROJECT_NAME)
        about.setWordWrap(True)
        about.setObjectName("name")
        abstract = QLabel(PROJECT_ABSTRACT)
        abstract.setWordWrap(True)
        abstract.setObjectName("caption")
        layout.addWidget(about)
        layout.addWidget(abstract)
        self.profile_settings = ProfileSettings()
        self.profile_settings.profileSaved.connect(self._save_profile)
        self.profile_settings.privacySaved.connect(self._save_privacy)
        layout.addWidget(self.profile_settings)
        layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(page)
        scroll.viewport().setAutoFillBackground(False)
        return scroll

    def eventFilter(self, watched, event):
        if watched is self.chat_body and event.type() == QEvent.Type.Resize:
            self._place_overlays()
        return super().eventFilter(watched, event)

    def _place_overlays(self) -> None:
        rect = self.chat_body.rect()
        self.empty_state.setGeometry(rect)
        self.messages.setGeometry(rect)
        self.new_button.adjustSize()
        self.new_button.move(
            max(8, (rect.width() - self.new_button.width()) // 2),
            max(8, rect.height() - self.new_button.height() - 12),
        )
        self.new_button.raise_()

    def _connect_worker(self) -> None:
        self.worker.snapshot.connect(self.update_snapshot)
        self.worker.incoming.connect(self.on_incoming)
        self.worker.historyReady.connect(self.show_history)
        self.worker.searchReady.connect(self.show_search_results)
        self.worker.messageState.connect(self.on_message_state)
        self.worker.actionResult.connect(self.on_action_result)
        self.worker.connectionChanged.connect(self.on_connection)
        self.worker.fatalError.connect(self.on_fatal)

    def apply_theme(self, theme: str, *, persist: bool = True, animate: bool = True) -> None:
        if theme not in PALETTES:
            theme = "telegram"
        self.theme = theme
        target = PALETTES[theme]
        if persist:
            self.worker.submit("set_ui", theme=theme)
        if not animate or self._reduce_motion:
            self._set_palette(target)
            return
        start = self._palette
        self._theme_from = start
        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setDuration(200)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        last = {"t": 0.0}

        def step(value: object) -> None:
            now = time.monotonic()
            ratio = float(value)
            if ratio < 1 and now - last["t"] < 0.016:
                return
            last["t"] = now
            self._set_palette(lerp_palette(start, target, ratio))

        anim.valueChanged.connect(step)
        anim.finished.connect(lambda: self._set_palette(target))
        self._theme_anim = anim
        anim.start()

    def _set_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.setStyleSheet(stylesheet(palette))
        self.banner.apply_palette(palette)
        self.conversations.apply_palette(palette)
        self.contacts.apply_palette(palette)
        self.messages.apply_palette(palette)
        self.empty_state.apply_palette(palette)
        self.input_shell.apply_palette(palette)
        self.new_button.apply_palette(palette)
        self.send_button.apply_palette(palette)
        self.motion_switch.apply_palette(palette)
        self.self_avatar.online_color = palette.online
        self.header_avatar.online_color = palette.online
        self.self_avatar.update()
        self.header_avatar.update()
        self.typing_dots.set_color(palette.text_secondary)
        muted = palette.text_secondary
        hover = palette.bg_hover
        for button in (self.emoji_button, self.attach_button, self.more_button, self.back_button, self.compose_button, self.search_icon):
            button.apply_colors(muted, hover)
        for nav, active in (
            (self.nav_chat, self.page_chat.isVisible()),
            (self.nav_contacts, self.page_contacts.isVisible()),
            (self.nav_moments, self.page_moments.isVisible()),
            (self.nav_box, self.page_box.isVisible()),
            (self.nav_settings, self.page_settings.isVisible()),
        ):
            nav.apply_nav(palette.accent, palette.accent_soft, muted, hover)
            nav.set_active(active)
        self.profile_settings.apply_palette(palette.accent, palette.accent_text)
        for name, button in self.theme_buttons.items():
            if name == self.theme or (palette.name == name):
                button.setStyleSheet(
                    f"QPushButton {{ background:{palette.accent}; color:{palette.accent_text}; border-radius:10px; }}"
                )
            else:
                button.setStyleSheet(
                    f"QPushButton {{ background:{palette.bg_input}; color:{palette.text}; border:1px solid {palette.border}; border-radius:10px; }}"
                )
        if self._fp is not None:
            self._fp.apply_palette(palette)
        self._refresh_badges()

    def _show_page(self, index: int) -> None:
        titles = ("聊天", "联系人", "朋友圈", "投递箱", "设置")
        self.side_title.setText(titles[index])
        for i, page in enumerate(self._stack):
            page.setVisible(i == index)
        self._social_open = index in (2, 3)
        if index == 2:
            self.main_stack.setCurrentWidget(self.moment_board)
        elif index == 3:
            self.main_stack.setCurrentWidget(self.drop_board)
        else:
            self.main_stack.setCurrentWidget(self.chat)
        self.compose_button.setVisible(index in (0, 1))
        self.search.setVisible(index in (0, 1))
        self.search_icon.setVisible(index in (0, 1))
        self.search.setPlaceholderText("搜索用户名或昵称" if index == 1 else "搜索")
        if index in (2, 3, 4) and not self._compact:
            self.splitter.setSizes([400, 740])
        if self._palette:
            self._set_palette(self._palette)
        if index == 1:
            self.rebuild_contacts()
            self._fill_people()
        self._apply_responsive()

    def set_reduce_motion(self, enabled: bool) -> None:
        self._reduce_motion = enabled
        self.conversations.set_reduce_motion(enabled)
        self.contacts.set_reduce_motion(enabled)
        if hasattr(self, "send_button"):
            self._refresh_send()
        self.worker.submit("set_ui", reduce_motion="1" if enabled else "0")

    def update_snapshot(self, data: dict[str, Any]) -> None:
        self.snapshot_data = data
        if not self.search.text().strip():
            self.rebuild_conversations()
        if self.page_contacts.isVisible():
            self.rebuild_contacts()
        self._fill_people()
        if "profile" in data and data.get("profile"):
            self.profile_settings.set_profile(data["profile"])
            profile = data["profile"]
            self.self_avatar.set_person(
                str(profile.get("display_name") or self.username),
                online=True,
                avatar=str(profile.get("avatar") or ""),
            )
        if "privacy" in data and data.get("privacy"):
            self.profile_settings.set_privacy(data["privacy"])
        self.moment_board.set_moments(list(data.get("moments") or []))
        self.drop_board.set_items(list(data.get("dropbox") or []))
        if self.current_conv:
            self.update_header()
        self._refresh_badges()

    def rebuild_conversations(self) -> None:
        recent = {row["conv"]: row for row in self.snapshot_data.get("recent", [])}
        keys = set(recent)
        keys.update(f"group:{name}" for name in self.snapshot_data.get("groups", {}))
        keys.update(f"dm:{name}" for name in self.snapshot_data.get("sessions", {}))
        if self.current_conv:
            keys.add(self.current_conv)
        ordered = sorted(
            keys,
            key=lambda key: (
                0 if key in self._pins else 1,
                -(recent.get(key, {}).get("ts", 0)),
                key,
            ),
        )
        online = set(self.snapshot_data.get("online", []))
        items: list[ConvItem] = []
        for conv in ordered:
            row = recent.get(conv, {})
            kind = "group" if str(conv).startswith("group:") else "dm"
            peer = conv[3:] if kind == "dm" else conv[6:]
            person = self._person(peer) if kind == "dm" else {}
            items.append(
                ConvItem(
                    key=conv,
                    title=str(person.get("display_name") or self.conv_title(conv)),
                    preview=str(row.get("body", "")),
                    ts=float(row.get("ts", 0) or 0),
                    online=kind == "dm" and peer in online,
                    unread=self.unread.get(conv, 0),
                    pinned=conv in self._pins,
                    muted=conv in self._mutes,
                    kind=kind,
                    clock=list_clock(float(row.get("ts", 0) or 0)),
                    avatar=str(person.get("avatar") or ""),
                )
            )
        self.conversations.set_items(items, self.current_conv)

    def rebuild_contacts(self) -> None:
        names = set(self.snapshot_data.get("online", []))
        names.update(self.snapshot_data.get("sessions", {}))
        for members in self.snapshot_data.get("groups", {}).values():
            names.update(members)
        names.update(self.directory)
        names.discard(self.username)
        online = set(self.snapshot_data.get("online", []))
        query = self.search.text().strip().lower() if self.page_contacts.isVisible() else ""
        items = []
        for name in sorted(names):
            if query and query not in name.lower():
                continue
            items.append(
                ConvItem(
                    key=f"dm:{name}",
                    title=name,
                    preview="在线" if name in online else "离线",
                    online=name in online,
                    kind="contact",
                )
            )
        self.contacts.set_items(items)

    def _person(self, username: str) -> dict[str, Any]:
        for bucket in ("friends", "incoming", "outgoing", "blocked", "rejected"):
            for item in self.snapshot_data.get(bucket) or []:
                if item.get("username") == username:
                    return item
        profile = self.snapshot_data.get("profile") or {}
        if profile.get("username") == username:
            return profile
        return {}

    def _dm_allowed(self, peer: str) -> bool:
        if "friends" not in self.snapshot_data:
            return True
        return any(item.get("username") == peer for item in self.snapshot_data.get("friends") or [])

    def _fill_people(self) -> None:
        if "friends" not in self.snapshot_data:
            self.people_panel.hide()
            self.contacts.show()
            return
        self.contacts.hide()
        self.people_panel.show()
        query = self.search.text().strip()
        self.people_panel.set_model(
            friends=list(self.snapshot_data.get("friends") or []),
            incoming=list(self.snapshot_data.get("incoming") or []),
            outgoing=list(self.snapshot_data.get("outgoing") or []),
            blocked=list(self.snapshot_data.get("blocked") or []),
            rejected=list(self.snapshot_data.get("rejected") or []),
            results=self._search_results if query else [],
        )

    def _refresh_badges(self) -> None:
        total = sum(self.unread.values())
        self.nav_chat.set_badge(total)
        incoming = self.snapshot_data.get("incoming") or []
        self.nav_contacts.set_badge(len(incoming) if "friends" in self.snapshot_data else 0)

    @staticmethod
    def conv_title(conv: str) -> str:
        return conv[6:] if conv.startswith("group:") else conv[3:]

    def _activate_key(self, key: str) -> None:
        if self._search_mode:
            self._search_mode = False
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
        self.open_conversation(key)

    def _activate_contact(self, key: str) -> None:
        if key.startswith("dm:"):
            self.worker.submit("open_chat", username=key[3:])

    def open_conversation(self, conv: str) -> None:
        if self._in_open:
            return
        self._in_open = True
        try:
            self.current_conv = conv
            self.unread[conv] = 0
            self._pending_new = 0
            self.new_button.set_count(0)
            self.worker.submit("mark_read", unread=self.unread)
            self.worker.submit("set_ui", current_conv=conv)
            self._pane = "chat"
            self.info_button.setEnabled(conv.startswith("dm:"))
            self.update_header()
            self._apply_responsive()
            self.worker.submit("history", conv=conv)
            if not self._search_mode:
                self.rebuild_conversations()
            else:
                self.conversations.select_key(conv, animate=False)
            self._refresh_send()
            self.composer.setFocus()
        finally:
            self._in_open = False

    def update_header(self) -> None:
        if not self.current_conv:
            self.chat_title.setText("选择一个会话")
            self.chat_subtitle.setText("消息只在本机解密")
            return
        conv = self.current_conv
        if conv.startswith("dm:"):
            peer = conv[3:]
            online = peer in set(self.snapshot_data.get("online", []))
            generation = self.snapshot_data.get("sessions", {}).get(peer, 0)
            short_fp = self.snapshot_data.get("fingerprints", {}).get(peer, "")
            fp_text = f" · 指纹 {short_fp}" if short_fp else ""
            person = self._person(peer)
            self.chat_title.setText(str(person.get("display_name") or peer))
            self.chat_subtitle.setText(f"{'在线' if online else '离线'} · 双棘轮代数 {generation}{fp_text}")
            self.header_avatar.set_person(
                str(person.get("display_name") or peer),
                online=online,
                avatar=str(person.get("avatar") or ""),
            )
        else:
            name = conv[6:]
            members = self.snapshot_data.get("groups", {}).get(name, [])
            self.chat_title.setText(name)
            self.chat_subtitle.setText(f"{len(members)} 位成员 · 逐成员双棘轮加密")
            self.header_avatar.set_person(name, group=True)
        self._sync_typing_visibility()

    def show_history(self, conv: str, rows: list[dict[str, Any]]) -> None:
        if conv != self.current_conv:
            return
        items: list[ChatItem] = []
        bubbles: dict[str, MessageBubble] = {}
        self._append_rows(items, rows, bubbles)
        for pending in self.snapshot_data.get("pending", []):
            if pending.get("conv") != conv:
                continue
            local_id = str(pending["local_id"])
            self._append_rows(
                items,
                [
                    {
                        "sender": self.username,
                        "body": pending["body"],
                        "ts": pending["ts"],
                        "state": pending["state"],
                        "local_id": local_id,
                    }
                ],
                bubbles,
            )
        finalize_groups(items, is_group=conv.startswith("group:"))
        self.bubbles = bubbles
        self.messages.set_messages(items)
        self.empty_state.setVisible(False)
        self.messages.setVisible(True)
        self._pending_new = 0
        self.new_button.set_count(0)
        if not self._reduce_motion:
            self._play_switch()
        QTimer.singleShot(0, lambda: self.messages.smooth_scroll_to_bottom(animated=False))
        self._place_overlays()

    def _append_rows(self, items: list[ChatItem], rows: list[dict[str, Any]], bubbles: dict[str, MessageBubble]) -> None:
        conv = self.current_conv or ""
        for row in rows:
            sender = str(row.get("sender", ""))
            raw = str(row.get("body", ""))
            ts = float(row.get("ts") or time.time())
            local_id = str(row.get("local_id") or "")
            if hidden_key(conv, sender, ts, raw) in self._hidden:
                continue
            kind = classify_row(sender, raw, str(row.get("kind") or ""))
            day = day_label(ts)
            if not items or items[-1].kind == "date" or getattr(self, "_last_day", None) != day:
                if not items or items[-1].body != day or items[-1].kind != "date":
                    if not any(item.kind == "date" and item.body == day for item in items):
                        items.append(ChatItem(kind="date", body=day, ts=ts, key=f"date:{day}:{len(items)}"))
            author, quote, text = ("", "", raw)
            if kind == "message":
                author, quote, text = decode_reply(raw)
            item = ChatItem(
                sender=sender,
                mine=sender == self.username and kind == "message",
                ts=ts,
                kind=kind,
                body=text if kind == "message" else raw,
                raw=raw,
                state=str(row.get("state") or "accepted"),
                local_id=local_id,
                reply_author=author,
                reply_text=quote,
                hint=security_hint(raw) or "",
                key=local_id or f"{ts:.3f}:{sender}:{len(items)}:{raw[:12]}",
                anim=1.0,
            )
            items.append(item)
            if local_id:
                bubbles[local_id] = MessageBubble(item, self._on_bubble_state, self)

    def append_message(
        self,
        sender: str,
        body: str,
        timestamp: float,
        mine: bool,
        state: str = "accepted",
        kind: str = "chat",
        local_id: str | None = None,
        animate: bool = True,
    ) -> MessageBubble:
        mapped = classify_row(sender, body, "error" if kind == "error" else kind)
        if kind == "error":
            mapped = "security"
        author, quote, text = ("", "", body)
        if mapped == "message":
            author, quote, text = decode_reply(body)
        item = ChatItem(
            sender=sender,
            mine=mine and mapped == "message",
            ts=timestamp,
            kind=mapped,
            body=text if mapped == "message" else body,
            raw=body,
            state=state,
            local_id=local_id or "",
            reply_author=author,
            reply_text=quote,
            hint=security_hint(body) or "",
            key=local_id or uuid.uuid4().hex,
            anim=0.0 if animate and not self._reduce_motion else 1.0,
        )
        items = [existing for existing in self.messages.items() if existing.kind != "typing"]
        day = day_label(timestamp)
        if not any(existing.kind == "date" and existing.body == day for existing in items):
            items.append(ChatItem(kind="date", body=day, ts=timestamp, key=f"date:{day}"))
        items.append(item)
        if self._typing and not mine:
            items.append(ChatItem(kind="typing", key="typing", sender=sender))
        finalize_groups(items, is_group=bool(self.current_conv and self.current_conv.startswith("group:")))
        was_bottom = self.messages.at_bottom() or mine or not self.messages.items()
        self.messages.set_messages(items)
        bubble = MessageBubble(item, self._on_bubble_state, self)
        if local_id:
            self.bubbles[local_id] = bubble
        if item.anim < 1:
            self._animate_item(item)
        if mine or was_bottom:
            self._pending_new = 0
            self.new_button.set_count(0)
            QTimer.singleShot(0, lambda: self.messages.smooth_scroll_to_bottom(not self._reduce_motion))
        else:
            self._pending_new += 1
            self.new_button.set_count(self._pending_new)
        self.empty_state.setVisible(False)
        self.messages.setVisible(True)
        return bubble

    def _animate_item(self, item: ChatItem) -> None:
        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setDuration(220)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        def step(value: object) -> None:
            item.anim = float(value)
            row = self._row_of(item)
            if row >= 0:
                self.messages.notify_row(row)

        anim.valueChanged.connect(step)
        anim.start()
        self._msg_anim = anim

    def _row_of(self, item: ChatItem) -> int:
        for index, current in enumerate(self.messages.items()):
            if current is item:
                return index
        return -1

    def _on_bubble_state(self, item: ChatItem) -> None:
        row = self._row_of(item)
        if row >= 0:
            self.messages.delegate.invalidate()
            self.messages.notify_row(row)

    def _play_switch(self) -> None:
        from PySide6.QtWidgets import QGraphicsOpacityEffect

        effect = QGraphicsOpacityEffect(self.messages)
        effect.setOpacity(0.0)
        self.messages.setGraphicsEffect(effect)
        self.messages.move(0, 8)
        fade = QVariantAnimation(self)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setDuration(180)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)

        def step(value: object) -> None:
            ratio = float(value)
            effect.setOpacity(ratio)
            self.messages.move(0, int(8 * (1 - ratio)))

        def done() -> None:
            self.messages.setGraphicsEffect(None)
            self._place_overlays()

        fade.valueChanged.connect(step)
        fade.finished.connect(done)
        self._switch_anim = fade
        fade.start()

    def send_current(self) -> None:
        text = self.composer.toPlainText()
        if not self.current_conv or not text.strip():
            if not self.current_conv and text.strip():
                self.show_toast("先选择一个聊天")
            return
        if len(text.encode("utf-8")) > 48 * 1024:
            self.show_toast("消息过长；加密信封必须小于 64KB", error=True)
            return
        if self.current_conv.startswith("dm:") and not self._dm_allowed(self.current_conv[3:]):
            self.show_toast("需要对方同意好友申请后才能发消息", error=True)
            return
        if self.reply_bar.author:
            text = encode_reply(self.reply_bar.author, self.reply_bar.quote, text.strip())
            self.reply_bar.clear_reply()
        self.composer.clear()
        self.emoji_panel.hide()
        local_id = uuid.uuid4().hex
        self.append_message(
            self.username,
            text,
            time.time(),
            mine=True,
            state="sending",
            local_id=local_id,
        )
        self.worker.submit("send", local_id=local_id, conv=self.current_conv, text=text)
        self._refresh_send()

    def on_message_state(self, local_id: str, state: str, error: str) -> None:
        bubble = self.bubbles.get(local_id)
        if bubble:
            bubble.set_state(state)
        if state == "failed":
            self.show_toast(f"发送失败：{error}", error=True)

    def on_incoming(self, item: dict[str, Any]) -> None:
        if item.get("kind") in {"presence", "social", "moment"}:
            return
        if item.get("kind") == "typing":
            self.set_peer_typing(True, str(item.get("sender") or ""))
            return
        group = item.get("group")
        sender = str(item.get("sender") or "")
        conv = f"group:{group}" if group else (f"dm:{sender}" if sender and sender != "系统" else "")
        body = str(item.get("text") or item.get("error") or "")
        kind = "error" if item.get("error") else str(item.get("kind") or "chat")
        if conv and conv == self.current_conv:
            self.set_peer_typing(False)
            self.append_message(sender, body, time.time(), mine=False, kind=kind, animate=True)
        elif conv:
            if conv not in self._mutes:
                self.unread[conv] = self.unread.get(conv, 0) + 1
            self.worker.submit("mark_read", unread=self.unread)
            self.rebuild_conversations()
        if item.get("error"):
            self.show_toast(str(item["error"]), error=True)

    def set_peer_typing(self, typing: bool, name: str = "") -> None:
        self._typing = typing
        self._sync_typing_visibility()
        self.typing_dots.set_running(typing)
        if typing:
            if self._typing_anim.state() != QVariantAnimation.State.Running:
                self._typing_anim.start()
        else:
            self._typing_anim.stop()
        items = [item for item in self.messages.items() if item.kind != "typing"]
        if typing and self.current_conv:
            items.append(ChatItem(kind="typing", key="typing", sender=name))
            self.messages.set_messages(items)
            if self.messages.at_bottom():
                QTimer.singleShot(0, lambda: self.messages.smooth_scroll_to_bottom(False))
        elif self.messages.items() and any(item.kind == "typing" for item in self.messages.items()):
            self.messages.set_messages(items)

    def _sync_typing_visibility(self) -> None:
        self.chat_subtitle.setVisible(not self._typing)
        self.typing_dots.setVisible(self._typing)
        self.typing_label.setVisible(self._typing)

    def _on_typing_phase(self, value: object) -> None:
        self.messages.typing_phase = float(value)
        for row, item in enumerate(self.messages.items()):
            if item.kind == "typing":
                self.messages.notify_row(row)

    def perform_search(self) -> None:
        if self.page_contacts.isVisible():
            if "friends" in self.snapshot_data:
                self.worker.submit("search_users", query=self.search.text().strip())
            else:
                self.rebuild_contacts()
            return
        query = self.search.text().strip()
        if not query:
            self._search_mode = False
            self.rebuild_conversations()
            return
        self.worker.submit("search", query=query)

    def show_search_results(self, rows: list[dict[str, Any]]) -> None:
        if not self.search.text().strip() or self.page_contacts.isVisible():
            return
        self._search_mode = True
        items = []
        for row in rows:
            conv = str(row["conv"])
            items.append(
                ConvItem(
                    key=conv,
                    title=self.conv_title(conv),
                    preview=str(row["body"]),
                    ts=float(row["ts"]),
                    kind="group" if conv.startswith("group:") else "dm",
                    clock=list_clock(float(row["ts"])),
                )
            )
        self.conversations.set_items(items)

    def _compose_menu(self) -> None:
        from PySide6.QtWidgets import QMenu

        if self.page_contacts.isVisible():
            self._add_friend_dialog()
            return
        menu = QMenu(self)
        chat = menu.addAction("新建聊天")
        group = menu.addAction("创建群聊")
        chosen = menu.exec(self.compose_button.mapToGlobal(QPoint(0, self.compose_button.height())))
        if chosen is chat:
            self.new_chat()
        elif chosen is group:
            self.new_group()

    def new_chat(self) -> None:
        name = self._ask("新建聊天", [("对方用户名", "bob")])
        if name:
            self.worker.submit("open_chat", username=name[0].strip())

    def new_group(self) -> None:
        values = self._ask("创建群聊", [("群名", "三人组"), ("成员", "bob, carol")])
        if not values:
            return
        members = [part.strip() for part in values[1].replace("，", ",").split(",") if part.strip()]
        self.worker.submit("create_group", name=values[0].strip(), members=members)

    def _ask(self, title: str, fields: list[tuple[str, str]]) -> list[str] | None:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setStyleSheet(stylesheet(self._palette))
        dialog.setMinimumWidth(380)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        heading = QLabel(title)
        heading.setObjectName("title")
        layout.addWidget(heading)
        edits = []
        for label, placeholder in fields:
            caption = QLabel(label)
            caption.setObjectName("secondary")
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            layout.addWidget(caption)
            layout.addWidget(edit)
            edits.append(edit)
        buttons = QHBoxLayout()
        cancel = QPushButton("取消")
        ok = QPushButton("确定")
        ok.setObjectName("primary")
        cancel.clicked.connect(dialog.reject)
        ok.clicked.connect(dialog.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(ok)
        layout.addLayout(buttons)
        dialog.setWindowOpacity(0)
        fade = QVariantAnimation(dialog)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setDuration(180)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        fade.valueChanged.connect(lambda value: dialog.setWindowOpacity(float(value)))
        dialog.show()
        fade.start()
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return [edit.text() for edit in edits]

    def show_fingerprint(self) -> None:
        if self.current_conv and self.current_conv.startswith("dm:"):
            self.worker.submit("fingerprint", username=self.current_conv[3:])

    def _show_fingerprint_card(self, username: str, fingerprint: str) -> None:
        if self._fp is None:
            overlay = BlurDialog(self.centralWidget(), username)
            card_layout = QVBoxLayout(overlay.card)
            card_layout.setContentsMargins(24, 22, 24, 20)
            card_layout.setSpacing(8)
            self._fp_title = QLabel()
            self._fp_title.setObjectName("title")
            self._fp_title.setWordWrap(True)
            self._fp_hint = QLabel("请用线下渠道核对这 16 组。不一致就不要继续聊。")
            self._fp_hint.setObjectName("secondary")
            self._fp_hint.setWordWrap(True)
            self._fp_body = QLabel()
            self._fp_body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._fp_body.setFont(ui_font(15))
            copy = QPushButton("复制指纹")
            copy.setObjectName("primary")
            copy.clicked.connect(self._copy_fingerprint)
            close = QPushButton("关闭")
            close.clicked.connect(overlay.dismiss)
            card_layout.addWidget(self._fp_title)
            card_layout.addWidget(self._fp_hint)
            card_layout.addWidget(self._fp_body)
            card_layout.addWidget(copy)
            card_layout.addWidget(close)
            overlay.card.setFixedSize(420, 280)
            self._fp = overlay
            self._fp.apply_palette(self._palette)
        self._fp_value = fingerprint
        self._fp_title.setText(f"{username} 的身份指纹")
        groups = fingerprint.split()
        lines = ["  ".join(groups[index : index + 4]) for index in range(0, len(groups), 4)]
        self._fp_body.setText("\n".join(lines))
        self._fp.present()

    def _copy_fingerprint(self) -> None:
        QGuiApplication.clipboard().setText(self._fp_value)
        self.show_toast("指纹已复制")

    def on_action_result(self, action: str, ok: bool, data: object) -> None:
        if not ok:
            self.show_toast(str(data), error=True)
            return
        if action == "open_chat":
            self._show_page(0)
            self.open_conversation(f"dm:{data}")
        elif action == "create_group":
            self._show_page(0)
            self.open_conversation(f"group:{data}")
        elif action == "fingerprint" and isinstance(data, dict):
            self._show_fingerprint_card(str(data["username"]), str(data["fingerprint"]))
        elif action == "users" and isinstance(data, dict):
            self.directory = [str(name) for name in data.get("users") or []]
            self.rebuild_contacts()
        elif action == "search_users" and isinstance(data, dict):
            self._search_results = list(data.get("users") or [])
            self._fill_people()
        elif action == "friend_request":
            self.show_toast("好友申请已发送")
        elif action == "friend_respond":
            self.show_toast("已处理好友申请")
        elif action == "friend_remove":
            self.show_toast("关系已更新")
        elif action == "friend_block":
            self.show_toast("已拉黑")
        elif action == "profile_set":
            self.show_toast("资料已保存")
        elif action == "privacy_set":
            self.show_toast("隐私已保存")
        elif action == "moment_post":
            self.show_toast("已发布到朋友圈")
        elif action in {"moment_delete", "moment_like", "moment_comment"}:
            self.moment_board.set_moments(list(self.snapshot_data.get("moments") or []))

    def on_connection(self, connected: bool, text: str) -> None:
        self._connected = connected
        if connected:
            self.banner.set_mode("hidden", text)
        elif "重连" in text or "正在" in text:
            self.banner.set_mode("warn", text)
        else:
            self.banner.set_mode("error", text)
        self._refresh_send()

    def on_fatal(self, text: str) -> None:
        self.show_toast(text, error=True)

    def show_toast(self, text: str, error: bool = False) -> None:
        palette = self._palette
        bg = palette.danger_bg if error else palette.bg_card
        fg = palette.danger_text if error else palette.text
        border = palette.danger if error else palette.border
        self.toast.setText(text)
        self.toast.setStyleSheet(
            f"background:{bg};color:{fg};border:1px solid {border};border-radius:12px;padding:10px 16px;font-size:13px;"
        )
        self.toast.adjustSize()
        self.toast.move(
            max(16, (self.width() - self.toast.width()) // 2),
            max(48, self.height() - self.toast.height() - 96),
        )
        self.toast.show()
        self.toast.raise_()
        if not self._reduce_motion:
            anim = QVariantAnimation(self)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.setDuration(160)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            anim.valueChanged.connect(lambda value: self.toast.setWindowOpacity(float(value)) if False else None)
            self._toast_anim = anim
            anim.start()
        self.toast_timer.start(3200)

    def _refresh_send(self) -> None:
        has_text = bool(self.composer.toPlainText().strip())
        self.send_button.set_active(has_text, animate=not self._reduce_motion)
        self.send_button.setToolTip("发送" if has_text else "语音")

    def _send_or_mic(self) -> None:
        if self.composer.toPlainText().strip():
            self.send_current()
        else:
            self.show_toast("按住说话还没做，先发文字吧")

    def _toggle_emoji(self) -> None:
        if self.emoji_panel.isVisible():
            self.emoji_panel.hide()
            return
        point = self.emoji_button.mapTo(self.chat, QPoint(0, -self.emoji_panel.height() - 8))
        self.emoji_panel.move(max(8, point.x()), max(8, point.y()))
        self.emoji_panel.show()
        self.emoji_panel.raise_()

    def _insert_emoji(self, emoji: str) -> None:
        self.composer.insert_text(emoji)
        self.emoji_panel.hide()
        self._refresh_send()

    def _attach(self) -> None:
        if not self.current_conv:
            self.show_toast("先打开一个会话，再投递文件")
            return
        if self.current_conv.startswith("dm:") and not self._dm_allowed(self.current_conv[3:]):
            self.show_toast("需要对方同意好友申请后才能发消息", error=True)
            return
        path, _selected = QFileDialog.getOpenFileName(self, "投递文件")
        if not path:
            return
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            self.show_toast(f"读不到这个文件：{exc}", error=True)
            return
        if not data:
            self.show_toast("不能投递空文件", error=True)
            return
        if len(data) > 24 * 1024:
            self.show_toast("投递箱单文件不超过 24KB", error=True)
            return
        name = Path(path).name
        local_id = uuid.uuid4().hex
        self.append_message(
            self.username,
            f"[文件] {name}",
            time.time(),
            mine=True,
            state="sending",
            local_id=local_id,
        )
        self.worker.submit(
            "send_file",
            local_id=local_id,
            conv=self.current_conv,
            name=name,
            data=base64.b64encode(data).decode("ascii"),
        )

    def _open_drop(self, path: str) -> None:
        if not path or not Path(path).is_file():
            self.show_toast("文件不在本机了", error=True)
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _save_profile(self, display_name: str, bio: str, avatar: str) -> None:
        self.worker.submit(
            "profile_set",
            display_name=display_name,
            bio=bio,
            avatar=avatar,
        )

    def _save_privacy(self, privacy: object) -> None:
        if not isinstance(privacy, dict):
            return
        self.worker.submit("privacy_set", **privacy)

    def _add_friend_dialog(self) -> None:
        values = self._ask("添加好友", [("用户名", "bob"), ("验证消息", "你好")])
        if not values or not values[0].strip():
            return
        self.worker.submit(
            "friend_request",
            username=values[0].strip(),
            greeting=values[1].strip(),
        )

    def _add_named(self, username: str) -> None:
        values = self._ask("添加好友", [("验证消息", f"你好，我是{self.username}")])
        if values is None:
            return
        self.worker.submit(
            "friend_request",
            username=username,
            greeting=values[0].strip(),
        )

    def _more_menu(self) -> None:
        from PySide6.QtWidgets import QMenu

        menu = QMenu(self)
        search = menu.addAction("搜索")
        pin = menu.addAction("置顶会话")
        mute = menu.addAction("静音")
        theme = menu.addAction(f"切换主题 · {THEME_LABELS.get(next_theme(self.theme), '')}")
        chosen = menu.exec(self.more_button.mapToGlobal(QPoint(0, self.more_button.height())))
        if chosen is search:
            self._focus_search()
        elif chosen is pin and self.current_conv:
            self._conv_menu(self.current_conv, "pin")
        elif chosen is mute and self.current_conv:
            self._conv_menu(self.current_conv, "mute")
        elif chosen is theme:
            self.apply_theme(next_theme(self.theme))

    def _conv_menu(self, key: str, action: str) -> None:
        target = self._pins if action == "pin" else self._mutes
        if key in target:
            target.remove(key)
        else:
            target.add(key)
        self.worker.submit(
            "set_ui",
            pins=json.dumps(sorted(self._pins), ensure_ascii=False),
            mutes=json.dumps(sorted(self._mutes), ensure_ascii=False),
        )
        self.rebuild_conversations()

    def _focus_search(self) -> None:
        if self._compact and self._pane == "chat":
            self._back()
        self._show_page(0)
        self.search.setFocus()
        self.search.selectAll()

    def _back(self) -> None:
        if self._social_open:
            self._show_page(0)
            return
        self._pane = "list"
        self._apply_responsive()

    def _jump_bottom(self) -> None:
        self._pending_new = 0
        self.new_button.set_count(0)
        self.messages.smooth_scroll_to_bottom(not self._reduce_motion)

    def _retry(self, local_id: str) -> None:
        bubble = self.bubbles.get(local_id)
        if bubble is None or not self.current_conv:
            return
        bubble.set_state("sending")
        self.worker.submit("send", local_id=local_id, conv=self.current_conv, text=bubble.item.raw)

    def _copy_item(self, item: ChatItem) -> None:
        QGuiApplication.clipboard().setText(item.raw or item.body)
        self.show_toast("已复制")

    def _reply_to(self, item: ChatItem) -> None:
        if not item.body:
            return
        self.reply_bar.set_reply(item.sender or "对方", item.body)
        self.composer.setFocus()

    def _delete_item(self, item: ChatItem) -> None:
        if not self.current_conv:
            return
        self._hidden.add(hidden_key(self.current_conv, item.sender, item.ts, item.raw or item.body))
        self.worker.submit("set_ui", hidden=json.dumps(sorted(self._hidden), ensure_ascii=False))
        if item.local_id and item.local_id in self.bubbles:
            del self.bubbles[item.local_id]
        kept = [current for current in self.messages.items() if current is not item and current.kind != "typing"]
        kept = [current for index, current in enumerate(kept) if not (current.kind == "date" and (index + 1 == len(kept) or kept[index + 1].kind == "date"))]
        finalize_groups(kept, is_group=self.current_conv.startswith("group:"))
        self.messages.set_messages(kept)

    def message_group_flags(self) -> list[tuple[bool, bool, bool, str]]:
        return group_flags(self.messages.items())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._apply_responsive()
        self._place_overlays()
        if self.toast.isVisible():
            self.toast.move(
                max(16, (self.width() - self.toast.width()) // 2),
                max(48, self.height() - self.toast.height() - 96),
            )
        if self._fp is not None:
            self._fp.resize_to_parent()

    def _apply_responsive(self) -> None:
        compact = self.width() < 800
        self._compact = compact
        social = self._social_open
        show_chat = bool(self.current_conv) and self._pane == "chat" and not social
        self.back_button.setVisible(compact and (show_chat or social))
        if compact:
            self.nav.setVisible(False)
            if social:
                self.sidebar.setVisible(True)
                self.main_stack.setVisible(True)
            else:
                self.sidebar.setVisible(not show_chat)
                self.main_stack.setVisible(show_chat)
        else:
            self.nav.setVisible(True)
            self.sidebar.setVisible(True)
            self.main_stack.setVisible(True)
            self.back_button.setVisible(False)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._place_overlays()
        self.empty_state.setVisible(self.current_conv is None)
        self.messages.setVisible(self.current_conv is not None)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.worker.stop_async()
        self.worker.wait(3000)
        event.accept()


def _load_set(raw: object) -> set[str]:
    if not raw:
        return set()
    try:
        value = json.loads(str(raw))
    except json.JSONDecodeError:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()
