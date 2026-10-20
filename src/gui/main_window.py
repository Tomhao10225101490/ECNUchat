"""桌面主窗口。左列是会话列表，右列是聊天。加密仍走 ChatEngine。"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEasingCurve, QEvent, QPoint, QRectF, Qt, QTimer, QUrl, QVariantAnimation, Signal
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QDesktopServices,
    QGuiApplication,
    QImageReader,
    QKeySequence,
    QPainter,
    QPainterPath,
    QPixmap,
)
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

import src.gui.widgets as gui_widgets
from src import PROJECT_NAME
from src.gui.app_pages import DropboxBoard, MomentBoard, MomentComposer, PeoplePanel, ProfileSettings
from src.attachments import MAX_FILE_BYTES, format_size, guess_mime, media_kind
from src.protocol import ProtocolError, validate_group_name
from src.gui.chat_view import ConvItem, ConversationList, MessageList, group_flags
from src.gui.icons import paint_icon
from src.gui.people import ContactBook, PeoplePicker, build_directory, people_from_snapshot
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
    MenuRow,
    MessageBubble,
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


class _PreviewThumb(QWidget):
    """圆角封面。图片铺满裁切，视频和文件画类型标记。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(56, 56)
        self._pix = QPixmap()
        self._kind = "file"
        self._accent = "#4BA0F5"
        self._ink = "#FFFFFF"

    def set_content(self, pixmap: QPixmap | None, kind: str, accent: str, ink: str) -> None:
        self._kind = kind
        self._accent = accent
        self._ink = ink
        self._pix = QPixmap()
        if pixmap is not None and not pixmap.isNull():
            dpr = self.devicePixelRatioF() or 1.0
            side = max(56, int(56 * dpr))
            scaled = pixmap.scaled(
                side,
                side,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = max(0, (scaled.width() - side) // 2)
            y = max(0, (scaled.height() - side) // 2)
            cropped = scaled.copy(x, y, min(side, scaled.width()), min(side, scaled.height()))
            cropped.setDevicePixelRatio(dpr)
            self._pix = cropped
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            rect = QRectF(0, 0, self.width(), self.height())
            path = QPainterPath()
            path.addRoundedRect(rect, 14, 14)
            painter.setClipPath(path)
            if self._pix is not None and not self._pix.isNull():
                painter.drawPixmap(self.rect(), self._pix)
            else:
                painter.fillRect(self.rect(), QColor("#1C2733" if self._kind == "video" else self._accent))
                if self._kind == "video":
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.setBrush(QColor(255, 255, 255, 230))
                    triangle = QPainterPath()
                    cx, cy = self.width() / 2, self.height() / 2
                    triangle.moveTo(cx - 6, cy - 9)
                    triangle.lineTo(cx + 10, cy)
                    triangle.lineTo(cx - 6, cy + 9)
                    triangle.closeSubpath()
                    painter.drawPath(triangle)
                else:
                    paint_icon(
                        painter,
                        "paperclip",
                        QRectF(16, 16, 24, 24),
                        self._ink,
                        self.devicePixelRatioF(),
                    )
            painter.setClipping(False)
            painter.setPen(QColor(255, 255, 255, 40))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), 14, 14)
        finally:
            painter.end()


class FilePreviewBar(QWidget):
    """发送前的文件卡片：圆角封面、类型和大小，可以滑出取消。"""

    cleared = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("filePreview")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._anim: QVariantAnimation | None = None
        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 10, 12, 4)
        outer.setSpacing(0)
        self.card = QFrame()
        self.card.setObjectName("previewCard")
        self.card.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QHBoxLayout(self.card)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)
        self.thumb = _PreviewThumb()
        self.title = ElideLabel()
        self.title.setObjectName("name")
        self.meta = QLabel()
        self.meta.setObjectName("secondary")
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(self.title)
        text.addWidget(self.meta)
        self.cancel = IconButton("close", 32, 16)
        self.cancel.setToolTip("移除")
        self.cancel.clicked.connect(self.cleared.emit)
        layout.addWidget(self.thumb)
        layout.addLayout(text, 1)
        layout.addWidget(self.cancel)
        outer.addWidget(self.card)
        self.hide()

    def show_file(
        self,
        name: str,
        size_text: str,
        pixmap: QPixmap | None,
        kind: str,
        *,
        reduce_motion: bool = False,
        accent: str = "#4BA0F5",
        ink: str = "#FFFFFF",
    ) -> None:
        labels = {"image": "图片", "video": "视频", "file": "文件"}
        self.title.setText(name)
        self.title.setToolTip(name)
        self.meta.setText(f"{labels.get(kind, '文件')} · {size_text}")
        self.thumb.set_content(pixmap, kind, accent, ink)
        already = self.isVisible() and self.maximumHeight() > 20
        self.show()
        target = max(self.sizeHint().height(), 88)
        self._slide(self.height() if already else 0, target, reduce_motion, hide=False)

    def apply_palette(self, palette: Palette) -> None:
        self.thumb.set_content(self.thumb._pix, self.thumb._kind, palette.accent, palette.accent_text)
        self.cancel.apply_colors(palette.text_secondary, palette.bg_hover)

    def dismiss(self, reduce_motion: bool = False) -> None:
        if not self.isVisible():
            return
        self._slide(self.height(), 0, reduce_motion, hide=True)

    def _slide(self, start: int, end: int, reduce_motion: bool, *, hide: bool) -> None:
        if self._anim is not None:
            self._anim.stop()
        if reduce_motion:
            self.setMaximumHeight(16777215)
            if hide:
                self.hide()
            else:
                self.show()
            return
        self.setMaximumHeight(max(0, start))
        anim = QVariantAnimation(self)
        anim.setStartValue(max(0, start))
        anim.setEndValue(max(0, end))
        anim.setDuration(180)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.valueChanged.connect(lambda value: self.setMaximumHeight(max(0, int(value))))

        def finish() -> None:
            self.setMaximumHeight(16777215)
            if hide:
                self.hide()

        anim.finished.connect(finish)
        self._anim = anim
        anim.start()


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
        self._group_hits: list[dict[str, Any]] = []
        self._history_hits: list[dict[str, Any]] = []
        self._typing = False
        self._pending_new = 0
        self._hidden = _load_set(initial.get("hidden", ""))
        self._pins = _load_set(initial.get("pins", ""))
        self._mutes = _load_set(initial.get("mutes", ""))
        self.directory: list[str] = []
        self._theme_anim: QVariantAnimation | None = None
        self._theme_from = self._palette
        self._fp: BlurDialog | None = None
        self._fp_value = ""
        self._staged: dict[str, Any] | None = None
        self.setWindowTitle(f"{PROJECT_NAME} — {self.username}")
        self.resize(1180, 760)
        self.setMinimumSize(420, 560)
        self._build()
        self._connect_worker()
        self.apply_theme(self.theme, persist=False, animate=False)
        self.update_snapshot(initial)
        self.update_header()
        self.banner.set_mode("hidden" if self._connected else "error", "" if self._connected else "未连接")
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

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(1)
        body.addWidget(self.splitter, 1)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.sidebar.setMinimumWidth(260)
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(0, 0, 0, 0)
        side.setSpacing(0)
        self.side_head = QWidget()
        self.side_head.setFixedHeight(56)
        head_layout = QHBoxLayout(self.side_head)
        head_layout.setContentsMargins(4, 8, 8, 8)
        head_layout.setSpacing(2)
        self.menu_button = IconButton("menu", 40, 20)
        self.menu_button.setToolTip("菜单")
        self.menu_button.clicked.connect(self._toggle_menu)
        self.side_back = IconButton("back", 40, 18)
        self.side_back.setToolTip("返回")
        self.side_back.clicked.connect(lambda: self._show_page(0))
        self.side_back.hide()
        self.side_title = QLabel("聊天")
        self.side_title.setObjectName("title")
        self.side_title.hide()
        self.compose_button = IconButton("plus", 36, 18)
        self.compose_button.setToolTip("新建")
        self.compose_button.clicked.connect(self._compose_menu)
        self.search = QLineEdit()
        self.search.setObjectName("searchField")
        self.search.setPlaceholderText("搜索")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedHeight(36)
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(200)
        self.search_timer.timeout.connect(self.perform_search)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        head_layout.addWidget(self.menu_button)
        head_layout.addWidget(self.side_back)
        head_layout.addWidget(self.side_title, 1)
        head_layout.addWidget(self.search, 1)
        head_layout.addWidget(self.compose_button)
        side.addWidget(self.side_head)

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
        self.contacts = ContactBook()
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
        self.people_panel.addClicked.connect(
            lambda name: self.worker.submit("friend_request", username=name, greeting="")
        )
        self.people_panel.groupAcceptClicked.connect(
            lambda name: self.worker.submit("group_respond", group=name, accept=True)
        )
        self.people_panel.groupRejectClicked.connect(
            lambda name: self.worker.submit("group_respond", group=name, accept=False)
        )
        self.people_panel.groupApproveClicked.connect(
            lambda group, username: self.worker.submit(
                "group_approve", group=group, username=username, accept=True
            )
        )
        self.people_panel.groupDenyClicked.connect(
            lambda group, username: self.worker.submit(
                "group_deny", group=group, username=username
            )
        )
        self.people_panel.groupJoinClicked.connect(
            lambda name: self.worker.submit("group_join", group=name)
        )
        self.people_panel.groupOpenClicked.connect(self._open_known_group)
        self.people_panel.hide()
        contacts_layout.addWidget(self.people_panel)
        contacts_layout.addWidget(self.contacts, 1)

        self.page_moments = MomentComposer()
        self.page_moments.postRequested.connect(
            lambda body, image, visibility: self.worker.submit(
                "moment_post", body=body, image=image, visibility=visibility
            )
        )
        self.page_box = QWidget()
        box_layout = QVBoxLayout(self.page_box)
        box_layout.setContentsMargins(8, 4, 8, 8)
        box_button = QPushButton("发送文件")
        box_button.setCursor(Qt.CursorShape.PointingHandCursor)
        box_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        box_button.clicked.connect(self._attach)
        box_layout.addWidget(box_button, alignment=Qt.AlignmentFlag.AlignLeft)
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
        self.menu_panel = self._build_menu()
        self.side_stack = QStackedWidget()
        self.side_stack.setAutoFillBackground(False)
        self.pages.setAutoFillBackground(False)
        self.menu_panel.setAutoFillBackground(False)
        self.side_stack.addWidget(self.pages)
        self.side_stack.addWidget(self.menu_panel)
        side.addWidget(self.side_stack, 1)
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
        self.header.setFixedHeight(56)
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
        self.chat_title = ElideLabel("")
        self.chat_title.setObjectName("title")
        self.chat_subtitle = ElideLabel("")
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
        self.info_button = QPushButton("指纹", self)
        self.info_button.hide()
        self.info_button.setEnabled(False)
        self.info_button.clicked.connect(self.show_fingerprint)
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
        self.messages.openRequested.connect(self._open_attachment)
        self.messages.filesDropped.connect(self._on_files_dropped)
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
        self.file_preview = FilePreviewBar()
        self.file_preview.cleared.connect(self._clear_staged)
        chat_layout.addWidget(self.file_preview)
        self.invite_bar = QWidget()
        self.invite_bar.setObjectName("composer")
        self.invite_bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        invite_layout = QHBoxLayout(self.invite_bar)
        invite_layout.setContentsMargins(12, 10, 12, 12)
        invite_layout.setSpacing(8)
        self.invite_text = QLabel("")
        self.invite_text.setWordWrap(True)
        self.invite_text.setObjectName("secondary")
        self.invite_ok = QPushButton("同意")
        self.invite_ok.setObjectName("primary")
        self.invite_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.invite_no = QPushButton("拒绝")
        self.invite_no.setCursor(Qt.CursorShape.PointingHandCursor)
        self.invite_ok.clicked.connect(self._invite_accept)
        self.invite_no.clicked.connect(self._invite_reject)
        invite_layout.addWidget(self.invite_text, 1)
        invite_layout.addWidget(self.invite_no)
        invite_layout.addWidget(self.invite_ok)
        self.invite_bar.hide()
        chat_layout.addWidget(self.invite_bar)
        chat_layout.addWidget(self.composer_bar)
        self.composer.installEventFilter(self)
        self.moment_board = MomentBoard()
        self.moment_board.likeClicked.connect(
            lambda moment_id: self.worker.submit("moment_like", id=moment_id)
        )
        self.moment_board.commentClicked.connect(
            lambda moment_id, body: self.worker.submit("moment_comment", id=moment_id, body=body)
        )
        self.moment_board.deleteClicked.connect(
            lambda moment_id: self.worker.submit("moment_delete", id=moment_id)
        )
        self.drop_board = DropboxBoard()
        self.drop_board.openRequested.connect(
            lambda path: QDesktopServices.openUrl(QUrl.fromLocalFile(path)) if path else None
        )
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

    def _build_menu(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 4, 0, 8)
        layout.setSpacing(0)
        profile = QHBoxLayout()
        profile.setContentsMargins(16, 8, 16, 14)
        profile.setSpacing(12)
        self.self_avatar = AvatarWidget(54)
        self.self_avatar.set_person(self.username, online=True)
        text = QVBoxLayout()
        text.setSpacing(0)
        self.menu_name = QLabel(self.username)
        self.menu_name.setObjectName("name")
        self.menu_handle = QLabel(self.username)
        self.menu_handle.setObjectName("caption")
        text.addWidget(self.menu_name)
        text.addWidget(self.menu_handle)
        profile.addWidget(self.self_avatar)
        profile.addLayout(text, 1)
        layout.addLayout(profile)
        hair = QFrame()
        hair.setObjectName("hair")
        layout.addWidget(hair)
        layout.addSpacing(6)
        rows = (
            ("chat", "聊天", 0),
            ("contacts", "联系人", 1),
            ("moments", "朋友圈", 2),
            ("box", "文件", 3),
            ("settings", "设置", 4),
        )
        built: list[MenuRow] = []
        for icon, label, index in rows:
            row = MenuRow(icon, label)
            row.clicked.connect(lambda _checked=False, page=index: self._show_page(page))
            layout.addWidget(row)
            built.append(row)
        self.nav_chat, self.nav_contacts, self.nav_moments, self.nav_box, self.nav_settings = built
        layout.addStretch(1)
        return panel

    def _toggle_menu(self) -> None:
        if self.side_stack.currentWidget() is self.menu_panel:
            self.side_stack.setCurrentWidget(self.pages)
            return
        self._set_palette(self._palette)
        self.side_stack.setCurrentWidget(self.menu_panel)

    def _build_settings(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 12)
        layout.setSpacing(2)
        hint = QLabel("主题")
        hint.setObjectName("section")
        hint.setContentsMargins(16, 4, 16, 0)
        layout.addWidget(hint)
        theme_row = QHBoxLayout()
        theme_row.setContentsMargins(12, 0, 12, 4)
        theme_row.setSpacing(2)
        self.theme_buttons: dict[str, QPushButton] = {}
        for name in THEME_ORDER:
            button = QPushButton(THEME_LABELS[name])
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setFixedHeight(32)
            button.clicked.connect(lambda _checked=False, theme=name: self.apply_theme(theme))
            self.theme_buttons[name] = button
            theme_row.addWidget(button)
        theme_row.addStretch(1)
        layout.addLayout(theme_row)
        row = QHBoxLayout()
        row.setContentsMargins(16, 6, 16, 6)
        label = QLabel("减少动态效果")
        self.motion_switch = ToggleSwitch()
        self.motion_switch.setChecked(self._reduce_motion)
        self.motion_switch.toggled.connect(self.set_reduce_motion)
        row.addWidget(label)
        row.addStretch(1)
        row.addWidget(self.motion_switch)
        layout.addLayout(row)
        self.profile_settings = ProfileSettings()
        self.profile_settings.profileSaved.connect(
            lambda name, bio, avatar: self.worker.submit(
                "profile_set", display_name=name, bio=bio, avatar=avatar
            )
        )
        self.profile_settings.privacySaved.connect(
            lambda privacy: self.worker.submit("privacy_set", **dict(privacy))
        )
        layout.addWidget(self.profile_settings)
        about = QLabel(PROJECT_NAME)
        about.setObjectName("caption")
        about.setContentsMargins(16, 18, 16, 0)
        layout.addWidget(about)
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
        if watched is self.composer and event.type() == QEvent.Type.KeyPress:
            if event.matches(QKeySequence.StandardKey.Paste) and self._paste_image():
                return True
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
        self.worker.fileProgress.connect(self.on_file_progress)

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
        gui_widgets.AVATAR_RING = palette.bg_side
        self.self_avatar.online_color = palette.online
        self.header_avatar.online_color = palette.online
        self.self_avatar.ring = palette.bg_nav
        self.header_avatar.ring = palette.bg_header
        self.self_avatar.update()
        self.header_avatar.update()
        self.typing_dots.set_color(palette.text_secondary)
        muted = palette.text_secondary
        hover = palette.bg_hover
        for button in (
            self.emoji_button,
            self.attach_button,
            self.more_button,
            self.back_button,
            self.compose_button,
            self.menu_button,
            self.side_back,
            self.file_preview.cancel,
        ):
            button.apply_colors(muted, hover)
        self.file_preview.apply_palette(palette)
        for nav, active in (
            (self.nav_chat, self.page_chat.isVisible()),
            (self.nav_contacts, self.page_contacts.isVisible()),
            (self.nav_moments, self.page_moments.isVisible()),
            (self.nav_box, self.page_box.isVisible()),
            (self.nav_settings, self.page_settings.isVisible()),
        ):
            nav.apply_nav(palette.accent, palette.text, muted, hover, palette.unread)
            nav.set_active(active)
        self.profile_settings.apply_palette(palette.accent, palette.accent_text)
        for name, button in self.theme_buttons.items():
            chosen = name == self.theme or palette.name == name
            color = palette.accent if chosen else palette.text
            weight = "600" if chosen else "400"
            button.setStyleSheet(
                "QPushButton {"
                f"background:transparent; color:{color}; border:none; border-radius:0; "
                f"padding:6px 10px; font-weight:{weight};"
                "}"
                f"QPushButton:hover {{ background:{palette.bg_hover}; }}"
            )
        if self._fp is not None:
            self._fp.apply_palette(palette)
        self._refresh_badges()

    def _show_page(self, index: int) -> None:
        titles = ("聊天", "联系人", "朋友圈", "文件", "设置")
        self.side_title.setText(titles[index])
        for i, page in enumerate(self._stack):
            page.setVisible(i == index)
        if index == 2:
            self.main_stack.setCurrentWidget(self.moment_board)
        elif index == 3:
            self.main_stack.setCurrentWidget(self.drop_board)
        else:
            self.main_stack.setCurrentWidget(self.chat)
        on_chats = index == 0
        on_contacts = index == 1
        self.menu_button.setVisible(on_chats)
        self.side_back.setVisible(not on_chats)
        self.side_title.setVisible(not on_chats and not on_contacts)
        self.compose_button.setVisible(index in (0, 1))
        self.compose_button.setToolTip("新建消息" if index == 0 else "新建")
        searching = index in (0, 1)
        self.search.setVisible(searching)
        if hasattr(self, "side_stack"):
            self.side_stack.setCurrentWidget(self.pages)
        self.search.blockSignals(True)
        self.search.clear()
        self.search.setPlaceholderText("搜索")
        self.search.blockSignals(False)
        if self._palette:
            self._set_palette(self._palette)
        if index == 1:
            self.rebuild_contacts()
            self._fill_people()

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
        if "moments" in data:
            self.moment_board.set_moments(list(data.get("moments") or []))
        conv = self.current_conv or ""
        if conv.startswith("invite:") and conv[7:] in self.snapshot_data.get("groups", {}):
            self.open_conversation(f"group:{conv[7:]}")
        elif conv.startswith("joining:") and conv[8:] in self.snapshot_data.get("groups", {}):
            self.open_conversation(f"group:{conv[8:]}")
        if "dropbox" in data:
            self.drop_board.set_items(list(data.get("dropbox") or []))
        if "profile" in data and hasattr(self, "profile_settings"):
            profile = dict(data.get("profile") or {})
            self.profile_settings.set_profile(profile)
            self.profile_settings.set_privacy(dict(data.get("privacy") or {}))
            display = str(profile.get("display_name") or self.username)
            self.menu_name.setText(display)
            self.self_avatar.set_person(display, online=True, avatar=str(profile.get("avatar") or ""))
        if self.current_conv:
            self.update_header()
        self._refresh_badges()

    def rebuild_conversations(self) -> None:
        recent = {row["conv"]: row for row in self.snapshot_data.get("recent", [])}
        keys = set(recent)
        groups = self.snapshot_data.get("groups", {})
        keys.update(f"group:{name}" for name in groups)
        keys.update(f"dm:{name}" for name in self.snapshot_data.get("sessions", {}))
        for item in self.snapshot_data.get("group_incoming") or []:
            name = str(item.get("group") or "")
            if name and name not in groups:
                keys.add(f"invite:{name}")
        for item in self.snapshot_data.get("group_joining") or []:
            name = str(item.get("group") or "")
            if name and name not in groups:
                keys.add(f"joining:{name}")
        for item in self.snapshot_data.get("group_requests") or []:
            name = str(item.get("group") or "")
            user = str(item.get("username") or "")
            if name and user:
                keys.add(f"request:{user}:{name}")
        if self.current_conv and not str(self.current_conv).startswith(("find:", "wait:")):
            keys.add(self.current_conv)
        ordered = sorted(
            keys,
            key=lambda key: (
                0 if key in self._pins else 1,
                0 if str(key).startswith(("invite:", "request:")) else 1,
                -(recent.get(key, {}).get("ts", 0)),
                key,
            ),
        )
        online = set(self.snapshot_data.get("online", []))
        items: list[ConvItem] = []
        for conv in ordered:
            row = recent.get(conv, {})
            kind = "dm" if str(conv).startswith("dm:") else "group"
            peer = conv[3:] if kind == "dm" else ""
            preview = str(row.get("body", "") or "")
            if str(conv).startswith("invite:"):
                preview = preview or self._invite_preview(conv[7:])
            elif str(conv).startswith("request:"):
                user, _group = self._split_request(conv)
                preview = preview or f"{user} 申请加入"
            elif str(conv).startswith("joining:"):
                preview = preview or "正在加入"
            elif kind == "group" and not preview:
                preview = "还没有消息"
            items.append(
                ConvItem(
                    key=conv,
                    title=self.conv_title(conv),
                    preview=preview,
                    ts=float(row.get("ts", 0) or 0),
                    online=kind == "dm" and peer in online,
                    unread=self.unread.get(conv, 0),
                    pinned=conv in self._pins,
                    muted=conv in self._mutes,
                    kind=kind,
                    clock=list_clock(float(row.get("ts", 0) or 0)),
                )
            )
        self.conversations.set_items(items, self.current_conv)

    def known_people(self) -> list[dict]:
        data = dict(self.snapshot_data)
        data["directory"] = list(self.directory)
        return people_from_snapshot(data, self.username)

    def rebuild_contacts(self) -> None:
        query = self.search.text().strip() if self.page_contacts.isVisible() else ""
        groups = sorted(str(name) for name in self.snapshot_data.get("groups", {}))
        self.contacts.set_entries(build_directory(self.known_people(), groups, query))
        if query:
            self.contacts.empty.setText("没有匹配的联系人")
        else:
            self.contacts.empty.setText("没有联系人")

    def _fill_people(self) -> None:
        if "friends" not in self.snapshot_data:
            self.people_panel.hide()
            return
        self.people_panel.show()
        query = self.search.text().strip().lower() if self.page_contacts.isVisible() else ""
        invites = list(self.snapshot_data.get("group_incoming") or [])
        outgoing = list(self.snapshot_data.get("group_outgoing") or [])
        requests = list(self.snapshot_data.get("group_requests") or [])
        if query:
            invites = [
                item
                for item in invites
                if query in str(item.get("group") or "").lower()
                or query in str(item.get("inviter") or "").lower()
            ]
            outgoing = [
                item
                for item in outgoing
                if query in str(item.get("group") or "").lower()
                or query in str(item.get("username") or "").lower()
            ]
            requests = [
                item
                for item in requests
                if query in str(item.get("group") or "").lower()
                or query in str(item.get("username") or "").lower()
            ]
        self.people_panel.set_model(
            friends=list(self.snapshot_data.get("friends") or []),
            incoming=list(self.snapshot_data.get("incoming") or []),
            outgoing=list(self.snapshot_data.get("outgoing") or []),
            blocked=list(self.snapshot_data.get("blocked") or []),
            rejected=list(self.snapshot_data.get("rejected") or []),
            group_invites=invites,
            group_outgoing=outgoing,
            group_requests=requests,
            group_results=list(self._group_hits) if query else [],
        )

    def _dm_allowed(self, username: str) -> bool:
        if "friends" not in self.snapshot_data:
            return True
        return any(
            str(item.get("username")) == username
            for item in self.snapshot_data.get("friends") or []
        )

    def _refresh_badges(self) -> None:
        total = sum(self.unread.values())
        self.nav_chat.set_badge(total)
        if "friends" in self.snapshot_data:
            pending = len(self.snapshot_data.get("incoming") or [])
            pending += len(self.snapshot_data.get("group_incoming") or [])
            pending += len(self.snapshot_data.get("group_requests") or [])
            self.nav_contacts.set_badge(pending)

    @staticmethod
    def conv_title(conv: str) -> str:
        if conv.startswith("invite:"):
            return conv[7:]
        if conv.startswith("joining:"):
            return conv[8:]
        if conv.startswith("find:"):
            return conv[5:]
        if conv.startswith("wait:"):
            return conv[5:]
        if conv.startswith("request:"):
            return conv.split(":", 2)[-1]
        if conv.startswith("group:"):
            return conv[6:]
        if conv.startswith("dm:"):
            return conv[3:]
        return conv

    @staticmethod
    def _split_request(conv: str) -> tuple[str, str]:
        user, _sep, group = conv[len("request:") :].partition(":")
        if not group:
            return "", user
        return user, group

    def _invite_preview(self, name: str) -> str:
        for item in self.snapshot_data.get("group_incoming") or []:
            if str(item.get("group") or "") == name:
                return f"{item.get('inviter') or '好友'} 邀请你加入"
        return "邀请你加入"

    def _activate_key(self, key: str) -> None:
        if key.startswith("find:"):
            self.worker.submit("group_join", group=key[5:])
            return
        if key.startswith("wait:"):
            self.show_toast("已申请，等待对方同意")
            return
        if self._search_mode:
            self._search_mode = False
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
        self.open_conversation(key)

    def _activate_contact(self, key: str) -> None:
        if key.startswith("dm:"):
            self.worker.submit("open_chat", username=key[3:])
        elif key.startswith("group:"):
            self._show_page(0)
            self.open_conversation(key)

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
            if conv.startswith(("dm:", "group:")):
                self.worker.submit("history", conv=conv)
            else:
                self.messages.set_messages([])
                self.bubbles.clear()
            self.empty_state.hide()
            self.messages.show()
            if not self._search_mode:
                self.rebuild_conversations()
            else:
                self.conversations.select_key(conv, animate=False)
            self._refresh_send()
            if conv.startswith(("dm:", "group:")):
                self.composer.setFocus()
        finally:
            self._in_open = False

    def update_header(self) -> None:
        if not self.current_conv:
            self.chat_title.setText("")
            self.chat_subtitle.setText("")
            self.header_avatar.hide()
            self.info_button.setEnabled(False)
            self.info_button.hide()
            self.composer_bar.hide()
            self.invite_bar.hide()
            return
        self.header_avatar.show()
        conv = self.current_conv
        pending = conv.startswith(("invite:", "request:"))
        self.composer_bar.setVisible(conv.startswith(("dm:", "group:")))
        self.invite_bar.setVisible(pending)
        self.info_button.setEnabled(conv.startswith("dm:"))
        self.info_button.hide()
        if conv.startswith("dm:"):
            peer = conv[3:]
            online = peer in set(self.snapshot_data.get("online", []))
            generation = self.snapshot_data.get("sessions", {}).get(peer, 0)
            short_fp = self.snapshot_data.get("fingerprints", {}).get(peer, "")
            fp_text = f" · 指纹 {short_fp}" if short_fp else ""
            self.chat_title.setText(peer)
            self.chat_subtitle.setText(f"{'在线' if online else '离线'} · 双棘轮代数 {generation}{fp_text}")
            self.header_avatar.set_person(peer, online=online)
        elif conv.startswith("invite:"):
            name = conv[7:]
            self.chat_title.setText(name)
            self.chat_subtitle.setText("等待你同意")
            self.header_avatar.set_person(name, group=True)
            self.invite_text.setText(self._invite_preview(name))
            self.invite_ok.setText("同意")
            self.invite_no.show()
        elif conv.startswith("request:"):
            user, name = self._split_request(conv)
            self.chat_title.setText(name)
            self.chat_subtitle.setText(f"{user} 申请加入")
            self.header_avatar.set_person(name, group=True)
            self.invite_text.setText(f"同意 {user} 加入 {name}")
            self.invite_ok.setText("同意")
            self.invite_no.show()
        elif conv.startswith("joining:"):
            name = conv[8:]
            self.chat_title.setText(name)
            self.chat_subtitle.setText("正在加入")
            self.header_avatar.set_person(name, group=True)
        else:
            name = conv[6:] if conv.startswith("group:") else conv
            members = self.snapshot_data.get("groups", {}).get(name, [])
            self.chat_title.setText(name)
            self.chat_subtitle.setText(f"{len(members)} 位成员")
            self.header_avatar.set_person(name, group=True)
        self._sync_typing_visibility()

    def _invite_accept(self) -> None:
        conv = self.current_conv or ""
        if conv.startswith("invite:"):
            self.worker.submit("group_respond", group=conv[7:], accept=True)
        elif conv.startswith("request:"):
            user, group = self._split_request(conv)
            self.worker.submit("group_approve", group=group, username=user, accept=True)

    def _invite_reject(self) -> None:
        conv = self.current_conv or ""
        if conv.startswith("invite:"):
            self.worker.submit("group_respond", group=conv[7:], accept=False)
        elif conv.startswith("request:"):
            user, group = self._split_request(conv)
            self.worker.submit("group_deny", group=group, username=user)

    def _open_known_group(self, name: str) -> None:
        self._show_page(0)
        self.open_conversation(f"group:{name}")

    def show_history(self, conv: str, rows: list[dict[str, Any]]) -> None:
        if conv != self.current_conv:
            return
        items: list[ChatItem] = []
        bubbles: dict[str, MessageBubble] = {}
        self._append_rows(items, rows, bubbles)
        extra: list[dict[str, Any]] = []
        for pending in self.snapshot_data.get("pending", []):
            if pending.get("conv") != conv:
                continue
            local_id = str(pending["local_id"])
            matched = None
            for item in items:
                if item.local_id == local_id:
                    matched = item
                    break
                if (
                    matched is None
                    and item.kind == "message"
                    and item.mine
                    and not item.local_id
                    and item.raw == str(pending.get("body") or "")
                ):
                    matched = item
            if matched is not None:
                matched.state = str(pending.get("state") or matched.state)
                matched.local_id = local_id
                matched.key = local_id
                pending_attachment = pending.get("attachment")
                if matched.attachment is None and isinstance(pending_attachment, dict):
                    matched.attachment = pending_attachment
                    matched.body = str(pending_attachment.get("caption") or matched.body)
                if matched.attachment and matched.state == "sending":
                    matched.progress = max(0.0, matched.progress)
                bubbles[local_id] = MessageBubble(matched, self._on_bubble_state, self)
                continue
            extra.append(
                {
                    "sender": self.username,
                    "body": pending["body"],
                    "ts": pending["ts"],
                    "state": pending["state"],
                    "local_id": local_id,
                    "attachment": pending.get("attachment"),
                }
            )
        if extra:
            self._append_rows(items, extra, bubbles)
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
            attachment = row.get("attachment") if isinstance(row.get("attachment"), dict) else None
            shown = str(attachment.get("caption") or "") if attachment else raw
            if hidden_key(conv, sender, ts, raw) in self._hidden:
                continue
            kind = classify_row(sender, shown, str(row.get("kind") or ""))
            day = day_label(ts)
            if not items or items[-1].kind == "date" or getattr(self, "_last_day", None) != day:
                if not items or items[-1].body != day or items[-1].kind != "date":
                    if not any(item.kind == "date" and item.body == day for item in items):
                        items.append(ChatItem(kind="date", body=day, ts=ts, key=f"date:{day}:{len(items)}"))
            author, quote, text = ("", "", shown)
            if kind == "message":
                author, quote, text = decode_reply(shown)
            state = str(row.get("state") or "accepted")
            item = ChatItem(
                sender=sender,
                mine=sender == self.username and kind == "message",
                ts=ts,
                kind=kind,
                body=text if kind == "message" else shown,
                raw=raw,
                state=state,
                local_id=local_id,
                reply_author=author,
                reply_text=quote,
                hint=security_hint(shown) or "",
                key=local_id or f"{ts:.3f}:{sender}:{len(items)}:{raw[:12]}",
                anim=1.0,
                attachment=attachment,
                progress=0.0 if attachment and state == "sending" else -1.0,
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
        attachment: dict[str, Any] | None = None,
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
            attachment=attachment,
            progress=0.0 if attachment and state == "sending" else -1.0,
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
        if self._staged:
            self._send_staged()
            return
        text = self.composer.toPlainText()
        if not self.current_conv or not text.strip():
            if not self.current_conv and text.strip():
                self.show_toast("先选择一个聊天")
            return
        if len(text.encode("utf-8")) > 48 * 1024:
            self.show_toast("消息过长；加密信封必须小于 64KB", error=True)
            return
        if not self.current_conv.startswith(("dm:", "group:")):
            self.show_toast("先同意加入，才能在群里发消息", error=True)
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

    def on_file_progress(self, local_id: str, done: int, total: int) -> None:
        bubble = self.bubbles.get(local_id)
        if bubble is None or total <= 0:
            return
        bubble.item.progress = max(0.0, min(1.0, done / total))
        self.messages.delegate.invalidate()
        row = self._row_of(bubble.item)
        if row >= 0:
            self.messages.notify_row(row)

    def on_incoming(self, item: dict[str, Any]) -> None:
        if item.get("kind") == "presence":
            return
        if item.get("kind") == "typing":
            self.set_peer_typing(True, str(item.get("sender") or ""))
            return
        local_id = str(item.get("local_id") or "")
        if item.get("kind") == "file_abort":
            self._drop_live_file(local_id)
            return
        group = item.get("group")
        sender = str(item.get("sender") or "")
        conv = f"group:{group}" if group else (f"dm:{sender}" if sender and sender != "系统" else "")
        attachment = item.get("attachment") if isinstance(item.get("attachment"), dict) else None
        if item.get("error"):
            attachment = None
            body = str(item.get("error") or "")
        elif attachment:
            body = str(attachment.get("caption") or "")
        else:
            body = str(item.get("text") or "")
        kind = "error" if item.get("error") else str(item.get("kind") or "chat")
        if kind == "file_progress":
            if conv and conv == self.current_conv and attachment and local_id:
                self._upsert_incoming_file(local_id, sender, attachment, "sending", create=True)
            return
        if kind == "file" and attachment and local_id:
            if self._upsert_incoming_file(
                local_id,
                sender,
                attachment,
                "accepted",
                create=bool(conv and conv == self.current_conv),
            ):
                if conv == self.current_conv:
                    self.set_peer_typing(False)
                return
        if conv and conv == self.current_conv:
            self.set_peer_typing(False)
            self.append_message(
                sender,
                body,
                time.time(),
                mine=False,
                kind=kind,
                animate=True,
                attachment=attachment,
            )
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
        query = self.search.text().strip()
        if self.page_contacts.isVisible():
            if not query:
                self._group_hits = []
            self.rebuild_contacts()
            self._fill_people()
            if query:
                self.worker.submit("search_groups", query=query)
            return
        if not query:
            self._search_mode = False
            self._group_hits = []
            self._history_hits = []
            self.rebuild_conversations()
            return
        self._search_mode = True
        self._history_hits = []
        self._render_search()
        self.worker.submit("search", query=query)
        self.worker.submit("search_groups", query=query)

    def show_search_results(self, rows: list[dict[str, Any]]) -> None:
        if not self.search.text().strip() or self.page_contacts.isVisible():
            return
        self._history_hits = list(rows)
        self._search_mode = True
        self._render_search()

    def _local_search_rows(self, query: str) -> list[dict[str, Any]]:
        needle = query.strip().lower()
        rows: list[dict[str, Any]] = []
        for name in self.snapshot_data.get("groups", {}):
            if needle in str(name).lower():
                rows.append({"conv": f"group:{name}", "body": "群聊", "ts": 0})
        for item in self.snapshot_data.get("group_incoming") or []:
            name = str(item.get("group") or "")
            inviter = str(item.get("inviter") or "")
            if name and (needle in name.lower() or needle in inviter.lower()):
                rows.append({"conv": f"invite:{name}", "body": f"{inviter} 邀请你加入", "ts": 0})
        for person in self.known_people():
            name = str(person.get("name") or "")
            if name and needle in name.lower():
                rows.append({"conv": f"dm:{name}", "body": "联系人", "ts": 0})
        return rows

    def _rows_from_group_hits(self, query: str) -> list[dict[str, Any]]:
        needle = query.strip().lower()
        rows: list[dict[str, Any]] = []
        for item in self._group_hits:
            name = str(item.get("name") or "")
            if not name or needle not in name.lower():
                continue
            relation = str(item.get("relation") or "")
            if relation == "member":
                rows.append({"conv": f"group:{name}", "body": "群聊", "ts": 0})
            elif relation == "invited":
                inviter = str(item.get("inviter") or "好友")
                rows.append({"conv": f"invite:{name}", "body": f"{inviter} 邀请你加入", "ts": 0})
            elif relation == "requested":
                rows.append({"conv": f"wait:{name}", "body": "已申请，等待对方同意", "ts": 0})
            elif relation == "joining":
                rows.append({"conv": f"joining:{name}", "body": "正在加入", "ts": 0})
            else:
                via = str(item.get("via") or "好友")
                size = item.get("size") or 0
                rows.append(
                    {
                        "conv": f"find:{name}",
                        "body": f"{via} 的群 · {size} 人 · 申请加入",
                        "ts": 0,
                    }
                )
        return rows

    def _render_search(self) -> None:
        query = self.search.text().strip()
        if not query or self.page_contacts.isVisible():
            return
        merged: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in (
            list(self._history_hits)
            + self._local_search_rows(query)
            + self._rows_from_group_hits(query)
        ):
            conv = str(row.get("conv") or "")
            if not conv or conv in seen:
                continue
            seen.add(conv)
            merged.append(row)
        items = [
            ConvItem(
                key=str(row["conv"]),
                title=self.conv_title(str(row["conv"])),
                preview=str(row.get("body") or ""),
                ts=float(row.get("ts") or 0),
                kind="dm" if str(row["conv"]).startswith("dm:") else "group",
                clock=list_clock(float(row.get("ts") or 0)),
            )
            for row in merged
        ]
        self.conversations.set_items(items)

    def _compose_menu(self) -> None:
        from PySide6.QtWidgets import QMenu

        menu = QMenu(self)
        chat = menu.addAction("新建消息")
        group = menu.addAction("新建群组")
        chosen = menu.exec(self.compose_button.mapToGlobal(QPoint(0, self.compose_button.height())))
        if chosen is chat:
            self.new_chat()
        elif chosen is group:
            self.new_group()

    def new_chat(self) -> None:
        picked = self._pick_people("chat")
        if picked:
            self.worker.submit("open_chat", username=picked[0])

    def new_group(self) -> None:
        picked = self._pick_people("group")
        if not picked:
            return
        name, members = picked
        try:
            validate_group_name(name)
        except ProtocolError as exc:
            self.show_toast(str(exc), error=True)
            return
        self.worker.submit("create_group", name=name, members=members)

    def _pick_people(self, mode: str) -> list[str] | tuple[str, list[str]] | None:
        picker = PeoplePicker(self.known_people(), mode=mode, palette=self._palette, parent=self)
        if picker.exec() != QDialog.DialogCode.Accepted:
            return None
        if mode == "chat":
            names = picker.selected()
            return names[:1] or None
        return picker.group_name(), picker.selected()

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
        elif action == "search_groups" and isinstance(data, dict):
            self._group_hits = list(data.get("groups") or [])
            if self.page_contacts.isVisible():
                self._fill_people()
            elif self._search_mode:
                self._render_search()
        elif action in {"group_respond", "group_approve", "group_join", "group_deny"} and isinstance(data, str):
            self.show_toast(data)

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
        bg = palette.danger_bg if error else palette.bg_menu
        fg = palette.danger_text if error else palette.text
        self.toast.setText(text)
        self.toast.setStyleSheet(
            f"background:{bg};color:{fg};border:none;border-radius:8px;padding:8px 14px;font-size:13px;"
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
        has_text = bool(self.composer.toPlainText().strip() or self._staged)
        self.send_button.set_active(has_text, animate=not self._reduce_motion)
        self.send_button.setToolTip("发送" if has_text else "语音")

    def _send_or_mic(self) -> None:
        if self.composer.toPlainText().strip() or self._staged:
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
        path, _selected = QFileDialog.getOpenFileName(
            self,
            "选择附件",
            "",
            "所有文件 (*.*);;图片 (*.png *.jpg *.jpeg *.gif *.webp *.bmp);;视频 (*.mp4 *.mov *.mkv *.webm *.avi)",
        )
        if path:
            self._stage_path(path)

    def _on_files_dropped(self, paths: object) -> None:
        chosen = [str(path) for path in paths] if isinstance(paths, list) else []
        if len(chosen) > 1:
            self.show_toast("一次发一个文件")
        if chosen:
            self._stage_path(chosen[0])

    def _stage_path(self, path: str) -> None:
        file_path = Path(path)
        if not file_path.is_file():
            self.show_toast("找不到这个文件", error=True)
            return
        size = file_path.stat().st_size
        if size > MAX_FILE_BYTES:
            self.show_toast("文件超过 8GiB，发送前已拒绝", error=True)
            return
        mime = guess_mime(file_path.name)
        kind = media_kind(mime)
        pixmap = None
        if kind == "image":
            reader = QImageReader(str(file_path))
            reader.setAutoTransform(True)
            image = reader.read()
            if not image.isNull():
                pixmap = QPixmap.fromImage(image)
        self._staged = {
            "path": str(file_path),
            "name": file_path.name,
            "size": size,
            "mime": mime,
            "media": kind,
        }
        self.file_preview.show_file(
            file_path.name,
            format_size(size),
            pixmap,
            kind,
            reduce_motion=self._reduce_motion,
            accent=self._palette.accent,
            ink=self._palette.accent_text,
        )
        self._refresh_send()

    def _clear_staged(self) -> None:
        self._staged = None
        self.file_preview.dismiss(self._reduce_motion)
        self._refresh_send()

    def _paste_image(self) -> bool:
        clipboard = QGuiApplication.clipboard()
        mime = clipboard.mimeData()
        if mime is None or not mime.hasImage():
            return False
        if mime.hasText() and mime.text().strip():
            return False
        image = clipboard.image()
        if image.isNull():
            return False
        folder = Path(tempfile.gettempdir()) / "ecnuchat-paste"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{uuid.uuid4().hex}.png"
        if not image.save(str(path), "PNG"):
            return False
        self._stage_path(str(path))
        return True

    def _send_staged(self) -> None:
        staged = self._staged
        if staged is None:
            return
        if not self.current_conv:
            self.show_toast("先选择一个聊天")
            return
        caption = self.composer.toPlainText().strip()
        if self.reply_bar.author:
            caption = encode_reply(
                self.reply_bar.author,
                self.reply_bar.quote,
                caption or str(staged["name"]),
            )
            self.reply_bar.clear_reply()
        if len(caption.encode("utf-8")) > 2000:
            self.show_toast("附件说明过长", error=True)
            return
        self.composer.clear()
        self.emoji_panel.hide()
        local_id = uuid.uuid4().hex
        attachment = {
            "name": staged["name"],
            "mime": staged["mime"],
            "size": staged["size"],
            "path": staged["path"],
            "media": staged["media"],
            "caption": caption,
            "sha256": "",
        }
        self.append_message(
            self.username,
            caption,
            time.time(),
            mine=True,
            state="sending",
            local_id=local_id,
            attachment=attachment,
        )
        path = str(staged["path"])
        name = str(staged["name"])
        mime = str(staged["mime"])
        self._clear_staged()
        self.worker.submit(
            "send_file",
            local_id=local_id,
            conv=self.current_conv,
            path=path,
            caption=caption,
            name=name,
            mime=mime,
        )
        self._refresh_send()

    def _open_attachment(self, item: ChatItem) -> None:
        attachment = item.attachment or {}
        path = str(attachment.get("path") or "")
        if not path or not Path(path).is_file():
            self.show_toast("文件不在本机", error=True)
            return
        kind = str(attachment.get("media") or "file")
        if kind == "image":
            self._show_image(path, str(attachment.get("name") or "图片"))
        elif kind == "video":
            self._show_video(path, str(attachment.get("name") or "视频"))
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _show_image(self, path: str, title: str) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(720, 540)
        layout = QVBoxLayout(dialog)
        label = QLabel()
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pixmap = QPixmap(path)
        if not pixmap.isNull():
            screen = self.screen()
            limit = 960
            if screen is not None:
                limit = int(screen.availableGeometry().width() * 0.7)
            label.setPixmap(
                pixmap.scaled(
                    limit,
                    int(limit * 0.75),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        layout.addWidget(label)
        dialog.exec()

    def _show_video(self, path: str, title: str) -> None:
        try:
            from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer
            from PySide6.QtMultimediaWidgets import QVideoWidget
        except Exception:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(960, 540)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(0, 0, 0, 0)
        screen = QVideoWidget(dialog)
        screen.setStyleSheet("background:#111111;")
        screen.setMinimumSize(640, 360)
        layout.addWidget(screen)
        player = QMediaPlayer(dialog)
        audio = QAudioOutput(dialog)
        player.setAudioOutput(audio)
        player.setVideoOutput(screen)

        def on_error(_code, text: str) -> None:
            player.stop()
            dialog.close()
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
            if text:
                self.show_toast(text, error=True)

        player.errorOccurred.connect(on_error)
        player.setSource(QUrl.fromLocalFile(path))
        player.play()
        dialog.finished.connect(player.stop)
        dialog.exec()

    def _find_file_item(self, local_id: str, attachment: dict[str, Any]) -> ChatItem | None:
        bubble = self.bubbles.get(local_id)
        if bubble is not None:
            return bubble.item
        digest = str(attachment.get("sha256") or "")
        name = str(attachment.get("name") or "")
        for current in self.messages.items():
            current_attachment = current.attachment or {}
            if local_id and current.local_id == local_id:
                return current
            if (
                digest
                and current_attachment.get("sha256") == digest
                and current_attachment.get("name") == name
                and current_attachment.get("path")
            ):
                return current
        return None

    def _drop_live_file(self, local_id: str) -> None:
        bubble = self.bubbles.pop(local_id, None)
        if bubble is None:
            return
        kept = [
            current
            for current in self.messages.items()
            if current is not bubble.item and current.kind != "typing"
        ]
        finalize_groups(kept, is_group=bool(self.current_conv and self.current_conv.startswith("group:")))
        self.messages.set_messages(kept)

    def _upsert_incoming_file(
        self,
        local_id: str,
        sender: str,
        attachment: dict[str, Any],
        state: str,
        *,
        create: bool,
    ) -> bool:
        existing = self._find_file_item(local_id, attachment)
        if existing is None:
            if not create:
                return False
            self.append_message(
                sender,
                str(attachment.get("caption") or ""),
                time.time(),
                mine=False,
                state=state,
                kind="file",
                local_id=local_id,
                animate=state == "sending",
                attachment=attachment,
            )
            return True
        existing.attachment = attachment
        existing.state = state
        existing.progress = 0.0 if state == "sending" else 1.0
        caption = str(attachment.get("caption") or "")
        if caption:
            existing.body = caption
        existing.local_id = local_id
        existing.key = local_id
        self.bubbles[local_id] = MessageBubble(existing, self._on_bubble_state, self)
        self.messages.delegate.invalidate()
        row = self._row_of(existing)
        if row >= 0:
            self.messages.notify_row(row)
        self.messages.viewport().update()
        return True

    def _more_menu(self) -> None:
        from PySide6.QtWidgets import QMenu

        menu = QMenu(self)
        search = menu.addAction("搜索")
        fingerprint = menu.addAction("身份指纹")
        fingerprint.setEnabled(bool(self.current_conv and self.current_conv.startswith("dm:")))
        pin = menu.addAction("置顶会话")
        mute = menu.addAction("静音")
        theme = menu.addAction(f"切换主题 · {THEME_LABELS.get(next_theme(self.theme), '')}")
        chosen = menu.exec(self.more_button.mapToGlobal(QPoint(0, self.more_button.height())))
        if chosen is search:
            self._focus_search()
        elif chosen is fingerprint:
            self.show_fingerprint()
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
        attachment = bubble.item.attachment
        if attachment:
            bubble.item.progress = 0.0
            self.worker.submit(
                "send_file",
                local_id=local_id,
                conv=self.current_conv,
                path=str(attachment.get("path") or ""),
                caption=str(attachment.get("caption") or bubble.item.body),
                name=str(attachment.get("name") or ""),
                mime=str(attachment.get("mime") or ""),
            )
            return
        self.worker.submit("send", local_id=local_id, conv=self.current_conv, text=bubble.item.raw)

    def _copy_item(self, item: ChatItem) -> None:
        QGuiApplication.clipboard().setText(item.raw or item.body)
        self.show_toast("已复制")

    def _reply_to(self, item: ChatItem) -> None:
        quote = item.body or str((item.attachment or {}).get("name") or "")
        if not quote:
            return
        self.reply_bar.set_reply(item.sender or "对方", quote)
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
        show_chat = bool(self.current_conv) and self._pane == "chat"
        self.back_button.setVisible(compact and show_chat)
        if compact:
            self.sidebar.setVisible(not show_chat)
            self.main_stack.setVisible(show_chat)
        else:
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
