"""会话列表和消息列表。消息用 QListView 委托绘制，避免一消息一控件。"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import (
    QAbstractListModel,
    QEasingCurve,
    QModelIndex,
    QPoint,
    QRect,
    QRectF,
    QSize,
    Qt,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QImageReader,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QListView,
    QMenu,
    QStyledItemDelegate,
    QStyle,
    QWidget,
)

from src.attachments import format_size
from src.gui.icons import paint_icon
from src.gui.logic import ChatItem, message_clock
from src.gui.theme import PALETTES, RADIUS_BUBBLE, Palette
from src.gui.widgets import elide, install_overlay_scroll, paint_avatar, rounded_path, ui_font

ROW_HEIGHT = 72


@dataclass
class ConvItem:
    key: str
    title: str
    preview: str
    ts: float = 0.0
    online: bool = False
    unread: int = 0
    pinned: bool = False
    muted: bool = False
    kind: str = "dm"
    clock: str = ""
    avatar: str = ""


class ConversationModel(QAbstractListModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.items: list[ConvItem] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.items)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.items):
            return None
        item = self.items[index.row()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.UserRole):
            return item.key if role == Qt.ItemDataRole.UserRole else item.title
        return None

    def item_at(self, row: int) -> ConvItem | None:
        if 0 <= row < len(self.items):
            return self.items[row]
        return None

    def set_items(self, items: list[ConvItem]) -> None:
        self.beginResetModel()
        self.items = list(items)
        self.endResetModel()


class ConversationDelegate(QStyledItemDelegate):
    def __init__(self, view: "ConversationList") -> None:
        super().__init__(view)
        self.view = view
        self.palette = PALETTES["telegram"]
        self.font_name = ui_font(15, QFont.Weight.DemiBold)
        self.font_preview = ui_font(13)
        self.font_time = ui_font(12)
        self.font_badge = ui_font(11, QFont.Weight.DemiBold)

    def apply_palette(self, palette: Palette) -> None:
        self.palette = palette
        self.view.viewport().update()

    def sizeHint(self, _option, _index) -> QSize:
        return QSize(self.view.viewport().width(), ROW_HEIGHT)

    def paint(self, painter: QPainter, option, index) -> None:
        item = self.view.model().item_at(index.row())
        if item is None:
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        rect = option.rect
        selected = index.row() == self.view.currentIndex().row()
        hovered = index.row() == self.view.hover_row and not selected
        if hovered:
            painter.fillRect(rect, QColor(self.palette.bg_hover))
        if selected:
            selection = self.view.selection_rect_for(index.row(), rect)
            if selection is not None:
                painter.setClipRect(rect)
                painter.fillRect(selection, QColor(self.palette.bg_selected))
                painter.setClipping(False)
        text_color = self.palette.text_selected if selected else self.palette.text
        muted = self.palette.text_selected if selected else self.palette.text_secondary
        if selected and self.palette.light and self.palette.name == "wechat":
            muted = "#3F7A34"
        avatar = QRectF(16, rect.y() + 12, 48, 48)
        paint_avatar(
            painter,
            avatar,
            item.title,
            online=item.online and item.kind == "dm",
            group=item.kind == "group",
            online_color=self.palette.online,
            pixel=18,
            avatar=item.avatar,
            ring=self.palette.bg_selected if selected else self.palette.bg_side,
        )
        left = 76
        right_pad = 16
        clock = item.clock
        clock_w = QFontMetrics(self.font_time).horizontalAdvance(clock) + 4 if clock else 0
        name_w = max(20, rect.width() - left - right_pad - clock_w - 8)
        painter.setFont(self.font_name)
        painter.setPen(QColor(text_color))
        painter.drawText(
            QRectF(left, rect.y() + 12, name_w, 22),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            elide(item.title, self.font_name, int(name_w)),
        )
        if clock:
            painter.setFont(self.font_time)
            painter.setPen(QColor(muted))
            painter.drawText(
                QRectF(rect.right() - right_pad - clock_w, rect.y() + 14, clock_w, 18),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                clock,
            )
        badge_w = 0
        label = ""
        if item.unread:
            label = "99+" if item.unread > 99 else str(item.unread)
            badge_w = max(18, QFontMetrics(self.font_badge).horizontalAdvance(label) + 10)
        icons = 0
        if item.pinned:
            icons += 16
        if item.muted:
            icons += 16
        preview_w = max(20, rect.width() - left - right_pad - badge_w - icons - 12)
        painter.setFont(self.font_preview)
        painter.setPen(QColor(muted))
        preview = " ".join((item.preview or "").split()) or " "
        painter.drawText(
            QRectF(left, rect.y() + 36, preview_w, 20),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            elide(preview, self.font_preview, int(preview_w)),
        )
        dpr = self.view.devicePixelRatioF()
        icon_x = left + preview_w + 4
        if item.pinned:
            paint_icon(painter, "pin", QRectF(icon_x, rect.y() + 38, 14, 14), muted, dpr)
            icon_x += 16
        if item.muted:
            paint_icon(painter, "mute", QRectF(icon_x, rect.y() + 38, 14, 14), muted, dpr)
        if item.unread:
            badge = QRectF(rect.right() - right_pad - badge_w, rect.y() + 38, badge_w, 18)
            painter.setPen(Qt.PenStyle.NoPen)
            if selected:
                painter.setBrush(QColor("#FFFFFF"))
            else:
                painter.setBrush(QColor(self.palette.unread))
            painter.drawRoundedRect(badge, 9, 9)
            painter.setPen(QColor(self.palette.unread if selected else "#FFFFFF"))
            painter.setFont(self.font_badge)
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, label)
        painter.restore()


class ConversationList(QListView):
    activated_key = Signal(str)
    context_key = Signal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("conversations")
        self._model = ConversationModel(self)
        self.setModel(self._model)
        self._delegate = ConversationDelegate(self)
        self.setItemDelegate(self._delegate)
        self.setUniformItemSizes(True)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setFrameShape(QListView.Shape.NoFrame)
        self.setMouseTracking(True)
        self.hover_row = -1
        self._reduce_motion = False
        self._from_row = -1
        self._to_row = -1
        self._progress = 1.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._set_progress)
        self._block = False
        self._sel_rect: QRectF | None = None
        self.selectionModel().currentChanged.connect(self._on_current)
        install_overlay_scroll(self)
        self.verticalScrollBar().valueChanged.connect(lambda _v: self._update_sel_rect())
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    def count(self) -> int:
        return self._model.rowCount()

    def apply_palette(self, palette: Palette) -> None:
        self._delegate.apply_palette(palette)
        _paint_viewport(self, palette.bg_side)
        bar = self.verticalScrollBar()
        if hasattr(bar, "set_color"):
            bar.set_color(palette.scroll)
        self.viewport().update()

    def set_reduce_motion(self, enabled: bool) -> None:
        self._reduce_motion = enabled

    def set_items(self, items: list[ConvItem], current: str | None = None) -> None:
        self._block = True
        self._model.set_items(items)
        self._block = False
        if current:
            self.select_key(current, animate=False)
        else:
            self._sel_rect = None
            self.viewport().update()

    def select_key(self, key: str, animate: bool = True) -> None:
        for row, item in enumerate(self._model.items):
            if item.key == key:
                previous = self.currentIndex().row()
                self._block = True
                self.setCurrentIndex(self._model.index(row))
                self._block = False
                self._move_selection(previous, row, animate and previous != row)
                return

    def _on_current(self, current: QModelIndex, previous: QModelIndex) -> None:
        if self._block or not current.isValid():
            return
        self._move_selection(previous.row(), current.row(), True)
        item = self._model.item_at(current.row())
        if item is not None:
            self.activated_key.emit(item.key)

    def _move_selection(self, previous: int, row: int, animate: bool) -> None:
        self._from_row = previous
        self._to_row = row
        if not animate or self._reduce_motion or previous < 0 or previous == row:
            self._progress = 1.0
            self._update_sel_rect()
            return
        self._anim.stop()
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._progress = 0.0
        self._anim.start()

    def _set_progress(self, value: object) -> None:
        self._progress = float(value)
        self._update_sel_rect()

    def _update_sel_rect(self) -> None:
        target = self._to_row if self._to_row >= 0 else self.currentIndex().row()
        if target < 0:
            self._sel_rect = None
            self.viewport().update()
            return
        rect_b = self.visualRect(self._model.index(target))
        if not rect_b.isValid():
            self._sel_rect = None
            self.viewport().update()
            return
        y = rect_b.y()
        if self._from_row >= 0 and self._progress < 1.0:
            rect_a = self.visualRect(self._model.index(self._from_row))
            if rect_a.isValid():
                y = rect_a.y() + (rect_b.y() - rect_a.y()) * self._progress
        self._sel_rect = QRectF(0, y, max(10, self.viewport().width()), ROW_HEIGHT)
        self.viewport().update()

    def selection_rect_for(self, _row: int, row_rect: QRect) -> QRectF | None:
        if self._sel_rect is None or not self._sel_rect.intersects(QRectF(row_rect)):
            return None
        return self._sel_rect

    def mouseMoveEvent(self, event) -> None:
        row = self.indexAt(event.pos()).row()
        if row != self.hover_row:
            self.hover_row = row
            self.viewport().update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        self.hover_row = -1
        self.viewport().update()
        super().leaveEvent(event)

    def _menu(self, pos) -> None:
        index = self.indexAt(pos)
        item = self._model.item_at(index.row())
        if item is None or item.kind == "contact":
            return
        menu = QMenu(self)
        pin = menu.addAction("取消置顶" if item.pinned else "置顶")
        mute = menu.addAction("取消静音" if item.muted else "静音")
        chosen = menu.exec(self.viewport().mapToGlobal(pos))
        if chosen is pin:
            self.context_key.emit(item.key, "pin")
        elif chosen is mute:
            self.context_key.emit(item.key, "mute")


class MessageModel(QAbstractListModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.items: list[ChatItem] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.items)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.items):
            return None
        item = self.items[index.row()]
        if role == Qt.ItemDataRole.UserRole:
            return item
        if role == Qt.ItemDataRole.DisplayRole:
            return item.body
        if role == Qt.ItemDataRole.ToolTipRole and item.kind == "message":
            from src.gui.widgets import STATE_TEXT

            return STATE_TEXT.get(item.state, "")
        return None

    def set_items(self, items: list[ChatItem]) -> None:
        self.beginResetModel()
        self.items = list(items)
        self.endResetModel()

    def notify(self, row: int) -> None:
        if 0 <= row < len(self.items):
            index = self.index(row)
            self.dataChanged.emit(index, index, [])


def _bubble_radii(mine: bool, head: bool, tail: bool) -> tuple[float, float, float, float]:
    big, small = float(RADIUS_BUBBLE), 6.0
    if mine:
        if head and tail:
            return (big, big, small, big)
        if head:
            return (big, big, small, big)
        if tail:
            return (big, small, small, big)
        return (big, small, small, big)
    if head and tail:
        return (big, big, big, small)
    if head:
        return (big, big, big, small)
    if tail:
        return (small, big, big, small)
    return (small, big, big, small)


class MessageDelegate(QStyledItemDelegate):
    def __init__(self, view: "MessageList") -> None:
        super().__init__(view)
        self.view = view
        self.palette = PALETTES["telegram"]
        self.font_body = ui_font(15)
        self.font_name = ui_font(13, QFont.Weight.DemiBold)
        self.font_meta = ui_font(12)
        self.font_system = ui_font(12)
        self._cache: dict[tuple, QSize] = {}
        self._pix: dict[tuple, QPixmap] = {}
        self.fail_rects: dict[int, QRect] = {}
        self.open_rects: dict[int, QRect] = {}

    def apply_palette(self, palette: Palette) -> None:
        self.palette = palette
        self._cache.clear()

    def invalidate(self) -> None:
        self._cache.clear()

    def sizeHint(self, option, index) -> QSize:
        item = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, ChatItem):
            return QSize(10, 8)
        width = option.rect.width()
        if width < 40:
            width = self.view.viewport().width() or 640
        attachment = item.attachment if isinstance(item.attachment, dict) else {}
        key = (
            item.key,
            item.kind,
            item.body,
            item.state,
            item.is_head,
            item.is_tail,
            item.show_avatar,
            item.show_name,
            item.reply_text,
            item.hint,
            attachment.get("path"),
            attachment.get("media"),
            round(float(item.progress), 2),
            width,
            self.palette.name,
        )
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        layout = self.layout_for(item, width)
        size = QSize(width, layout["height"])
        self._cache[key] = size
        return size

    def layout_for(self, item: ChatItem, width: int) -> dict:
        if item.kind == "date":
            return {"height": 36, "kind": "date"}
        if item.kind == "system":
            return {"height": 40, "kind": "system"}
        if item.kind == "typing":
            return {"height": 48, "kind": "typing"}
        if item.kind == "security":
            return self._security_layout(item, width)
        return self._message_layout(item, width)

    def _text_bounds(self, text: str, font: QFont, max_width: int) -> tuple[int, int]:
        metrics = QFontMetrics(font)
        flags = int(Qt.TextFlag.TextWordWrap | Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        rect = metrics.boundingRect(QRect(0, 0, max(20, max_width), 4000), flags, text or " ")
        return max(12, min(max_width, rect.width())), max(metrics.lineSpacing(), rect.height())

    def _message_layout(self, item: ChatItem, width: int) -> dict:
        gutter = 52 if (not item.mine or item.show_avatar) else 0
        if item.mine and not item.show_avatar:
            gutter = 0
        max_bubble = max(120, int(width * 0.65))
        pad_x, pad_y = 12, 8
        meta_h = 16
        reply_h = 36 if item.reply_text else 0
        inner_max = max(48, max_bubble - pad_x * 2)
        attachment = item.attachment if isinstance(item.attachment, dict) else None
        media_kind = str(attachment.get("media") or "file") if attachment else ""
        if attachment and media_kind == "image":
            media_w, media_h = 220, 160
        elif attachment and media_kind == "video":
            media_w, media_h = 220, 132
        elif attachment:
            media_w, media_h = 220, 58
        else:
            media_w, media_h = 0, 0
        media_w = min(media_w, inner_max)
        caption = item.body if not attachment or item.body else ""
        if attachment and not item.body:
            text_w, text_h = 0, 0
        else:
            text_w, text_h = self._text_bounds(item.body or " ", self.font_body, inner_max)
        meta_w = QFontMetrics(self.font_meta).horizontalAdvance("00:00") + 22
        content_w = max(text_w, meta_w, media_w, 72)
        bubble_w = min(max_bubble, content_w + pad_x * 2)
        text_gap = 6 if attachment and text_h else 0
        progress_h = 8 if attachment and item.state == "sending" else 0
        bubble_h = pad_y + reply_h + media_h + text_gap + text_h + progress_h + 2 + meta_h + pad_y
        top = 8 if item.is_head else 2
        name_h = 18 if item.show_name else 0
        height = top + name_h + max(bubble_h, 36 if item.show_avatar else 0) + 2
        if item.mine:
            bubble_x = width - 16 - bubble_w - (44 if item.show_avatar else 0)
        else:
            bubble_x = 16 + (44 if True else 0)
            if not item.show_avatar and not item.mine:
                bubble_x = 60
            elif item.show_avatar or not item.mine:
                bubble_x = 60
        return {
            "kind": "message",
            "height": height,
            "top": top,
            "bubble": QRect(bubble_x, top + name_h, bubble_w, bubble_h),
            "name_h": name_h,
            "text_w": text_w,
            "text_h": text_h,
            "reply_h": reply_h,
            "pad_x": pad_x,
            "pad_y": pad_y,
            "meta_h": meta_h,
            "media_h": media_h,
            "media_kind": media_kind,
            "text_gap": text_gap,
            "progress_h": progress_h,
            "caption": caption,
        }

    def _security_layout(self, item: ChatItem, width: int) -> dict:
        max_w = min(460, int(width * 0.72))
        inner = max(96, max_w - 56)
        title_font = ui_font(15, QFont.Weight.DemiBold)
        title_w, title_h = self._text_bounds(item.body, title_font, inner)
        hint_w, hint_h = (0, 0)
        if item.hint:
            hint_w, hint_h = self._text_bounds(item.hint, self.font_meta, inner)
            hint_h += 2
        content_w = max(title_w, hint_w, 160)
        bubble_w = min(max_w, content_w + 56)
        inner_w = max(96, bubble_w - 56)
        title_w, title_h = self._text_bounds(item.body, title_font, inner_w)
        if item.hint:
            _hint_w, hint_h = self._text_bounds(item.hint, self.font_meta, inner_w)
            hint_h += 2
        gap = 4 if item.hint else 0
        bubble_h = 10 + max(title_h, 20) + gap + hint_h + 10
        return {
            "kind": "security",
            "height": bubble_h + 12,
            "bubble": QRect((width - bubble_w) // 2, 6, bubble_w, bubble_h),
            "title_h": max(title_h, 20),
            "hint_h": hint_h,
        }

    def paint(self, painter: QPainter, option, index) -> None:
        item = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, ChatItem):
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        layout = self.layout_for(item, option.rect.width())
        painter.translate(option.rect.topLeft())
        progress = 1.0 if item.anim >= 0.999 else max(0.0, min(1.0, item.anim))
        if progress < 1:
            distance = 16 if item.mine else 8
            painter.setOpacity(progress)
            painter.translate(0, (1 - progress) * distance)
            if item.mine:
                scale = 0.96 + 0.04 * progress
                bubble = layout.get("bubble")
                if isinstance(bubble, QRect):
                    cx = bubble.center().x()
                    cy = bubble.bottom()
                    painter.translate(cx, cy)
                    painter.scale(scale, scale)
                    painter.translate(-cx, -cy)
        kind = layout["kind"]
        if kind == "date":
            self._paint_chip(painter, option.rect.width(), 8, item.body, quiet=True)
        elif kind == "system":
            self._paint_chip(painter, option.rect.width(), 8, item.body, quiet=False)
        elif kind == "typing":
            self._paint_typing(painter, option.rect.width())
        elif kind == "security":
            self._paint_security(painter, item, layout)
        else:
            self._paint_message(painter, item, layout, index.row(), option.rect)
        painter.restore()

    def _paint_chip(self, painter: QPainter, width: int, y: int, text: str, quiet: bool) -> None:
        font = self.font_system
        painter.setFont(font)
        metrics = QFontMetrics(font)
        text_w = metrics.horizontalAdvance(text) + 20
        rect = QRectF((width - text_w) / 2, y, text_w, 22)
        painter.setPen(Qt.PenStyle.NoPen)
        color = QColor(self.palette.system_bg)
        if quiet:
            color.setAlpha(180)
        painter.setBrush(color)
        painter.drawRoundedRect(rect, 11, 11)
        painter.setPen(QColor(self.palette.system_text))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)

    def _paint_typing(self, painter: QPainter, width: int) -> None:
        import math

        rect = QRectF(60, 8, 58, 32)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self.palette.bubble_in))
        painter.drawRoundedRect(rect, 16, 16)
        phase = self.view.typing_phase
        for index in range(3):
            shift = math.sin((phase + index / 3) * math.tau)
            color = QColor(self.palette.text_secondary)
            color.setAlphaF(0.35 + 0.65 * (shift * 0.5 + 0.5))
            painter.setBrush(color)
            painter.drawEllipse(QRectF(72 + index * 12, 20 - shift * 3, 5, 5))

    def _paint_security(self, painter: QPainter, item: ChatItem, layout: dict) -> None:
        rect = QRectF(layout["bubble"])
        painter.setPen(QPen(QColor(self.palette.danger), 1.4))
        painter.setBrush(QColor(self.palette.security_bg))
        painter.drawRoundedRect(rect, 12, 12)
        dpr = self.view.devicePixelRatioF()
        paint_icon(painter, "alert", QRectF(rect.x() + 12, rect.y() + 12, 18, 18), self.palette.danger, dpr)
        painter.setPen(QColor(self.palette.danger))
        painter.setFont(ui_font(15, QFont.Weight.DemiBold))
        title_h = float(layout.get("title_h", 22))
        text_flags = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap
        painter.drawText(QRectF(rect.x() + 38, rect.y() + 8, rect.width() - 50, title_h), text_flags, item.body)
        if item.hint:
            painter.setFont(self.font_meta)
            painter.setPen(QColor(self.palette.text_secondary))
            hint_top = rect.y() + 8 + title_h + 4
            painter.drawText(
                QRectF(rect.x() + 38, hint_top, rect.width() - 50, float(layout.get("hint_h", 18))),
                text_flags,
                item.hint,
            )

    def _paint_message(self, painter: QPainter, item: ChatItem, layout: dict, row: int, option_rect: QRect) -> None:
        bubble = QRectF(layout["bubble"])
        if item.show_avatar:
            if item.mine:
                ax = bubble.right() + 8
            else:
                ax = 16
            avatar = QRectF(ax, bubble.top(), 36, 36)
            paint_avatar(
                painter,
                avatar,
                item.sender,
                online=False,
                group=False,
                online_color=self.palette.online,
                pixel=14,
                ring=self.palette.bg_chat,
            )
        if item.show_name:
            painter.setFont(self.font_name)
            painter.setPen(QColor(self.palette.accent))
            painter.drawText(QRectF(bubble.left() + 4, layout["top"], bubble.width(), 16), item.sender)
        fill = self.palette.bubble_out if item.mine else self.palette.bubble_in
        text_color = self.palette.text_out if item.mine else self.palette.text
        meta_color = self.palette.meta_out if item.mine else self.palette.meta_in
        radii = _bubble_radii(item.mine, item.is_head, item.is_tail)
        path = rounded_path(bubble, radii)
        if self.palette.light and not item.mine:
            painter.setPen(QPen(QColor(self.palette.border), 1))
        elif item.state == "failed":
            painter.setPen(QPen(QColor(self.palette.danger), 1.4))
        else:
            painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(fill))
        if item.is_tail:
            path = path.united(self._tail_path(bubble, item.mine))
        painter.drawPath(path)
        cursor_y = bubble.top() + layout["pad_y"]
        if item.reply_text:
            reply = QRectF(bubble.left() + 8, cursor_y, bubble.width() - 16, layout["reply_h"] - 6)
            painter.setPen(Qt.PenStyle.NoPen)
            shade = QColor(0, 0, 0, 28 if not self.palette.light else 18)
            painter.setBrush(shade)
            painter.drawRoundedRect(reply, 8, 8)
            painter.setBrush(QColor(self.palette.accent))
            painter.drawRoundedRect(QRectF(reply.left(), reply.top() + 4, 3, reply.height() - 8), 1.5, 1.5)
            painter.setPen(QColor(self.palette.accent))
            painter.setFont(self.font_meta)
            painter.drawText(QRectF(reply.left() + 10, reply.top() + 2, reply.width() - 16, 14), item.reply_author)
            painter.setPen(QColor(text_color))
            painter.drawText(
                QRectF(reply.left() + 10, reply.top() + 16, reply.width() - 16, 16),
                elide(item.reply_text, self.font_meta, int(reply.width() - 16)),
            )
            cursor_y += layout["reply_h"]
        media_h = int(layout.get("media_h") or 0)
        if media_h and isinstance(item.attachment, dict):
            media = QRectF(
                bubble.left() + layout["pad_x"],
                cursor_y,
                bubble.width() - layout["pad_x"] * 2,
                media_h,
            )
            self._paint_attachment(painter, item, media, text_color)
            absolute = media.translated(option_rect.topLeft()).toRect()
            self.open_rects[row] = absolute
            cursor_y += media_h + int(layout.get("text_gap") or 0)
        else:
            self.open_rects.pop(row, None)
        painter.setPen(QColor(text_color))
        painter.setFont(self.font_body)
        text_rect = QRectF(
            bubble.left() + layout["pad_x"],
            cursor_y,
            bubble.width() - layout["pad_x"] * 2,
            layout["text_h"] + 2,
        )
        painter.drawText(
            text_rect,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
            item.body,
        )
        if media_h and item.state == "sending" and item.progress >= 0:
            cursor_y += layout["text_h"]
            ratio = max(0.0, min(1.0, float(item.progress)))
            track = QRectF(
                bubble.left() + layout["pad_x"],
                cursor_y + 2,
                bubble.width() - layout["pad_x"] * 2,
                3,
            )
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(0, 0, 0, 40))
            painter.drawRoundedRect(track, 1.5, 1.5)
            painter.setBrush(QColor(self.palette.accent))
            painter.drawRoundedRect(
                QRectF(track.left(), track.top(), max(3.0, track.width() * ratio), 3),
                1.5,
                1.5,
            )
        clock = message_clock(item.ts)
        painter.setFont(self.font_meta)
        painter.setPen(QColor(meta_color))
        meta = QRectF(bubble.right() - 68, bubble.bottom() - layout["meta_h"] - 6, 46, layout["meta_h"])
        painter.drawText(meta, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, clock)
        icon_rect = QRectF(bubble.right() - 20, bubble.bottom() - 20, 14, 14)
        dpr = self.view.devicePixelRatioF()
        if item.state == "sending":
            paint_icon(painter, "clock", icon_rect, meta_color, dpr)
            self.view.delegate.fail_rects.pop(row, None)
        elif item.state == "delivered":
            paint_icon(painter, "checks", icon_rect, self.palette.accent if not item.mine else meta_color, dpr)
        elif item.state == "failed":
            paint_icon(painter, "alert", icon_rect, self.palette.danger, dpr)
            absolute = icon_rect.translated(option_rect.topLeft()).toRect().adjusted(-4, -4, 4, 4)
            self.fail_rects[row] = absolute
        else:
            paint_icon(painter, "check", icon_rect, meta_color, dpr)
            self.fail_rects.pop(row, None)

    def _paint_attachment(self, painter: QPainter, item: ChatItem, rect: QRectF, text_color: str) -> None:
        attachment = item.attachment or {}
        kind = str(attachment.get("media") or "file")
        painter.save()
        clip = QPainterPath()
        clip.addRoundedRect(rect, 8, 8)
        painter.setClipPath(clip)
        if kind == "image":
            pix = self._load_pix(str(attachment.get("path") or ""), int(rect.width()), int(rect.height()))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(0, 0, 0, 24))
            painter.drawRect(rect)
            if pix is not None and not pix.isNull():
                x = rect.left() + (rect.width() - pix.width()) / 2
                y = rect.top() + (rect.height() - pix.height()) / 2
                painter.drawPixmap(int(x), int(y), pix)
            else:
                self._paint_file_card(painter, attachment, rect, text_color)
        elif kind == "video":
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#1c2733"))
            painter.drawRect(rect)
            painter.setBrush(QColor(255, 255, 255, 230))
            cx, cy = rect.center().x(), rect.center().y() - 8
            triangle = QPainterPath()
            triangle.moveTo(cx - 8, cy - 12)
            triangle.lineTo(cx + 14, cy)
            triangle.lineTo(cx - 8, cy + 12)
            triangle.closeSubpath()
            painter.drawPath(triangle)
            painter.setClipping(False)
            painter.setPen(QColor("white"))
            painter.setFont(self.font_meta)
            size = format_size(int(attachment.get("size") or 0))
            name = elide(
                f"{attachment.get('name') or '视频'} · {size}",
                self.font_meta,
                int(rect.width() - 16),
            )
            painter.drawText(
                QRectF(rect.left() + 8, rect.bottom() - 22, rect.width() - 16, 16),
                name,
            )
            if item.state == "sending" and item.progress >= 0:
                painter.drawText(
                    QRectF(rect.left(), rect.center().y() + 18, rect.width(), 16),
                    Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
                    f"{int(max(0.0, min(1.0, item.progress)) * 100)}%",
                )
        else:
            painter.setClipping(False)
            self._paint_file_card(painter, attachment, rect, text_color)
        painter.restore()

    def _paint_file_card(self, painter: QPainter, attachment: dict, rect: QRectF, text_color: str) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 28))
        painter.drawRoundedRect(rect, 10, 10)
        badge = QRectF(rect.left() + 10, rect.center().y() - 14, 28, 28)
        painter.setBrush(QColor(self.palette.accent))
        painter.drawEllipse(badge)
        dpr = self.view.devicePixelRatioF()
        paint_icon(
            painter,
            "paperclip",
            badge.adjusted(6, 6, -6, -6),
            self.palette.accent_text,
            dpr,
        )
        text_left = badge.right() + 10
        text_width = max(24, rect.right() - text_left - 8)
        painter.setPen(QColor(text_color))
        painter.setFont(self.font_body)
        name = elide(str(attachment.get("name") or "文件"), self.font_body, int(text_width))
        painter.drawText(QRectF(text_left, rect.top() + 8, text_width, 20), name)
        painter.setFont(self.font_meta)
        painter.setPen(QColor(self.palette.text_secondary if text_color != self.palette.text_out else self.palette.meta_out))
        size = format_size(int(attachment.get("size") or 0))
        painter.drawText(
            QRectF(text_left, rect.top() + 30, text_width, 16),
            f"{size} · 打开",
        )

    def _load_pix(self, path: str, width: int, height: int) -> QPixmap | None:
        if not path or width < 8 or height < 8:
            return None
        key = (path, width, height)
        cached = self._pix.get(key)
        if cached is not None:
            return cached
        reader = QImageReader(path)
        reader.setAutoTransform(True)
        image = reader.read()
        if image.isNull():
            pix = QPixmap()
        else:
            pix = QPixmap.fromImage(image).scaled(
                width,
                height,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        if len(self._pix) > 48:
            self._pix.clear()
        self._pix[key] = pix
        return pix

    def _tail_path(self, bubble: QRectF, mine: bool) -> QPainterPath:
        """贴在下角的小尖角，伸出不超过 5px，留在头像缝里。"""
        path = QPainterPath()
        if mine:
            path.moveTo(bubble.right() - 12, bubble.bottom() - 9)
            path.lineTo(bubble.right() + 5, bubble.bottom() - 1.5)
            path.lineTo(bubble.right() - 2, bubble.bottom() - 1)
        else:
            path.moveTo(bubble.left() + 12, bubble.bottom() - 9)
            path.lineTo(bubble.left() - 5, bubble.bottom() - 1.5)
            path.lineTo(bubble.left() + 2, bubble.bottom() - 1)
        path.closeSubpath()
        return path


class MessageList(QListView):
    retryRequested = Signal(str)
    copyRequested = Signal(object)
    replyRequested = Signal(object)
    deleteRequested = Signal(object)
    openRequested = Signal(object)
    filesDropped = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("messages")
        self._model = MessageModel(self)
        self.setModel(self._model)
        self.delegate = MessageDelegate(self)
        self.setItemDelegate(self.delegate)
        self.setUniformItemSizes(False)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.setFrameShape(QListView.Shape.NoFrame)
        self.setMouseTracking(True)
        self.setAcceptDrops(True)
        self.verticalScrollBar().setSingleStep(12)
        self.setLayoutMode(QListView.LayoutMode.SinglePass)
        install_overlay_scroll(self)
        self.typing_phase = 0.0
        self._stick = True
        self._scroll_anim = None
        self.verticalScrollBar().valueChanged.connect(self._on_scroll)
        self.verticalScrollBar().rangeChanged.connect(self._on_range)

    def apply_palette(self, palette: Palette) -> None:
        self.delegate.apply_palette(palette)
        _paint_viewport(self, palette.bg_chat)
        bar = self.verticalScrollBar()
        if hasattr(bar, "set_color"):
            bar.set_color(palette.scroll)
        self.viewport().update()

    def set_messages(self, items: list[ChatItem]) -> None:
        self.delegate.invalidate()
        self._model.set_items(items)
        self._stick = True

    def items(self) -> list[ChatItem]:
        return self._model.items

    def notify_row(self, row: int) -> None:
        self._model.notify(row)

    def at_bottom(self) -> bool:
        bar = self.verticalScrollBar()
        return bar.maximum() - bar.value() <= 48

    def smooth_scroll_to_bottom(self, animated: bool = True) -> None:
        bar = self.verticalScrollBar()
        end = bar.maximum()
        if not animated or abs(end - bar.value()) < 2:
            bar.setValue(end)
            return
        anim = QVariantAnimation(self)
        anim.setStartValue(bar.value())
        anim.setEndValue(end)
        anim.setDuration(220)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.valueChanged.connect(lambda value: bar.setValue(int(value)))
        self._scroll_anim = anim
        anim.start()

    def _on_scroll(self, _value: int) -> None:
        self._stick = self.at_bottom()

    def _on_range(self, _minimum: int, _maximum: int) -> None:
        if self._stick:
            self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            for row, rect in list(self.delegate.fail_rects.items()):
                if rect.contains(event.pos()):
                    item = self._model.items[row] if row < len(self._model.items) else None
                    if item and item.local_id:
                        self.retryRequested.emit(item.local_id)
                        return
            for row, rect in list(self.delegate.open_rects.items()):
                if rect.contains(event.pos()):
                    item = self._model.items[row] if row < len(self._model.items) else None
                    if item and item.attachment:
                        self.openRequested.emit(item)
                        return
        super().mousePressEvent(event)

    def dragEnterEvent(self, event) -> None:
        mime = event.mimeData()
        if mime is not None and mime.hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event) -> None:
        self.dragEnterEvent(event)

    def dropEvent(self, event) -> None:
        paths: list[str] = []
        mime = event.mimeData()
        if mime is not None:
            for url in mime.urls():
                if url.isLocalFile():
                    paths.append(url.toLocalFile())
        if not paths:
            event.ignore()
            return
        event.acceptProposedAction()
        self.filesDropped.emit(paths)

    def contextMenuEvent(self, event) -> None:
        index = self.indexAt(event.pos())
        item = index.data(Qt.ItemDataRole.UserRole) if index.isValid() else None
        if not isinstance(item, ChatItem) or item.kind not in {"message", "security", "system"}:
            return
        menu = QMenu(self)
        copy_action = menu.addAction("复制")
        reply_action = menu.addAction("回复") if item.kind == "message" else None
        delete_action = menu.addAction("删除")
        chosen = menu.exec(event.globalPos())
        if chosen is copy_action:
            self.copyRequested.emit(item)
        elif reply_action is not None and chosen is reply_action:
            self.replyRequested.emit(item)
        elif chosen is delete_action:
            self.deleteRequested.emit(item)

    def resizeEvent(self, event) -> None:
        self.delegate.invalidate()
        super().resizeEvent(event)


def _paint_viewport(view: QListView, color: str) -> None:
    for widget in (view, view.viewport()):
        palette = widget.palette()
        qcolor = QColor(color)
        palette.setColor(QPalette.ColorRole.Base, qcolor)
        palette.setColor(QPalette.ColorRole.Window, qcolor)
        widget.setPalette(palette)
        widget.setAutoFillBackground(True)


def group_flags(items: list[ChatItem]) -> list[tuple[bool, bool, bool, str]]:
    return [(item.show_avatar, item.show_name, item.is_tail, item.kind) for item in items]
