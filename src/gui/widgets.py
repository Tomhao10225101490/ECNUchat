"""按钮、输入框、头像、滚动条和浮层。"""

from __future__ import annotations

import hashlib
import time

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QEvent,
    QObject,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QInputMethodEvent,
    QKeyEvent,
    QLinearGradient,
    QPainter,
    QPaintEvent,
    QPalette,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollBar,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.gui.icons import paint_icon
from src.gui.logic import composer_enter_action, composer_target_height
from src.gui.theme import FONT_FAMILIES, RADIUS_BUBBLE, RADIUS_BUTTON, Palette


def ui_font(px: int, weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    font = QFont()
    font.setFamilies(list(FONT_FAMILIES))
    font.setPixelSize(px)
    font.setWeight(weight)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font


def avatar_colors(name: str) -> tuple[QColor, QColor]:
    digest = hashlib.sha256((name or "?").encode("utf-8")).digest()
    hue = digest[0] / 255 * 360
    hue2 = (hue + 32 + digest[1] % 28) % 360
    first = QColor.fromHsv(int(hue) % 360, 148, 206)
    second = QColor.fromHsv(int(hue2) % 360, 168, 158)
    return first, second


def avatar_letter(name: str, group: bool = False) -> str:
    if group:
        return "群"
    text = (name or "?").strip()
    if not text:
        return "?"
    return text[:1].upper()


def paint_avatar(
    painter: QPainter,
    rect: QRectF,
    name: str,
    *,
    online: bool = False,
    group: bool = False,
    online_color: str = "#31D158",
    pixel: int = 15,
) -> None:
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    start, end = avatar_colors("group:" + name if group else name)
    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0, start)
    gradient.setColorAt(1, end)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(gradient)
    painter.drawEllipse(rect)
    painter.setPen(QColor("#FFFFFF"))
    font = ui_font(max(12, int(pixel)), QFont.Weight.DemiBold)
    painter.setFont(font)
    painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, avatar_letter(name, group))
    if online:
        radius = max(4.5, rect.width() * 0.14)
        center_x = rect.right() - radius * 0.55
        center_y = rect.bottom() - radius * 0.55
        painter.setBrush(QColor("#FFFFFF"))
        painter.drawEllipse(QPointF(center_x, center_y), radius + 1.7, radius + 1.7)
        painter.setBrush(QColor(online_color))
        painter.drawEllipse(QPointF(center_x, center_y), radius, radius)
    painter.restore()


class AvatarWidget(QWidget):
    def __init__(self, size: int = 40, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.name = ""
        self.online = False
        self.group = False
        self.online_color = "#31D158"

    def set_person(self, name: str, *, online: bool = False, group: bool = False) -> None:
        self.name = name
        self.online = online
        self.group = group
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        paint_avatar(
            painter,
            QRectF(0.5, 0.5, self.width() - 1, self.height() - 1),
            self.name,
            online=self.online,
            group=self.group,
            online_color=self.online_color,
            pixel=max(13, int(self.width() * 0.38)),
        )


class IconButton(QAbstractButton):
    def __init__(
        self,
        name: str,
        size: int = 36,
        icon_px: int = 20,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.icon_name = name
        self.icon_px = icon_px
        self._hover = 0.0
        self._scale = 1.0
        self._bg = "transparent"
        self._fg = "#8B9BB4"
        self._hover_bg = "#202B36"
        self.setFixedSize(size, size)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._hover_anim = QVariantAnimation(self)
        self._hover_anim.setDuration(140)
        self._hover_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hover_anim.valueChanged.connect(self._set_hover)
        self._scale_anim = QPropertyAnimation(self, b"scale", self)
        self._scale_anim.setDuration(120)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_scale(self) -> float:
        return self._scale

    def set_scale(self, value: float) -> None:
        self._scale = float(value)
        self.update()

    scale = Property(float, get_scale, set_scale)

    def _set_hover(self, value: object) -> None:
        self._hover = float(value)
        self.update()

    def apply_colors(self, fg: str, hover_bg: str, bg: str = "transparent") -> None:
        self._fg = fg
        self._hover_bg = hover_bg
        self._bg = bg
        self.update()

    def enterEvent(self, event) -> None:
        self._run(self._hover_anim, self._hover, 1.0)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._run(self._hover_anim, self._hover, 0.0)
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        self._run(self._scale_anim, self._scale, 0.96)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._run(self._scale_anim, self._scale, 1.0)
        super().mouseReleaseEvent(event)

    def _run(self, anim: QVariantAnimation, start: float, end: float) -> None:
        anim.stop()
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.start()

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(self.width() / 2, self.height() / 2)
        painter.scale(self._scale, self._scale)
        painter.translate(-self.width() / 2, -self.height() / 2)
        if self._hover > 0.01 or self._bg != "transparent":
            color = QColor(self._hover_bg if self._hover > 0.01 else self._bg)
            if self._bg == "transparent":
                color.setAlphaF(self._hover)
            elif self._hover > 0:
                color = QColor(self._hover_bg)
                color.setAlphaF(min(1.0, 0.35 + self._hover * 0.65))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            radius = RADIUS_BUTTON
            painter.drawRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 2), radius, radius)
        dpr = self.devicePixelRatioF()
        side = float(self.icon_px)
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        paint_icon(painter, self.icon_name, rect, self._fg, dpr)


class NavButton(IconButton):
    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(name, 48, 22, parent)
        self.active = False
        self._badge = 0
        self._accent = "#3390EC"
        self._soft = "#1A3C5C"
        self._muted = "#8B9BB4"

    def set_active(self, active: bool) -> None:
        self.active = active
        self.update()

    def set_badge(self, count: int) -> None:
        self._badge = count
        self.update()

    def apply_nav(self, accent: str, soft: str, muted: str, hover: str) -> None:
        self._accent = accent
        self._soft = soft
        self._muted = muted
        self.apply_colors(accent if self.active else muted, hover)

    def paintEvent(self, event: QPaintEvent) -> None:
        self._fg = self._accent if self.active else self._muted
        if self.active:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(self._soft))
            painter.drawRoundedRect(QRectF(6, 4, self.width() - 12, self.height() - 8), 12, 12)
            painter.setBrush(QColor(self._accent))
            painter.drawRoundedRect(QRectF(4, 14, 3, self.height() - 28), 1.5, 1.5)
            painter.end()
        super().paintEvent(event)
        if self._badge > 0:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#FF3B30"))
            painter.drawEllipse(QRectF(self.width() - 16, 8, 10, 10))
            painter.end()


class SendButton(QAbstractButton):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(40, 40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._active = False
        self._morph = 0.0
        self._scale = 1.0
        self._hover = 0.0
        self._accent = "#3390EC"
        self._accent_text = "#FFFFFF"
        self._muted = "#8B9BB4"
        self._track = "#314558"
        self._morph_anim = QVariantAnimation(self)
        self._morph_anim.setDuration(180)
        self._morph_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._morph_anim.valueChanged.connect(self._set_morph)
        self._scale_anim = QPropertyAnimation(self, b"scale", self)
        self._scale_anim.setDuration(180)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hover_anim = QVariantAnimation(self)
        self._hover_anim.setDuration(140)
        self._hover_anim.valueChanged.connect(self._set_hover)

    def get_scale(self) -> float:
        return self._scale

    def set_scale(self, value: float) -> None:
        self._scale = float(value)
        self.update()

    scale = Property(float, get_scale, set_scale)

    def _set_morph(self, value: object) -> None:
        self._morph = float(value)
        self.update()

    def _set_hover(self, value: object) -> None:
        self._hover = float(value)
        self.update()

    def apply_palette(self, palette: Palette) -> None:
        self._accent = palette.accent
        self._accent_text = palette.accent_text
        self._muted = palette.text_tertiary
        self._track = palette.border
        self.update()

    def set_active(self, active: bool, *, animate: bool = True) -> None:
        target = 1.0 if active else 0.0
        same = active == self._active and abs(self._morph - target) < 0.01
        self._active = active
        if same:
            return
        if not animate:
            self._morph_anim.stop()
            self._scale_anim.stop()
            self._morph = target
            self._scale = 1.0
            self.update()
            return
        self._morph_anim.stop()
        self._morph_anim.setStartValue(self._morph)
        self._morph_anim.setEndValue(target)
        self._morph_anim.start()
        self._scale_anim.stop()
        self._scale_anim.setStartValue(0.86 if active else 1.0)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()

    def enterEvent(self, event) -> None:
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        self._scale_anim.stop()
        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(0.96)
        self._scale_anim.start()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._scale_anim.stop()
        self._scale_anim.setStartValue(self._scale)
        self._scale_anim.setEndValue(1.0)
        self._scale_anim.start()
        super().mouseReleaseEvent(event)

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(self.width() / 2, self.height() / 2)
        painter.scale(self._scale, self._scale)
        painter.translate(-self.width() / 2, -self.height() / 2)
        rect = QRectF(1, 1, self.width() - 2, self.height() - 2)
        painter.setPen(Qt.PenStyle.NoPen)
        if self._morph < 0.98:
            track = QColor(self._track)
            painter.setBrush(track)
            painter.drawEllipse(rect)
        if self._morph > 0.02:
            accent = QColor(self._accent)
            if self._hover > 0:
                accent = QColor(self._accent).lighter(100 + int(self._hover * 8))
            accent.setAlphaF(self._morph)
            painter.setBrush(accent)
            painter.drawEllipse(rect)
        dpr = self.devicePixelRatioF()
        icon_rect = QRectF(10, 10, 20, 20)
        if self._morph < 0.5:
            paint_icon(painter, "mic", icon_rect, self._muted, dpr)
        else:
            paint_icon(painter, "send", icon_rect, self._accent_text, dpr)


class FadeScrollBar(QScrollBar):
    """细滚动条，平时透明，悬停或滚动时才浮现。"""

    def __init__(self, orientation: Qt.Orientation, parent: QWidget | None = None) -> None:
        super().__init__(orientation, parent)
        self._alpha = 0.0
        self._color = QColor("#6A8298")
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._set_alpha)
        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(lambda: self.fade_to(0.0))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.valueChanged.connect(lambda _v: self.flash())

    def sizeHint(self):
        if self.orientation() == Qt.Orientation.Vertical:
            return self.minimumSizeHint()
        return super().sizeHint()

    def _set_alpha(self, value: object) -> None:
        self._alpha = float(value)
        self.update()

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def fade_to(self, alpha: float) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._alpha)
        self._anim.setEndValue(alpha)
        self._anim.start()

    def flash(self) -> None:
        self.fade_to(0.9)
        self._hide_timer.start(700)

    def paintEvent(self, _event: QPaintEvent) -> None:
        if self._alpha < 0.02 or self.maximum() <= self.minimum():
            return
        span = self.height() if self.orientation() == Qt.Orientation.Vertical else self.width()
        if span <= 0:
            return
        page = max(1, self.pageStep())
        total = max(1, self.maximum() - self.minimum() + page)
        handle = max(28, int(span * page / total))
        travel = max(1, span - handle)
        ratio = (self.value() - self.minimum()) / max(1, self.maximum() - self.minimum())
        offset = int(travel * ratio)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        color = QColor(self._color)
        color.setAlphaF(self._alpha * 0.85)
        painter.setBrush(color)
        if self.orientation() == Qt.Orientation.Vertical:
            painter.drawRoundedRect(QRectF(2, offset + 2, max(2, self.width() - 4), max(8, handle - 4)), 3, 3)
        else:
            painter.drawRoundedRect(QRectF(offset + 2, 2, max(8, handle - 4), max(2, self.height() - 4)), 3, 3)


def install_overlay_scroll(view: QWidget) -> FadeScrollBar:
    bar = FadeScrollBar(Qt.Orientation.Vertical, view)
    setter = getattr(view, "setVerticalScrollBar")
    setter(bar)
    hider = getattr(view, "setHorizontalScrollBarPolicy")
    hider(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

    class Watcher(QObject):
        def eventFilter(self, watched: QObject, event: QEvent) -> bool:
            if event.type() == QEvent.Type.Enter:
                bar.fade_to(0.55)
                bar._hide_timer.stop()
            elif event.type() == QEvent.Type.Leave:
                bar._hide_timer.start(400)
            return False

    watcher = Watcher(view)
    view.installEventFilter(watcher)
    viewport = getattr(view, "viewport", None)
    if viewport is not None:
        viewport().installEventFilter(watcher)
        viewport().setMouseTracking(True)
    view._scroll_watcher = watcher  # type: ignore[attr-defined]
    return bar


class ComposerEdit(QTextEdit):
    """圆角输入框里的多行文本。Enter 发送，Shift+Enter 换行，组字时不发送。"""

    sendRequested = Signal()
    heightChanged = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._preedit = ""
        self._swallow_until = 0.0
        self.setAcceptRichText(False)
        self.setFrameStyle(QFrame.Shape.NoFrame)
        self.setFont(ui_font(15))
        self.setPlaceholderText("输入消息…")
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.document().setDocumentMargin(0)
        self.setViewportMargins(12, 8, 12, 8)
        self.setCursorWidth(2)
        self.setMinimumHeight(self._line() + 16)
        self.setFixedHeight(self._line() + 16)
        self.textChanged.connect(self._reflow)
        self.install_overlay = install_overlay_scroll(self)

    def _line(self) -> int:
        return max(18, self.fontMetrics().lineSpacing())

    def preedit_text(self) -> str:
        return self._preedit

    def inputMethodEvent(self, event: QInputMethodEvent) -> None:
        commit = event.commitString()
        preedit = event.preeditString()
        if commit and not preedit:
            self._swallow_until = time.monotonic() + 0.08
        self._preedit = preedit
        super().inputMethodEvent(event)
        self._reflow()

    def inputMethodQuery(self, query):
        return super().inputMethodQuery(query)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        enter = event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
        if self._preedit:
            super().keyPressEvent(event)
            return
        if enter:
            action = composer_enter_action(
                shift=bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier),
                preedit=self._preedit,
                swallow_until=self._swallow_until,
                now=time.monotonic(),
            )
            if action == "newline":
                super().keyPressEvent(event)
                return
            if action == "compose":
                self._swallow_until = 0.0
                event.accept()
                return
            self.sendRequested.emit()
            event.accept()
            return
        if event.key() == Qt.Key.Key_Tab:
            event.ignore()
            return
        super().keyPressEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._reflow()

    def _reflow(self) -> None:
        if self.viewport().width() < 20:
            return
        self.document().setTextWidth(self.viewport().width())
        height, scrolled = composer_target_height(
            self.document().size().height(), self._line(), pad=16, max_lines=6
        )
        if height != self.height():
            self.setFixedHeight(height)
            self.heightChanged.emit(height)
        self.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
            if scrolled
            else Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

    def insert_text(self, text: str) -> None:
        self.textCursor().insertText(text)
        self.setFocus()


class ReplyBar(QWidget):
    dismissed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.author = ""
        self.quote = ""
        self._accent = "#3390EC"
        self._soft = "#1A3C5C"
        self._text = "#F2F6FA"
        self._muted = "#8B9BB4"
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 4, 4)
        layout.setSpacing(8)
        text = QVBoxLayout()
        text.setSpacing(0)
        self.author_label = QLabel()
        self.author_label.setObjectName("caption")
        self.snippet = QLabel()
        self.snippet.setObjectName("secondary")
        text.addWidget(self.author_label)
        text.addWidget(self.snippet)
        layout.addLayout(text, 1)
        self.close_button = IconButton("close", 28, 14)
        self.close_button.clicked.connect(self.clear_reply)
        layout.addWidget(self.close_button)
        self.hide()

    def apply_palette(self, palette: Palette) -> None:
        self._accent = palette.accent
        self._soft = palette.accent_soft
        self._text = palette.text
        self._muted = palette.text_secondary
        self.author_label.setStyleSheet(f"color:{palette.accent};font-size:12px;font-weight:600;background:transparent")
        self.snippet.setStyleSheet(f"color:{palette.text_secondary};font-size:13px;background:transparent")
        self.close_button.apply_colors(palette.text_secondary, palette.bg_hover)
        self.update()

    def set_reply(self, author: str, quote: str) -> None:
        self.author = author
        self.quote = " ".join(quote.split())
        self.author_label.setText(f"回复 {author}")
        self.snippet.setText(self.quote)
        self.show()

    def clear_reply(self) -> None:
        self.author = ""
        self.quote = ""
        self.hide()
        self.dismissed.emit()

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self._soft))
        painter.drawRoundedRect(QRectF(8, 4, self.width() - 12, self.height() - 4), 8, 8)
        painter.setBrush(QColor(self._accent))
        painter.drawRoundedRect(QRectF(8, 8, 3, self.height() - 12), 1.5, 1.5)


class InputShell(QWidget):
    """看得见边框的圆角输入区，焦点时描边过渡到主题色。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.edit = ComposerEdit()
        self.reply = ReplyBar()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)
        layout.addWidget(self.reply)
        layout.addWidget(self.edit)
        self._focus = 0.0
        self._border = "#314558"
        self._accent = "#3390EC"
        self._fill = "#242F3D"
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._set_focus)
        self.edit.installEventFilter(self)

    def _set_focus(self, value: object) -> None:
        self._focus = float(value)
        self.update()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.edit and event.type() in (QEvent.Type.FocusIn, QEvent.Type.FocusOut):
            target = 1.0 if event.type() == QEvent.Type.FocusIn else 0.0
            self._anim.stop()
            self._anim.setStartValue(self._focus)
            self._anim.setEndValue(target)
            self._anim.start()
        return False

    def apply_palette(self, palette: Palette) -> None:
        self._border = palette.border
        self._accent = palette.accent
        self._fill = palette.bg_input
        self.reply.apply_palette(palette)
        self.edit.setStyleSheet(
            "QTextEdit { background: transparent; border: none; color: %s; }" % palette.text
        )
        palette_qt = self.edit.palette()
        palette_qt.setColor(QPalette.ColorRole.Text, QColor(palette.text))
        palette_qt.setColor(QPalette.ColorRole.PlaceholderText, QColor(palette.text_tertiary))
        self.edit.setPalette(palette_qt)
        bar = self.edit.verticalScrollBar()
        if isinstance(bar, FadeScrollBar):
            bar.set_color(palette.scroll)
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        border = _mix(self._border, self._accent, self._focus)
        rect = QRectF(1, 1, self.width() - 2, self.height() - 2)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self._fill))
        painter.drawRoundedRect(rect, RADIUS_BUBBLE, RADIUS_BUBBLE)
        pen = QPen(QColor(border))
        pen.setWidthF(1.0 + self._focus)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), RADIUS_BUBBLE, RADIUS_BUBBLE)


def _mix(start: str, end: str, t: float) -> str:
    from src.gui.theme import lerp_color

    return lerp_color(start, end, t)


class TypingDots(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(36, 16)
        self._phase = 0.0
        self._color = QColor("#8B9BB4")
        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(900)
        self._anim.setLoopCount(-1)
        self._anim.valueChanged.connect(self._set_phase)

    def _set_phase(self, value: object) -> None:
        self._phase = float(value)
        self.update()

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def set_running(self, running: bool) -> None:
        if running and self._anim.state() != QVariantAnimation.State.Running:
            self._anim.start()
        elif not running:
            self._anim.stop()
            self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        import math

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        for index in range(3):
            shift = math.sin((self._phase + index / 3.0) * math.tau) 
            alpha = 0.35 + 0.65 * (shift * 0.5 + 0.5)
            color = QColor(self._color)
            color.setAlphaF(alpha)
            painter.setBrush(color)
            y = 8 - shift * 3
            painter.drawEllipse(QRectF(4 + index * 10, y - 2.5, 5, 5))


class EmptyState(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette: Palette | None = None

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        palette = self._palette
        if palette is None:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        cx = self.width() / 2
        cy = self.height() / 2 - 36
        painter.setPen(Qt.PenStyle.NoPen)
        blob = QColor(palette.accent)
        blob.setAlpha(28 if not palette.light else 36)
        painter.setBrush(blob)
        painter.drawEllipse(QRectF(cx - 74, cy - 58, 148, 148))
        bubble = QColor(palette.bubble_in if palette.light else palette.bubble_out)
        painter.setBrush(bubble)
        painter.drawRoundedRect(QRectF(cx - 78, cy - 18, 92, 48), 16, 16)
        painter.setBrush(QColor(palette.bubble_out))
        painter.drawRoundedRect(QRectF(cx - 8, cy + 22, 96, 40), 16, 16)
        dpr = self.devicePixelRatioF()
        paint_icon(painter, "lock", QRectF(cx - 11, cy - 46, 22, 22), palette.accent, dpr)
        painter.setPen(QColor(palette.text))
        painter.setFont(ui_font(17, QFont.Weight.DemiBold))
        title = "选择一个聊天开始加密对话"
        painter.drawText(QRectF(24, cy + 84, self.width() - 48, 28), Qt.AlignmentFlag.AlignCenter, title)
        painter.setPen(QColor(palette.text_secondary))
        painter.setFont(ui_font(13))
        painter.drawText(
            QRectF(24, cy + 114, self.width() - 48, 22),
            Qt.AlignmentFlag.AlignCenter,
            "消息只在本机解密，服务器看不到正文",
        )


class EmojiPanel(QFrame):
    chosen = Signal(str)

    EMOJI = (
        "😀 😂 😊 😍 😘 😭 😅 🤔 😴 🥳 "
        "👍 👎 👋 🙏 💪 🤝 👀 ❤️ 🔥 ✨ "
        "🎉 ✅ ❌ 💯 🔒 🔑 💬 📎 ⭐ 🌟"
    ).split()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        from PySide6.QtWidgets import QPushButton

        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(2)
        columns = 8
        row = None
        for index, emoji in enumerate(self.EMOJI):
            if index % columns == 0:
                row = QHBoxLayout()
                row.setSpacing(2)
                layout.addLayout(row)
            button = QPushButton(emoji, self)
            button.setFixedSize(36, 36)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setStyleSheet(
                "QPushButton { background: transparent; border: none; border-radius: 8px; font-size: 18px; }"
                "QPushButton:hover { background: rgba(128,128,128,0.16); }"
            )
            button.clicked.connect(lambda _checked=False, text=emoji: self.chosen.emit(text))
            assert row is not None
            row.addWidget(button)
        rows = (len(self.EMOJI) + columns - 1) // columns
        self.setFixedSize(columns * 38 + 20, rows * 38 + 20)
        self.hide()


class NewMessageButton(QAbstractButton):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._count = 0
        self._alpha = 0.0
        self._fill = "#17212B"
        self._text = "#F2F6FA"
        self._accent = "#3390EC"
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.hide()
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._set_alpha)

    def _set_alpha(self, value: object) -> None:
        self._alpha = float(value)
        self.update()
        if self._alpha <= 0.01 and self._count <= 0:
            self.hide()

    def apply_palette(self, palette: Palette) -> None:
        self._fill = palette.bg_card
        self._text = palette.text
        self._accent = palette.accent
        self.update()

    def set_count(self, count: int) -> None:
        self._count = max(0, count)
        self.setText("↓ 新消息" if self._count <= 1 else f"↓ {self._count} 条新消息")
        width = max(112, QFontMetrics(ui_font(13, QFont.Weight.DemiBold)).horizontalAdvance(self.text()) + 36)
        self.setFixedSize(width, 36)
        self._anim.stop()
        self._anim.setStartValue(self._alpha)
        self._anim.setEndValue(1.0 if self._count else 0.0)
        if self._count:
            self.show()
            self.raise_()
        self._anim.start()

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setOpacity(self._alpha)
        painter.setPen(Qt.PenStyle.NoPen)
        shadow = QColor(0, 0, 0, 40)
        painter.setBrush(shadow)
        painter.drawRoundedRect(QRectF(2, 3, self.width() - 4, self.height() - 4), 18, 18)
        painter.setBrush(QColor(self._fill))
        painter.setPen(QPen(QColor(self._accent), 1))
        painter.drawRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 4), 16, 16)
        painter.setPen(QColor(self._accent))
        painter.setFont(ui_font(13, QFont.Weight.DemiBold))
        painter.drawText(self.rect().adjusted(0, -2, 0, -2), Qt.AlignmentFlag.AlignCenter, self.text())


class ToggleSwitch(QAbstractButton):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(44, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._knob = 0.0
        self._on = "#3390EC"
        self._off = "#C8C8C8"
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._set_knob)
        self.toggled.connect(self._start)

    def _set_knob(self, value: object) -> None:
        self._knob = float(value)
        self.update()

    def _start(self, checked: bool) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._knob)
        self._anim.setEndValue(1.0 if checked else 0.0)
        self._anim.start()

    def apply_palette(self, palette: Palette) -> None:
        self._on = palette.accent
        self._off = palette.border
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        track = QColor(_mix(self._off, self._on, self._knob))
        painter.setBrush(track)
        painter.drawRoundedRect(QRectF(1, 3, 42, 20), 10, 10)
        painter.setBrush(QColor("#FFFFFF"))
        x = 4 + self._knob * 18
        painter.drawEllipse(QRectF(x, 5, 16, 16))


class BlurDialog(QFrame):
    """带背景虚化和缩放淡入的卡片弹窗。"""

    def __init__(self, parent: QWidget, title: str) -> None:
        super().__init__(parent)
        self.setObjectName("overlay")
        self.setGeometry(parent.rect())
        self._title = title
        self._palette: Palette | None = None
        self._shot = None
        self._scale = 0.96
        self._opacity = 0.0
        self.card = QFrame(self)
        self.card.setObjectName("card")
        self._scale_anim = QVariantAnimation(self)
        self._scale_anim.setDuration(180)
        self._scale_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._scale_anim.valueChanged.connect(self._set_scale)
        self._fade_anim = QVariantAnimation(self)
        self._fade_anim.setDuration(180)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim.valueChanged.connect(self._set_opacity)
        self.hide()

    def _set_scale(self, value: object) -> None:
        self._scale = float(value)
        self._place_card()

    def _set_opacity(self, value: object) -> None:
        self._opacity = float(value)
        self.update()

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.card.setStyleSheet(
            f"QFrame#card {{ background: {palette.bg_card}; border: 1px solid {palette.border}; border-radius: 12px; }}"
        )

    def present(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        self.setGeometry(parent.rect())
        shot = parent.grab()
        self._shot = _frost(shot)
        self._place_card()
        self.show()
        self.raise_()
        self._opacity = 0.0
        self._scale = 0.96
        self._fade_anim.stop()
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._scale_anim.stop()
        self._scale_anim.setStartValue(0.96)
        self._scale_anim.setEndValue(1.0)
        self._fade_anim.start()
        self._scale_anim.start()

    def dismiss(self) -> None:
        self._fade_anim.stop()
        self._fade_anim.setStartValue(self._opacity)
        self._fade_anim.setEndValue(0.0)
        self._fade_anim.finished.connect(self.hide)
        self._fade_anim.start()

    def resize_to_parent(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
            self._place_card()

    def _place_card(self) -> None:
        width = min(440, max(280, self.width() - 48))
        height = min(self.card.sizeHint().height() + 8, self.height() - 48)
        height = max(height, 220)
        cw = int(width * self._scale)
        ch = int(height * self._scale)
        self.card.setGeometry((self.width() - cw) // 2, (self.height() - ch) // 2, cw, ch)

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        if self._shot is not None:
            painter.setOpacity(self._opacity)
            painter.drawPixmap(0, 0, self._shot)
        painter.setOpacity(self._opacity)
        dim = QColor(0, 0, 0, 90 if self._palette and not self._palette.light else 50)
        painter.fillRect(self.rect(), dim)

    def mousePressEvent(self, event) -> None:
        if not self.card.geometry().contains(event.position().toPoint()):
            self.dismiss()
        else:
            super().mousePressEvent(event)


def _frost(shot):
    small = shot.scaled(max(1, shot.width() // 8), max(1, shot.height() // 8), Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
    image = small.toImage()
    # 两次盒式模糊，再放大，得到毛玻璃而不是闪白。
    for _ in range(2):
        image = image.scaled(max(1, image.width() // 2), max(1, image.height() // 2), Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
        image = image.scaled(small.width(), small.height(), Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
    return QPixmap.fromImage(image).scaled(shot.size(), Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)


class StatusText(QObject):
    """给测试和读屏用的状态文案，不创建顶层窗口。"""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._text = ""
        self._style = ""

    def text(self) -> str:
        return self._text

    def setText(self, value: str) -> None:
        self._text = value

    def setStyleSheet(self, value: str) -> None:
        self._style = value


STATE_TEXT = {
    "sending": "发送中",
    "accepted": "已发送",
    "delivered": "已送达",
    "failed": "发送失败",
}


class MessageBubble(QObject):
    """消息状态代理。画面由列表委托绘制，这里保留状态文案。"""

    def __init__(self, item, on_state=None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.item = item
        self.status_label = StatusText(self)
        self._on_state = on_state
        self.set_state(item.state)

    def set_state(self, state: str) -> None:
        self.item.state = state
        self.status_label.setText(STATE_TEXT.get(state, ""))
        self.status_label.setStyleSheet("color:#ff6b6b" if state == "failed" else "")
        if self._on_state:
            self._on_state(self.item)


class ElideLabel(QLabel):
    """单行省略显示，text() 仍返回完整字符串。"""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._full = text
        QLabel.setText(self, text)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def setText(self, text: str) -> None:
        self._full = text or ""
        self._elide()

    def text(self) -> str:
        return self._full

    def sizeHint(self) -> QSize:
        metrics = QFontMetrics(self.font())
        return QSize(96, metrics.height() + 4)

    def minimumSizeHint(self) -> QSize:
        metrics = QFontMetrics(self.font())
        return QSize(0, metrics.height() + 2)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        width = self.contentsRect().width()
        if width < 24:
            shown = self._full
        else:
            shown = QFontMetrics(self.font()).elidedText(self._full, Qt.TextElideMode.ElideRight, max(0, width))
        if QLabel.text(self) != shown:
            QLabel.setText(self, shown)


def elide(text: str, font: QFont, width: int) -> str:
    if width <= 0:
        return ""
    return QFontMetrics(font).elidedText(text or "", Qt.TextElideMode.ElideRight, width)


def rounded_path(rect: QRectF, radii: tuple[float, float, float, float]):
    from PySide6.QtGui import QPainterPath

    tl, tr, br, bl = radii
    path = QPainterPath()
    path.moveTo(rect.left() + tl, rect.top())
    path.lineTo(rect.right() - tr, rect.top())
    path.arcTo(QRectF(rect.right() - 2 * tr, rect.top(), 2 * tr, 2 * tr), 90, -90)
    path.lineTo(rect.right(), rect.bottom() - br)
    path.arcTo(QRectF(rect.right() - 2 * br, rect.bottom() - 2 * br, 2 * br, 2 * br), 0, -90)
    path.lineTo(rect.left() + bl, rect.bottom())
    path.arcTo(QRectF(rect.left(), rect.bottom() - 2 * bl, 2 * bl, 2 * bl), 270, -90)
    path.lineTo(rect.left(), rect.top() + tl)
    path.arcTo(QRectF(rect.left(), rect.top(), 2 * tl, 2 * tl), 180, -90)
    path.closeSubpath()
    return path
