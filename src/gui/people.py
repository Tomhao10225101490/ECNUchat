"""通讯录和选人。按名字里的一段就能筛，不用把用户名敲完整。"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import (
    QAbstractListModel,
    QModelIndex,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPalette, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QPushButton,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)

from src.protocol import MAX_GROUP_MEMBERS
from src.gui.icons import paint_icon
from src.gui.theme import PALETTES, Palette, stylesheet
from src.gui.widgets import elide, install_overlay_scroll, paint_avatar, ui_font


def _fill_viewport(view: QListView, color: str) -> None:
    for widget in (view, view.viewport()):
        palette = widget.palette()
        qcolor = QColor(color)
        palette.setColor(QPalette.ColorRole.Base, qcolor)
        palette.setColor(QPalette.ColorRole.Window, qcolor)
        widget.setPalette(palette)
        widget.setAutoFillBackground(True)

HEADER_HEIGHT = 28
PERSON_HEIGHT = 60
RAIL_WIDTH = 18


@dataclass
class DirectoryEntry:
    kind: str
    key: str
    title: str
    subtitle: str = ""
    online: bool = False
    letter: str = ""


def section_letter(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return "#"
    ch = text[0].upper()
    if "A" <= ch <= "Z":
        return ch
    return "#"


def suggest_group_name(members: list[str]) -> str:
    picked = [name for name in members if name][:3]
    if not picked:
        return "群聊"
    text = "、".join(picked)
    if len(members) > 3:
        text += "等"
    return text[:32]


def build_directory(
    people: list[dict],
    groups: list[str],
    query: str = "",
) -> list[DirectoryEntry]:
    """群聊放在最上面，其余联系人按首字母分节。query 命中名字中的任意一段即可。"""
    needle = query.strip().lower()
    rows: list[DirectoryEntry] = []
    matched_groups = [name for name in groups if not needle or needle in name.lower()]
    if matched_groups:
        rows.append(DirectoryEntry("header", "section:群聊", "群聊", letter="群聊"))
        for name in sorted(matched_groups, key=str.lower):
            rows.append(
                DirectoryEntry("group", f"group:{name}", name, "群聊", letter="群聊")
            )
    buckets: dict[str, list[dict]] = {}
    for person in people:
        name = str(person.get("name") or "")
        if not name or (needle and needle not in name.lower()):
            continue
        buckets.setdefault(section_letter(name), []).append(person)
    for letter in sorted(buckets, key=lambda item: (item == "#", item)):
        rows.append(DirectoryEntry("header", f"section:{letter}", letter, letter=letter))
        for person in sorted(buckets[letter], key=lambda item: str(item["name"]).lower()):
            name = str(person["name"])
            online = bool(person.get("online"))
            subtitle = "在线" if online else "离线"
            if person.get("known"):
                subtitle += " · 聊过"
            rows.append(
                DirectoryEntry(
                    "person",
                    f"dm:{name}",
                    name,
                    subtitle,
                    online,
                    letter,
                )
            )
    return rows


class _DirectoryModel(QAbstractListModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.items: list[DirectoryEntry] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.items)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.items):
            return None
        item = self.items[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return item.title
        if role == Qt.ItemDataRole.UserRole:
            return item
        return None

    def set_items(self, items: list[DirectoryEntry]) -> None:
        self.beginResetModel()
        self.items = list(items)
        self.endResetModel()


class _DirectoryDelegate(QStyledItemDelegate):
    def __init__(self, view: "_DirectoryList") -> None:
        super().__init__(view)
        self.view = view
        self.palette = PALETTES["telegram"]
        self.font_name = ui_font(15, QFont.Weight.DemiBold)
        self.font_meta = ui_font(12)
        self.font_header = ui_font(12, QFont.Weight.DemiBold)

    def apply_palette(self, palette: Palette) -> None:
        self.palette = palette
        self.view.viewport().update()

    def sizeHint(self, _option, index) -> QSize:
        item = index.data(Qt.ItemDataRole.UserRole)
        height = HEADER_HEIGHT if isinstance(item, DirectoryEntry) and item.kind == "header" else PERSON_HEIGHT
        return QSize(self.view.viewport().width(), height)

    def paint(self, painter: QPainter, option, index) -> None:
        item = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, DirectoryEntry):
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        rect = option.rect
        if item.kind == "header":
            painter.setFont(self.font_header)
            painter.setPen(QColor(self.palette.text_tertiary))
            painter.drawText(
                QRectF(16, rect.y(), rect.width() - 28, rect.height()),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                item.title,
            )
            painter.restore()
            return
        hovered = index.row() == self.view.hover_row
        checked = item.title in self.view.checked or (
            item.kind == "group" and item.key in self.view.checked
        )
        if hovered and not checked:
            painter.fillRect(rect, QColor(self.palette.bg_hover))
        if checked:
            painter.fillRect(rect, QColor(self.palette.bg_selected))
        avatar = QRectF(16, rect.y() + 10, 40, 40)
        ring = self.palette.bg_side
        if checked:
            ring = self.palette.bg_selected
        elif hovered:
            ring = self.palette.bg_hover
        paint_avatar(
            painter,
            avatar,
            item.title,
            online=item.online and item.kind == "person",
            group=item.kind == "group",
            online_color=self.palette.online,
            pixel=16,
            ring=ring,
        )
        left = 68
        right = rect.width() - RAIL_WIDTH - (36 if self.view.multi else 12)
        painter.setFont(self.font_name)
        painter.setPen(QColor(self.palette.text_selected if checked else self.palette.text))
        painter.drawText(
            QRectF(left, rect.y() + 10, max(20, right - left), 22),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            elide(item.title, self.font_name, int(max(20, right - left))),
        )
        painter.setFont(self.font_meta)
        meta = self.palette.text_selected if checked else (
            self.palette.online if item.online else self.palette.text_secondary
        )
        painter.setPen(QColor(meta))
        painter.drawText(
            QRectF(left, rect.y() + 32, max(20, right - left), 16),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            item.subtitle,
        )
        if self.view.multi and item.kind == "person":
            box = QRectF(rect.width() - RAIL_WIDTH - 30, rect.y() + 18, 22, 22)
            painter.setPen(QPen(QColor(self.palette.accent if checked else self.palette.border), 1.6))
            painter.setBrush(QColor(self.palette.accent if checked else "transparent"))
            painter.drawEllipse(box)
            if checked:
                paint_icon(painter, "check", box.adjusted(4, 4, -4, -4), self.palette.accent_text, self.view.devicePixelRatioF())
        painter.restore()


class _DirectoryList(QListView):
    activated_entry = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._model = _DirectoryModel(self)
        self.setModel(self._model)
        self._delegate = _DirectoryDelegate(self)
        self.setItemDelegate(self._delegate)
        self.setUniformItemSizes(False)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.setFrameShape(QListView.Shape.NoFrame)
        self.setMouseTracking(True)
        self.hover_row = -1
        self.multi = False
        self.checked: list[str] = []
        install_overlay_scroll(self)
        self.clicked.connect(self._click)

    def set_entries(self, items: list[DirectoryEntry]) -> None:
        self._model.set_items(items)
        self.viewport().update()

    def entries(self) -> list[DirectoryEntry]:
        return list(self._model.items)

    def apply_palette(self, palette: Palette) -> None:
        self._delegate.apply_palette(palette)
        _fill_viewport(self, palette.bg_side)
        bar = self.verticalScrollBar()
        if hasattr(bar, "set_color"):
            bar.set_color(palette.scroll)

    def scroll_to_letter(self, letter: str) -> None:
        for row, entry in enumerate(self._model.items):
            if entry.kind == "header" and entry.letter == letter:
                self.scrollTo(self._model.index(row), QAbstractItemView.ScrollHint.PositionAtTop)
                return

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

    def _click(self, index: QModelIndex) -> None:
        item = index.data(Qt.ItemDataRole.UserRole)
        if isinstance(item, DirectoryEntry) and item.kind != "header":
            self.activated_entry.emit(item)


class LetterRail(QWidget):
    jumped = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedWidth(RAIL_WIDTH)
        self._letters: list[str] = []
        self._palette = PALETTES["telegram"]
        self.setMouseTracking(True)

    def set_letters(self, letters: list[str]) -> None:
        self._letters = list(letters)
        self.update()

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.update()

    def _letter_at(self, y: float) -> str | None:
        if not self._letters:
            return None
        slot = self.height() / len(self._letters)
        index = int(y / max(slot, 1))
        index = max(0, min(len(self._letters) - 1, index))
        return self._letters[index]

    def mousePressEvent(self, event) -> None:
        letter = self._letter_at(event.position().y())
        if letter:
            self.jumped.emit(letter)

    def mouseMoveEvent(self, event) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            letter = self._letter_at(event.position().y())
            if letter:
                self.jumped.emit(letter)
        super().mouseMoveEvent(event)

    def paintEvent(self, _event) -> None:
        if not self._letters:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        painter.setPen(QColor(self._palette.accent))
        slot = self.height() / len(self._letters)
        painter.setFont(ui_font(10 if slot >= 14 else 8, QFont.Weight.DemiBold))
        for index, letter in enumerate(self._letters):
            label = "群" if letter == "群聊" else letter
            painter.drawText(
                QRectF(0, index * slot, self.width(), slot),
                Qt.AlignmentFlag.AlignCenter,
                label,
            )


class ContactBook(QWidget):
    """微信式通讯录：字母分节，右侧可滑动跳转。"""

    activated_key = Signal(str)
    toggled = Signal(str, bool)
    limitReached = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.list = _DirectoryList(self)
        self.rail = LetterRail(self)
        self.empty = QLabel("没有联系人")
        self.empty.setObjectName("secondary")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setWordWrap(True)
        self.empty.hide()
        self.flash = QLabel(self)
        self.flash.setObjectName("letterFlash")
        self.flash.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.flash.setFixedSize(72, 72)
        self.flash.hide()
        self._flash_timer = QTimer(self)
        self._flash_timer.setSingleShot(True)
        self._flash_timer.timeout.connect(self.flash.hide)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.list, 1)
        layout.addWidget(self.empty, 1)
        layout.addWidget(self.rail)
        self.list.activated_entry.connect(self._activate)
        self.rail.jumped.connect(self._jump)
        self._limit = MAX_GROUP_MEMBERS - 1

    def set_multi(self, enabled: bool) -> None:
        self.list.multi = enabled

    def set_entries(self, items: list[DirectoryEntry]) -> None:
        self.list.set_entries(items)
        letters: list[str] = []
        for entry in items:
            if entry.kind == "header" and entry.letter not in letters:
                letters.append(entry.letter)
        self.rail.set_letters(letters)
        has_rows = any(entry.kind != "header" for entry in items)
        self.list.setVisible(has_rows)
        self.rail.setVisible(has_rows)
        self.empty.setVisible(not has_rows)

    def entries(self) -> list[DirectoryEntry]:
        return self.list.entries()

    def count(self) -> int:
        return len(self.entries())

    def checked_names(self) -> list[str]:
        return list(self.list.checked)

    def toggle(self, name: str) -> bool:
        if name in self.list.checked:
            self.list.checked.remove(name)
            self.list.viewport().update()
            self.toggled.emit(name, False)
            return False
        if len(self.list.checked) >= self._limit:
            return False
        self.list.checked.append(name)
        self.list.viewport().update()
        self.toggled.emit(name, True)
        return True

    def apply_palette(self, palette: Palette) -> None:
        self.list.apply_palette(palette)
        self.rail.apply_palette(palette)
        self.flash.setStyleSheet(
            "QLabel#letterFlash {"
            f"background:{palette.bg_menu};color:{palette.text};"
            "border:none;border-radius:12px;"
            "font-size:28px;font-weight:600;"
            "}"
        )

    def set_reduce_motion(self, _enabled: bool) -> None:
        return None

    def scroll_to_letter(self, letter: str) -> None:
        self._jump(letter)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.flash.move(
            max(0, (self.list.width() - self.flash.width()) // 2),
            max(0, (self.height() - self.flash.height()) // 2),
        )
        self.flash.raise_()

    def hideEvent(self, event) -> None:
        self._flash_timer.stop()
        self.flash.hide()
        super().hideEvent(event)

    def _jump(self, letter: str) -> None:
        self.list.scroll_to_letter(letter)
        self.flash.setText("群" if letter == "群聊" else letter)
        self.flash.move(
            max(0, (self.list.width() - self.flash.width()) // 2),
            max(0, (self.height() - self.flash.height()) // 2),
        )
        self.flash.show()
        self.flash.raise_()
        self._flash_timer.start(420)

    def _activate(self, entry: DirectoryEntry) -> None:
        if self.list.multi:
            if entry.kind != "person":
                return
            existed = entry.title in self.list.checked
            ok = self.toggle(entry.title)
            if not existed and not ok:
                self.limitReached.emit()
            return
        self.activated_key.emit(entry.key)


class _ChipStrip(QWidget):
    """已选成员的头像。点一下就取消。"""

    removed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._names: list[str] = []
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(8)
        self._row.addStretch(1)
        self.setFixedHeight(40)
        self.hide()

    def set_names(self, names: list[str]) -> None:
        if names == self._names:
            return
        self._names = list(names)
        while self._row.count():
            item = self._row.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for name in names:
            button = QPushButton(name[:1].upper())
            button.setObjectName("chip")
            button.setToolTip(f"{name} · 点一下取消")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, picked=name: self.removed.emit(picked))
            self._row.addWidget(button)
        self._row.addStretch(1)
        self.setVisible(bool(names))


class PeoplePicker(QDialog):
    """发起聊天点一个人；拉群时勾选，搜索只需要名字里的一段。"""

    def __init__(
        self,
        people: list[dict],
        *,
        mode: str,
        palette: Palette,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.mode = mode
        self._people = list(people)
        self._palette = palette
        self.setStyleSheet(stylesheet(palette))
        self.setMinimumSize(420, 560)
        self.setWindowTitle("新建群组" if mode == "group" else "新建消息")
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)
        title = QLabel(self.windowTitle())
        title.setObjectName("title")
        self.search = QLineEdit()
        self.search.setObjectName("searchField")
        self.search.setPlaceholderText("搜索")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._refresh)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("群名称")
        self.chips = _ChipStrip()
        self.chips.removed.connect(self.toggle)
        self.picked_label = QLabel("")
        self.picked_label.setObjectName("caption")
        self.book = ContactBook()
        self.book.set_multi(mode == "group")
        self.book.apply_palette(palette)
        self.book.toggled.connect(lambda _name, _on: self._sync_button())
        self.book.limitReached.connect(self._show_limit)
        self.empty = QLabel("没有匹配的联系人")
        self.empty.setObjectName("secondary")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.limit_hint = QLabel("")
        self.limit_hint.setObjectName("caption")
        buttons = QHBoxLayout()
        cancel = QPushButton("取消")
        self.finish_button = QPushButton("完成")
        self.finish_button.setObjectName("primary")
        cancel.clicked.connect(self.reject)
        self.finish_button.clicked.connect(self._finish)
        buttons.addWidget(cancel)
        buttons.addWidget(self.finish_button)
        root.addWidget(title)
        root.addWidget(self.search)
        if mode == "group":
            root.addWidget(self.name_edit)
            root.addWidget(self.chips)
            root.addWidget(self.picked_label)
        root.addWidget(self.book, 1)
        root.addWidget(self.empty)
        root.addWidget(self.limit_hint)
        root.addLayout(buttons)
        if mode == "chat":
            self.book.activated_key.connect(self._pick_one)
            self.finish_button.hide()
        self._refresh()
        self.search.setFocus()
        self.search.returnPressed.connect(self._enter)

    def _refresh(self) -> None:
        rows = build_directory(self._people, [], self.search.text())
        self.book.set_entries(rows)
        self.empty.setVisible(not any(row.kind == "person" for row in rows))
        self.book.setVisible(not self.empty.isVisible())
        self._sync_button()

    def visible_names(self) -> list[str]:
        return [row.title for row in self.book.entries() if row.kind == "person"]

    def selected(self) -> list[str]:
        return self.book.checked_names()

    def toggle(self, name: str) -> bool:
        existed = name in self.book.list.checked
        ok = self.book.toggle(name)
        if existed or ok:
            self.limit_hint.setText("")
        else:
            self._show_limit()
        self._sync_button()
        return ok

    def group_name(self) -> str:
        typed = self.name_edit.text().strip()
        return typed or suggest_group_name(self.selected())

    def _show_limit(self) -> None:
        self.limit_hint.setText(f"一个群最多再加 {MAX_GROUP_MEMBERS - 1} 人")

    def _sync_button(self) -> None:
        names = self.selected()
        count = len(names)
        self.finish_button.setText(f"完成（{count}）" if count else "完成")
        self.finish_button.setEnabled(count > 0)
        if self.mode != "group":
            return
        self.chips.set_names(names)
        self.picked_label.setText("、".join(names))
        if not self.name_edit.text().strip():
            self.name_edit.setPlaceholderText(suggest_group_name(names) if names else "群名称")

    def _pick_one(self, key: str) -> None:
        if key.startswith("dm:"):
            self.book.list.checked = [key[3:]]
            self.accept()

    def _enter(self) -> None:
        names = self.visible_names()
        if len(names) != 1:
            return
        if self.mode == "chat":
            self._pick_one(f"dm:{names[0]}")
            return
        self.toggle(names[0])

    def _finish(self) -> None:
        if self.mode == "group" and not self.selected():
            return
        self.accept()


def people_from_snapshot(snapshot: dict, username: str) -> list[dict]:
    names: set[str] = set()
    names.update(str(name) for name in snapshot.get("online", []))
    names.update(str(name) for name in snapshot.get("sessions", {}))
    for members in snapshot.get("groups", {}).values():
        names.update(str(name) for name in members)
    names.update(str(name) for name in snapshot.get("directory", []))
    names.discard(username)
    online = {str(name) for name in snapshot.get("online", [])}
    known = {str(name) for name in snapshot.get("sessions", {})}
    return [
        {"name": name, "online": name in online, "known": name in known}
        for name in sorted(names, key=str.lower)
    ]
