"""联系人、朋友圈、投递箱和资料隐私。聊天窗本身仍在主窗口里。"""

from __future__ import annotations

import base64
import time
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets import AVATAR_COLORS, AvatarWidget
from src.social import POST_VISIBILITIES


def _clear(layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.setParent(None)
            widget.deleteLater()


def _scroll(host: QWidget) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    scroll.setWidget(host)
    scroll.viewport().setAutoFillBackground(False)
    return scroll


def _clock(ts: float) -> str:
    if not ts:
        return ""
    return time.strftime("%m-%d %H:%M", time.localtime(float(ts)))


def _section(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("section")
    label.setContentsMargins(12, 10, 12, 2)
    return label


def _button(text: str, kind: str = "") -> QPushButton:
    button = QPushButton(text)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    if kind:
        button.setProperty("kind", kind)
        button.style().unpolish(button)
        button.style().polish(button)
    return button


def _row() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("row")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(12, 8, 8, 8)
    layout.setSpacing(2)
    return frame, layout


def _pixmap(data_b64: str, edge: int) -> QPixmap | None:
    if not data_b64:
        return None
    try:
        raw = base64.b64decode(data_b64, validate=True)
    except Exception:
        return None
    image = QImage()
    if not image.loadFromData(raw, "JPEG") or image.isNull():
        return None
    return QPixmap.fromImage(image).scaled(
        edge,
        edge,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )


class PeoplePanel(QWidget):
    """好友申请、同意、拒绝、取消、拉黑和搜索结果。"""

    acceptClicked = Signal(str)
    rejectClicked = Signal(str)
    cancelClicked = Signal(str)
    removeClicked = Signal(str)
    blockClicked = Signal(str)
    unblockClicked = Signal(str)
    messageClicked = Signal(str)
    addClicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = QWidget()
        self._body = QVBoxLayout(self._host)
        self._body.setContentsMargins(0, 0, 0, 12)
        self._body.setSpacing(0)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(_scroll(self._host))
        self.set_model()

    def set_model(
        self,
        *,
        friends: list[dict[str, Any]] | None = None,
        incoming: list[dict[str, Any]] | None = None,
        outgoing: list[dict[str, Any]] | None = None,
        blocked: list[dict[str, Any]] | None = None,
        rejected: list[dict[str, Any]] | None = None,
        results: list[dict[str, Any]] | None = None,
    ) -> None:
        incoming = list(incoming or [])
        outgoing = list(outgoing or [])
        friends = list(friends or [])
        rejected = list(rejected or [])
        blocked = list(blocked or [])
        results = list(results or [])
        payload = (friends, incoming, outgoing, blocked, rejected, results)
        if payload == getattr(self, "_payload", None):
            return
        self._payload = payload
        _clear(self._body)
        if results:
            self._body.addWidget(_section("搜索结果"))
            for item in results:
                self._body.addWidget(self._result_card(item))
        if incoming:
            self._body.addWidget(_section("新的朋友"))
            for item in incoming:
                self._body.addWidget(self._incoming_card(item))
        if outgoing:
            self._body.addWidget(_section("等待对方同意"))
            for item in outgoing:
                self._body.addWidget(self._outgoing_card(item))
        if rejected:
            self._body.addWidget(_section("未通过"))
            for item in rejected:
                self._body.addWidget(self._rejected_card(item))
        if friends:
            self._body.addWidget(_section("好友"))
            for item in friends:
                self._body.addWidget(self._friend_card(item))
        elif not incoming and not results:
            empty = QLabel("还没有好友")
            empty.setObjectName("secondary")
            empty.setContentsMargins(12, 8, 12, 8)
            self._body.addWidget(empty)
        if blocked:
            self._body.addWidget(_section("黑名单"))
            for item in blocked:
                self._body.addWidget(self._blocked_card(item))
        self._body.addStretch(1)

    def _person_row(self, item: dict[str, Any], extra: str = "") -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        avatar = AvatarWidget(40)
        avatar.set_person(
            str(item.get("display_name") or item.get("username") or ""),
            online=bool(item.get("online")),
            avatar=str(item.get("avatar") or ""),
        )
        text = QVBoxLayout()
        text.setSpacing(0)
        name = QLabel(str(item.get("display_name") or item.get("username") or ""))
        name.setObjectName("name")
        subtitle = extra or str(item.get("username") or "")
        handle = QLabel(subtitle)
        handle.setObjectName("caption")
        handle.setWordWrap(True)
        text.addWidget(name)
        text.addWidget(handle)
        row.addWidget(avatar)
        row.addLayout(text, 1)
        return row

    def _incoming_card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        username = str(item["username"])
        greeting = str(item.get("greeting") or "请求添加你为好友")
        layout.addLayout(self._person_row(item, greeting))
        buttons = QHBoxLayout()
        accept = _button("同意")
        accept.setObjectName(f"accept-{username}")
        reject = _button("拒绝", "quiet")
        reject.setObjectName(f"reject-{username}")
        accept.clicked.connect(lambda _checked=False, name=username: self.acceptClicked.emit(name))
        reject.clicked.connect(lambda _checked=False, name=username: self.rejectClicked.emit(name))
        buttons.addWidget(accept)
        buttons.addWidget(reject)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        accept.setObjectName(f"accept-{username}")
        return frame

    def _outgoing_card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        username = str(item["username"])
        layout.addLayout(self._person_row(item, str(item.get("greeting") or "等待对方同意")))
        cancel = _button("取消申请", "quiet")
        cancel.setObjectName(f"cancel-{username}")
        cancel.clicked.connect(lambda _checked=False, name=username: self.cancelClicked.emit(name))
        layout.addWidget(cancel, alignment=Qt.AlignmentFlag.AlignLeft)
        return frame

    def _rejected_card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        username = str(item["username"])
        layout.addLayout(self._person_row(item, "对方没有通过"))
        again = _button("再次申请")
        again.setObjectName(f"again-{username}")
        again.clicked.connect(lambda _checked=False, name=username: self.addClicked.emit(name))
        layout.addWidget(again, alignment=Qt.AlignmentFlag.AlignLeft)
        return frame

    def _friend_card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        username = str(item["username"])
        bio = str(item.get("bio") or item.get("username") or "")
        layout.addLayout(self._person_row(item, bio))
        buttons = QHBoxLayout()
        message = _button("发消息")
        remove = _button("删除", "quiet")
        block = _button("拉黑", "danger")
        message.clicked.connect(lambda _checked=False, name=username: self.messageClicked.emit(name))
        remove.clicked.connect(lambda _checked=False, name=username: self.removeClicked.emit(name))
        block.clicked.connect(lambda _checked=False, name=username: self.blockClicked.emit(name))
        buttons.addWidget(message)
        buttons.addWidget(remove)
        buttons.addWidget(block)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return frame

    def _blocked_card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        username = str(item["username"])
        layout.addLayout(self._person_row(item, "已拉黑"))
        unblock = _button("取消拉黑")
        unblock.setObjectName(f"unblock-{username}")
        unblock.clicked.connect(lambda _checked=False, name=username: self.unblockClicked.emit(name))
        layout.addWidget(unblock, alignment=Qt.AlignmentFlag.AlignLeft)
        return frame

    def _result_card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        username = str(item["username"])
        relation = str(item.get("relation") or "none")
        labels = {
            "none": "可以添加",
            "friend": "已是好友",
            "outgoing": "已申请，等待同意",
            "incoming": "对方申请了你",
            "blocked": "你已拉黑对方",
            "unavailable": "无法添加",
        }
        layout.addLayout(self._person_row(item, labels.get(relation, relation)))
        if relation == "none":
            add = _button("添加")
            add.setObjectName(f"add-{username}")
            add.clicked.connect(lambda _checked=False, name=username: self.addClicked.emit(name))
            layout.addWidget(add, alignment=Qt.AlignmentFlag.AlignLeft)
        elif relation == "incoming":
            accept = _button("同意")
            accept.setObjectName(f"accept-{username}")
            accept.clicked.connect(lambda _checked=False, name=username: self.acceptClicked.emit(name))
            layout.addWidget(accept, alignment=Qt.AlignmentFlag.AlignLeft)
        elif relation == "friend":
            message = _button("发消息")
            message.clicked.connect(lambda _checked=False, name=username: self.messageClicked.emit(name))
            layout.addWidget(message, alignment=Qt.AlignmentFlag.AlignLeft)
        return frame


class MomentComposer(QWidget):
    postRequested = Signal(str, str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)
        self.body = QTextEdit()
        self.body.setObjectName("plain")
        self.body.setPlaceholderText("这一刻的想法…")
        self.body.setFixedHeight(96)
        layout.addWidget(self.body)
        self.visibility = QComboBox()
        self.visibility.addItem("好友可见", "friends")
        self.visibility.addItem("仅自己可见", "private")
        layout.addWidget(self.visibility)
        self.image_label = QLabel("未附加图片")
        self.image_label.setObjectName("caption")
        layout.addWidget(self.image_label)
        row = QHBoxLayout()
        self.image_button = _button("加图片", "quiet")
        self.clear_image = _button("去掉图片", "quiet")
        self.publish = _button("发布")
        self.image_button.clicked.connect(self._pick)
        self.clear_image.clicked.connect(self._clear_image)
        self.publish.clicked.connect(self._publish)
        row.addWidget(self.image_button)
        row.addWidget(self.clear_image)
        row.addWidget(self.publish)
        layout.addLayout(row)
        layout.addStretch(1)
        self._image = ""

    def _pick(self) -> None:
        from PySide6.QtWidgets import QFileDialog

        from src.gui.media import jpeg_token
        from src.social import MAX_MOMENT_IMAGE_CHARS

        path, _selected = QFileDialog.getOpenFileName(self, "选择朋友圈图片", "", "图片 (*.jpg *.jpeg *.png *.webp)")
        if not path:
            return
        try:
            self._image = jpeg_token(path, max_edge=320, max_chars=MAX_MOMENT_IMAGE_CHARS)
        except Exception as exc:
            self._image = ""
            self.image_label.setText(str(exc))
            return
        self.image_label.setText("已附上一张小图")

    def _clear_image(self) -> None:
        self._image = ""
        self.image_label.setText("未附加图片")

    def _publish(self) -> None:
        body = self.body.toPlainText().strip()
        if not body and not self._image:
            self.image_label.setText("写点字，或加一张图")
            return
        visibility = str(self.visibility.currentData() or "friends")
        if visibility not in POST_VISIBILITIES:
            visibility = "friends"
        self.postRequested.emit(body, self._image, visibility)
        self.body.clear()
        self._clear_image()


class MomentBoard(QWidget):
    likeClicked = Signal(str)
    commentClicked = Signal(str, str)
    deleteClicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("chat")
        self._host = QWidget()
        self._body = QVBoxLayout(self._host)
        self._body.setContentsMargins(0, 0, 0, 0)
        self._body.setSpacing(0)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(_scroll(self._host), 1)
        self.set_moments([])

    def set_moments(self, moments: list[dict[str, Any]]) -> None:
        if moments == getattr(self, "_moments", None):
            return
        self._moments = list(moments)
        _clear(self._body)
        if not moments:
            empty = QLabel("还没有动态")
            empty.setObjectName("secondary")
            empty.setContentsMargins(16, 18, 16, 8)
            self._body.addWidget(empty)
        for item in moments:
            self._body.addWidget(self._card(item))
        self._body.addStretch(1)

    def _card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        moment_id = str(item.get("id") or "")
        head = QHBoxLayout()
        avatar = AvatarWidget(36)
        avatar.set_person(
            str(item.get("display_name") or item.get("author") or ""),
            avatar=str(item.get("avatar") or ""),
        )
        text = QVBoxLayout()
        text.setSpacing(0)
        name = QLabel(str(item.get("display_name") or item.get("author") or ""))
        name.setObjectName("link")
        meta = "仅自己可见" if item.get("visibility") == "private" else "好友可见"
        when = QLabel(f"{_clock(float(item.get('created') or 0))} · {meta}")
        when.setObjectName("caption")
        text.addWidget(name)
        text.addWidget(when)
        head.addWidget(avatar)
        head.addLayout(text, 1)
        layout.addLayout(head)
        body = str(item.get("body") or "")
        if body:
            content = QLabel(body)
            content.setWordWrap(True)
            content.setObjectName("name")
            content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(content)
        pix = _pixmap(str(item.get("image") or ""), 280)
        if pix is not None:
            picture = QLabel()
            picture.setPixmap(pix)
            layout.addWidget(picture)
        elif item.get("has_image"):
            waiting = QLabel("图片加载中")
            waiting.setObjectName("caption")
            layout.addWidget(waiting)
        likes = list(item.get("likes") or [])
        like = _button(("已赞" if item.get("liked") else "赞") + f" {len(likes)}")
        like.setObjectName(f"like-{moment_id}")
        like.clicked.connect(lambda _checked=False, mid=moment_id: self.likeClicked.emit(mid))
        actions = QHBoxLayout()
        actions.addWidget(like)
        if item.get("mine"):
            delete = _button("删除", "quiet")
            delete.setObjectName(f"delete-{moment_id}")
            delete.clicked.connect(lambda _checked=False, mid=moment_id: self.deleteClicked.emit(mid))
            actions.addWidget(delete)
        actions.addStretch(1)
        layout.addLayout(actions)
        for comment in item.get("comments") or []:
            line = QLabel(f"{comment.get('display_name') or comment.get('author')}：{comment.get('body')}")
            line.setWordWrap(True)
            line.setObjectName("secondary")
            layout.addWidget(line)
        comment_row = QHBoxLayout()
        edit = QLineEdit()
        edit.setPlaceholderText("评论")
        send = _button("发送")
        send.setObjectName(f"comment-{moment_id}")

        def submit(mid: str = moment_id, box: QLineEdit = edit) -> None:
            text_value = box.text().strip()
            if not text_value:
                return
            box.clear()
            self.commentClicked.emit(mid, text_value)

        edit.returnPressed.connect(submit)
        send.clicked.connect(submit)
        comment_row.addWidget(edit, 1)
        comment_row.addWidget(send)
        layout.addLayout(comment_row)
        return frame


class DropboxBoard(QWidget):
    openRequested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("chat")
        self._host = QWidget()
        self._body = QVBoxLayout(self._host)
        self._body.setContentsMargins(0, 0, 0, 0)
        self._body.setSpacing(0)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(_scroll(self._host), 1)
        self.set_items([])

    def set_items(self, items: list[dict[str, Any]]) -> None:
        if items == getattr(self, "_items", None):
            return
        self._items = list(items)
        _clear(self._body)
        if not items:
            empty = QLabel("还没有文件")
            empty.setObjectName("secondary")
            empty.setContentsMargins(16, 18, 16, 8)
            self._body.addWidget(empty)
        for item in items:
            self._body.addWidget(self._card(item))
        self._body.addStretch(1)

    def _card(self, item: dict[str, Any]) -> QWidget:
        frame, layout = _row()
        direction = "收到" if item.get("direction") == "in" else "发出"
        name = QLabel(str(item.get("name") or "file"))
        name.setObjectName("name")
        size = int(item.get("size") or 0)
        meta = QLabel(
            f"{direction} · {item.get('peer') or ''} · {size} 字节 · {_clock(float(item.get('created') or 0))}"
        )
        meta.setObjectName("caption")
        meta.setWordWrap(True)
        layout.addWidget(name)
        layout.addWidget(meta)
        path = str(item.get("path") or "")
        open_button = _button("打开")
        open_button.clicked.connect(lambda _checked=False, target=path: self.openRequested.emit(target))
        layout.addWidget(open_button, alignment=Qt.AlignmentFlag.AlignLeft)
        return frame


class ProfileSettings(QWidget):
    profileSaved = Signal(str, str, str)
    privacySaved = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 8)
        layout.setSpacing(8)
        self._accent = "#3390EC"
        title = QLabel("资料")
        title.setObjectName("section")
        layout.addWidget(title)
        head = QHBoxLayout()
        self.avatar = AvatarWidget(56)
        self.avatar.set_person("我")
        head.addWidget(self.avatar)
        fields = QVBoxLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("昵称")
        self.bio_edit = QLineEdit()
        self.bio_edit.setPlaceholderText("简介")
        fields.addWidget(self.name_edit)
        fields.addWidget(self.bio_edit)
        head.addLayout(fields, 1)
        layout.addLayout(head)
        presets = QHBoxLayout()
        presets.setSpacing(8)
        self.preset_buttons: list[QPushButton] = []
        self.avatar_token = ""
        for index in range(8):
            button = QPushButton("")
            button.setFixedSize(22, 22)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.clicked.connect(lambda _checked=False, i=index: self._choose_preset(i))
            self.preset_buttons.append(button)
            presets.addWidget(button)
        presets.addStretch(1)
        layout.addLayout(presets)
        photo_row = QHBoxLayout()
        photo = _button("上传头像", "quiet")
        photo.clicked.connect(self._pick_avatar)
        save = _button("保存资料")
        save.clicked.connect(self._save_profile)
        photo_row.addWidget(photo)
        photo_row.addWidget(save)
        photo_row.addStretch(1)
        layout.addLayout(photo_row)
        self.profile_hint = QLabel("")
        self.profile_hint.setWordWrap(True)
        self.profile_hint.setObjectName("caption")
        layout.addWidget(self.profile_hint)

        privacy_title = QLabel("隐私")
        privacy_title.setObjectName("section")
        layout.addWidget(privacy_title)
        self.approval = self._switch_row(layout, "加我需要同意")
        self.show_online = self._switch_row(layout, "对好友显示在线")
        self.searchable = self._switch_row(layout, "允许被搜索到")
        self.approval.setChecked(True)
        self.show_online.setChecked(True)
        self.searchable.setChecked(True)
        self.moments = QComboBox()
        self.moments.addItem("好友可见全部", "friends")
        self.moments.addItem("只看最近三天", "three_days")
        self.moments.addItem("不让好友看", "none")
        layout.addWidget(self.moments)
        save_privacy = _button("保存隐私")
        save_privacy.clicked.connect(self._save_privacy)
        layout.addWidget(save_privacy, alignment=Qt.AlignmentFlag.AlignLeft)
        self._paint_presets()

    def _switch_row(self, layout: QVBoxLayout, text: str):
        from src.gui.widgets import ToggleSwitch

        row = QHBoxLayout()
        label = QLabel(text)
        switch = ToggleSwitch()
        row.addWidget(label)
        row.addStretch(1)
        row.addWidget(switch)
        layout.addLayout(row)
        return switch

    def _choose_preset(self, index: int) -> None:
        self.avatar_token = f"preset:{index}"
        self.avatar.set_person(self.name_edit.text() or "我", avatar=self.avatar_token)
        self.profile_hint.setText("")
        self._paint_presets()

    def _pick_avatar(self) -> None:
        from PySide6.QtWidgets import QFileDialog

        from src.gui.media import jpeg_token
        from src.social import MAX_AVATAR_CHARS

        path, _selected = QFileDialog.getOpenFileName(self, "选择头像", "", "图片 (*.jpg *.jpeg *.png *.webp)")
        if not path:
            return
        try:
            self.avatar_token = jpeg_token(
                path, max_edge=48, max_chars=MAX_AVATAR_CHARS, prefix="jpeg:"
            )
        except Exception as exc:
            self.profile_hint.setText(str(exc))
            return
        self.avatar.set_person(self.name_edit.text() or "我", avatar=self.avatar_token)
        self.profile_hint.setText("")
        self._paint_presets()

    def _save_profile(self) -> None:
        self.profileSaved.emit(self.name_edit.text().strip(), self.bio_edit.text().strip(), self.avatar_token)

    def _save_privacy(self) -> None:
        self.privacySaved.emit(
            {
                "require_approval": self.approval.isChecked(),
                "show_online": self.show_online.isChecked(),
                "searchable": self.searchable.isChecked(),
                "moments_visibility": str(self.moments.currentData() or "friends"),
            }
        )

    def set_profile(self, profile: dict[str, Any]) -> None:
        if self.name_edit.hasFocus() or self.bio_edit.hasFocus():
            return
        name = str(profile.get("display_name") or "")
        bio = str(profile.get("bio") or "")
        avatar = str(profile.get("avatar") or "")
        self.name_edit.setText(name)
        self.bio_edit.setText(bio)
        self.avatar_token = avatar
        self.avatar.set_person(name or "我", online=True, avatar=avatar)
        self._paint_presets()

    def set_privacy(self, privacy: dict[str, Any]) -> None:
        if any(widget.hasFocus() for widget in (self.approval, self.show_online, self.searchable, self.moments)):
            return
        self.approval.setChecked(bool(privacy.get("require_approval", True)))
        self.show_online.setChecked(bool(privacy.get("show_online", True)))
        self.searchable.setChecked(bool(privacy.get("searchable", True)))
        visibility = str(privacy.get("moments_visibility") or "friends")
        index = max(0, self.moments.findData(visibility))
        self.moments.setCurrentIndex(index)

    def apply_palette(self, accent: str, text: str) -> None:
        self._accent = accent
        self._accent_text = text
        self._paint_presets()

    def _paint_presets(self) -> None:
        for index, button in enumerate(self.preset_buttons):
            color = AVATAR_COLORS[index]
            selected = self.avatar_token == f"preset:{index}"
            border = self._accent if selected else "transparent"
            button.setStyleSheet(
                "QPushButton { background:%s; border:2px solid %s; border-radius:11px; padding:0; min-width:0; }"
                % (color, border)
            )
