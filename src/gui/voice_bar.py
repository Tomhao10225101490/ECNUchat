"""按住说话的录音条，以及麦克风采集。"""

from __future__ import annotations

import time

from PySide6.QtCore import QObject, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QWidget

from src.gui.theme import Palette
from src.gui.widgets import ui_font
from src.voice import MAX_VOICE_MS, SAMPLE_RATE, format_duration, level_from_pcm

_MAX_PCM_BYTES = SAMPLE_RATE * 2 * MAX_VOICE_MS // 1000


class VoiceCapture(QObject):
    """16kHz 单声道。没有麦克风时 start 返回一句给人看的原因。"""

    def __init__(self) -> None:
        super().__init__()
        self._pcm = bytearray()
        self._source = None
        self._io = None
        self.levels: list[int] = []
        self.hit_limit = False

    def start(self) -> str | None:
        self.stop()
        try:
            from PySide6.QtMultimedia import QAudioFormat, QAudioSource, QMediaDevices
        except Exception:
            return "这台电脑还不能录音"
        if not QMediaDevices.audioInputs():
            return "没有找到麦克风"
        device = QMediaDevices.defaultAudioInput()
        fmt = QAudioFormat()
        fmt.setSampleRate(SAMPLE_RATE)
        fmt.setChannelCount(1)
        fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)
        if not device.isFormatSupported(fmt):
            return "麦克风不支持录音所需的格式"
        self._pcm = bytearray()
        self.levels = []
        self.hit_limit = False
        source = QAudioSource(device, fmt)
        io = source.start()
        if io is None or source.error() != QAudioSource.Error.NoError:
            source.stop()
            return "麦克风打不开"
        self._source = source
        self._io = io
        io.readyRead.connect(self.pull)
        return None

    def pull(self) -> None:
        io = self._io
        if io is None or self.hit_limit:
            return
        chunk = io.readAll()
        raw = bytes(chunk.data()) if hasattr(chunk, "data") else bytes(chunk)
        if not raw:
            return
        room = _MAX_PCM_BYTES - len(self._pcm)
        if room <= 0:
            self.hit_limit = True
            return
        if len(raw) > room:
            raw = raw[: room - (room % 2)]
            self.hit_limit = True
        if len(raw) % 2:
            raw = raw[:-1]
        if not raw:
            return
        self._pcm.extend(raw)
        self.levels.append(level_from_pcm(raw))
        if len(self.levels) > 28:
            self.levels = self.levels[-28:]
        if len(self._pcm) >= _MAX_PCM_BYTES:
            self.hit_limit = True

    def elapsed_ms(self) -> int:
        return len(self._pcm) // 2 * 1000 // SAMPLE_RATE

    def stop(self) -> bytes:
        io = self._io
        self._io = None
        if io is not None:
            try:
                self.pull()
            except Exception:
                pass
        source = self._source
        self._source = None
        if source is not None:
            source.stop()
        pcm = bytes(self._pcm)
        self._pcm = bytearray()
        if len(pcm) % 2:
            pcm = pcm[:-1]
        return pcm


class VoiceHoldBar(QWidget):
    """替换输入框：红点、时长、波形，以及松开发送或松开取消。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("voiceHold")
        self.setMinimumHeight(40)
        self._ms = 0
        self._peaks: list[int] = []
        self._cancel = False
        self._pulse = True
        self._text = "#F5F5F5"
        self._secondary = "#708499"
        self._fill = "#242F3D"
        self._danger = "#FF5A5F"
        self._accent = "#3390EC"

    def apply_palette(self, palette: Palette) -> None:
        self._text = palette.text
        self._secondary = palette.text_secondary
        self._fill = palette.bg_input
        self._danger = palette.danger
        self._accent = palette.accent
        self.update()

    def show_state(self, ms: int, peaks: list[int], cancel: bool, *, pulse: bool) -> None:
        self._ms = max(0, int(ms))
        self._peaks = [int(item) for item in peaks][-28:]
        self._cancel = cancel
        self._pulse = pulse
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(0, 0, self.width(), self.height())
        painter.setPen(Qt.PenStyle.NoPen)
        fill = QColor(self._danger if self._cancel else self._fill)
        if self._cancel:
            fill.setAlpha(36)
            painter.setBrush(QColor(self._fill))
            painter.drawRoundedRect(rect, 20, 20)
            painter.setBrush(fill)
        else:
            painter.setBrush(fill)
        painter.drawRoundedRect(rect, 20, 20)
        dot = QColor(self._danger)
        if self._pulse and int(time.monotonic() * 2) % 2 == 0:
            dot.setAlpha(120)
        painter.setBrush(dot)
        painter.drawEllipse(QRectF(14, (self.height() - 8) / 2, 8, 8))
        painter.setFont(ui_font(14, QFont.Weight.DemiBold))
        painter.setPen(QColor(self._danger if self._cancel else self._text))
        painter.drawText(QRectF(30, 0, 52, self.height()), Qt.AlignmentFlag.AlignVCenter, format_duration(self._ms))
        hint = "松开取消" if self._cancel else "松开发送 · 上滑取消"
        painter.setFont(ui_font(13))
        painter.setPen(QColor(self._danger if self._cancel else self._secondary))
        hint_width = 148
        painter.drawText(
            QRectF(self.width() - hint_width - 12, 0, hint_width, self.height()),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            hint,
        )
        left = 88
        right = self.width() - hint_width - 20
        self._paint_levels(painter, left, right)

    def _paint_levels(self, painter: QPainter, left: float, right: float) -> None:
        peaks = self._peaks
        if not peaks:
            return
        avail = max(8.0, right - left)
        slot = 6.0
        if len(peaks) * slot > avail:
            slot = avail / len(peaks)
        bar_w = min(2.6, max(1.5, slot * 0.55))
        color = QColor(self._danger if self._cancel else self._accent)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        mid = self.height() / 2
        for index, peak in enumerate(peaks):
            height = max(3.0, min(18.0, 3 + (max(0, min(100, peak)) / 100) * 15))
            x = left + index * slot + (slot - bar_w) / 2
            painter.drawRoundedRect(QRectF(x, mid - height / 2, bar_w, height), 1.2, 1.2)
