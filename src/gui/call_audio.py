"""通话的麦克风和扬声器。钥匙不经过这里。"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer

from src.call import FRAME_BYTES, SAMPLE_RATE


class CallCapture(QObject):
    """16kHz 单声道，每 40 毫秒吐一帧。没有麦克风时 start 返回一句给人看的原因。"""

    def __init__(self) -> None:
        super().__init__()
        self._source = None
        self._io = None
        self._buf = bytearray()
        self._on_frame: Callable[[bytes], None] | None = None

    def start(self, on_frame: Callable[[bytes], None]) -> str | None:
        self.stop()
        self._on_frame = on_frame
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
            return "麦克风不支持通话所需的格式"
        source = QAudioSource(device, fmt)
        io = source.start()
        if io is None or source.error() != QAudioSource.Error.NoError:
            source.stop()
            return "麦克风打不开"
        self._source = source
        self._io = io
        self._buf = bytearray()
        io.readyRead.connect(self._pull)
        return None

    def _pull(self) -> None:
        io = self._io
        if io is None:
            return
        chunk = io.readAll()
        raw = bytes(chunk.data()) if hasattr(chunk, "data") else bytes(chunk)
        if not raw:
            return
        self._buf.extend(raw)
        if len(self._buf) % 2:
            self._buf = self._buf[:-1]
        callback = self._on_frame
        while len(self._buf) >= FRAME_BYTES and callback is not None:
            frame = bytes(self._buf[:FRAME_BYTES])
            del self._buf[:FRAME_BYTES]
            callback(frame)

    def stop(self) -> None:
        io = self._io
        self._io = None
        self._on_frame = None
        source = self._source
        self._source = None
        self._buf = bytearray()
        if source is not None:
            source.stop()
        if io is not None:
            try:
                io.readyRead.disconnect(self._pull)
            except Exception:
                pass


class CallPlayback(QObject):
    """先攒三帧再开播，短抖动不把声音撕开。"""

    def __init__(self) -> None:
        super().__init__()
        self._sink = None
        self._io = None
        self._pending: list[bytes] = []
        self._started = False
        self._timer = QTimer(self)
        self._timer.setInterval(20)
        self._timer.timeout.connect(self._drain)

    def start(self) -> str | None:
        self.stop()
        try:
            from PySide6.QtMultimedia import QAudioFormat, QAudioSink, QMediaDevices
        except Exception:
            return "没有找到扬声器"
        if not QMediaDevices.audioOutputs():
            return "没有找到扬声器"
        fmt = QAudioFormat()
        fmt.setSampleRate(SAMPLE_RATE)
        fmt.setChannelCount(1)
        fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)
        device = QMediaDevices.defaultAudioOutput()
        if not device.isFormatSupported(fmt):
            return "没有找到扬声器"
        sink = QAudioSink(device, fmt, self)
        io = sink.start()
        if io is None or sink.error() != QAudioSink.Error.NoError:
            sink.stop()
            return "没有找到扬声器"
        self._sink = sink
        self._io = io
        self._pending = []
        self._started = False
        self._timer.start()
        return None

    def push(self, pcm: bytes) -> None:
        if not pcm or self._sink is None:
            return
        self._pending.append(bytes(pcm))
        if not self._started and len(self._pending) >= 3:
            self._started = True
        if self._started:
            self._drain()

    def _drain(self) -> None:
        io = self._io
        if io is None or not self._started:
            return
        while self._pending:
            frame = self._pending[0]
            try:
                written = int(io.write(frame))
            except Exception:
                return
            if written <= 0:
                return
            if written >= len(frame):
                self._pending.pop(0)
                continue
            self._pending[0] = frame[written:]
            return

    def stop(self) -> None:
        self._timer.stop()
        sink = self._sink
        self._sink = None
        self._io = None
        self._pending = []
        self._started = False
        if sink is not None:
            sink.stop()
