"""语音消息的纯函数：WAV、时长、波形。不碰界面、网络和数据库。"""

from __future__ import annotations

import struct

SAMPLE_RATE = 16_000
MIN_VOICE_MS = 400
MAX_VOICE_MS = 180_000
PEAK_COUNT = 28
_MAX_PCM_BYTES = SAMPLE_RATE * 2 * MAX_VOICE_MS // 1000


def duration_ms(pcm: bytes, rate: int = SAMPLE_RATE) -> int:
    if rate <= 0 or len(pcm) < 2:
        return 0
    return (len(pcm) // 2) * 1000 // rate


def format_duration(ms: int) -> str:
    total_ms = max(0, int(ms))
    # 四舍五入到秒。不到一秒的语音也显示成 0:01，避免气泡上出现 0:00。
    if total_ms <= 0:
        total = 0
    else:
        total = max(1, (total_ms + 500) // 1000)
    return f"{total // 60}:{total % 60:02d}"


def hold_should_cancel(origin_x: int, origin_y: int, x: int, y: int) -> bool:
    """按住说话时，上滑或左滑表示取消。"""
    return (origin_y - y) >= 56 or (origin_x - x) >= 72


def read_voice(value: object, mime: str = "") -> dict | None:
    """核对信封和历史里的时长、波形。不合格就当没有，不把整条消息判废。"""
    if mime and not str(mime).lower().startswith("audio/"):
        return None
    if not isinstance(value, dict):
        return None
    ms = value.get("ms")
    peaks = value.get("peaks")
    if isinstance(ms, bool) or not isinstance(ms, int) or not 0 <= ms <= MAX_VOICE_MS:
        return None
    if not isinstance(peaks, list) or len(peaks) != PEAK_COUNT:
        return None
    clean: list[int] = []
    for item in peaks:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 100:
            return None
        clean.append(item)
    return {"ms": ms, "peaks": clean}


def peaks_from_pcm(pcm: bytes, bars: int = PEAK_COUNT) -> list[int]:
    samples = len(pcm) // 2
    if samples <= 0 or bars <= 0:
        return [0] * max(0, bars)
    values = struct.unpack("<" + "h" * samples, pcm[: samples * 2])
    peaks: list[int] = []
    for index in range(bars):
        start = samples * index // bars
        end = samples * (index + 1) // bars
        if end <= start:
            peaks.append(0)
            continue
        peak = 0
        for sample in values[start:end]:
            magnitude = sample if sample >= 0 else -sample
            if magnitude > peak:
                peak = magnitude
        peaks.append(min(100, peak * 100 // 32767))
    return peaks


def level_from_pcm(pcm: bytes) -> int:
    peaks = peaks_from_pcm(pcm, 1)
    return peaks[0] if peaks else 0


def pcm_to_wav(pcm: bytes, rate: int = SAMPLE_RATE) -> bytes:
    if len(pcm) % 2:
        pcm = pcm[:-1]
    if len(pcm) > _MAX_PCM_BYTES:
        pcm = pcm[:_MAX_PCM_BYTES]
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + len(pcm),
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        rate,
        rate * 2,
        2,
        16,
        b"data",
        len(pcm),
    )
    return header + pcm


def wav_to_pcm(data: bytes) -> tuple[bytes, int]:
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("语音不是 WAV")
    offset = 12
    rate = 0
    channels = 0
    bits = 0
    pcm = b""
    while offset + 8 <= len(data):
        chunk = data[offset : offset + 4]
        size = struct.unpack_from("<I", data, offset + 4)[0]
        start = offset + 8
        end = start + size
        if end > len(data):
            raise ValueError("语音不完整")
        if chunk == b"fmt ":
            if size < 16:
                raise ValueError("语音格式无效")
            audio_format, channels, rate, _byte_rate, _block, bits = struct.unpack_from("<HHIIHH", data, start)
            if audio_format != 1 or channels != 1 or bits != 16 or rate <= 0:
                raise ValueError("语音格式无效")
        elif chunk == b"data":
            pcm = data[start:end]
        offset = end + (size & 1)
    if rate <= 0 or not pcm:
        raise ValueError("语音是空的")
    if len(pcm) % 2:
        pcm = pcm[:-1]
    return pcm, rate
