"""在独立 QThread 内运行 ChatEngine、asyncio、SQLite 与 WebSocket。"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any

from PySide6.QtCore import QThread, Signal

from src.client import ChatEngine
from src.protocol import fingerprint


@dataclass(frozen=True)
class ConnectionConfig:
    username: str
    password: str
    host: str = "127.0.0.1"
    port: int = 8765
    db_path: str = ""

    @property
    def uri(self) -> str:
        return f"ws://{self.host}:{self.port}"


class EngineWorker(QThread):
    ready = Signal(object)
    snapshot = Signal(object)
    incoming = Signal(object)
    historyReady = Signal(str, object)
    searchReady = Signal(object)
    messageState = Signal(str, str, str)
    actionResult = Signal(str, bool, object)
    connectionChanged = Signal(bool, str)
    fatalError = Signal(str)

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__()
        self.config = config
        self._loop: asyncio.AbstractEventLoop | None = None
        self._commands: asyncio.Queue[tuple[str, dict[str, Any]]] | None = None
        self._pending: list[tuple[str, dict[str, Any]]] = []
        self._pending_lock = threading.Lock()
        self._stopping = False
        self.engine: ChatEngine | None = None

    def submit(self, action: str, **payload: Any) -> None:
        item = (action, payload)
        loop = self._loop
        queue = self._commands
        if loop is not None and queue is not None and loop.is_running():
            loop.call_soon_threadsafe(queue.put_nowait, item)
            return
        with self._pending_lock:
            self._pending.append(item)

    def stop_async(self) -> None:
        self.submit("stop")

    def run(self) -> None:
        try:
            asyncio.run(self._main())
        except Exception as exc:
            self.fatalError.emit(str(exc))

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._commands = asyncio.Queue()
        with self._pending_lock:
            for item in self._pending:
                self._commands.put_nowait(item)
            self._pending.clear()
        try:
            await self._open_engine()
            self.ready.emit(self._snapshot())
            inbox_task = asyncio.create_task(self._pump_inbox())
            commands_task = asyncio.create_task(self._pump_commands())
            await commands_task
            inbox_task.cancel()
            await asyncio.gather(inbox_task, return_exceptions=True)
        finally:
            if self.engine is not None:
                await self.engine.close()
                self.engine = None
            self.connectionChanged.emit(False, "已退出")

    async def _open_engine(self) -> None:
        config = self.config
        db_path = config.db_path or f"data/{config.username}.db"
        self.connectionChanged.emit(False, "正在解锁本地保险库…")
        engine = ChatEngine.open(config.username, config.password, db_path)
        self.engine = engine
        outbox_before = set(engine.store.list_outbox_peers())
        self.connectionChanged.emit(False, "正在建立安全连接…")
        try:
            await engine.connect(config.uri)
        except Exception:
            await engine.close()
            self.engine = None
            raise
        outbox_after = set(engine.store.list_outbox_peers())
        for local_id, conv, _body, state, _ts in engine.store.pending_message_statuses():
            if state != "sending":
                continue
            peer = conv[3:] if conv.startswith("dm:") else None
            recovered = (
                peer in outbox_before and peer not in outbox_after
            ) or (
                conv.startswith("group:") and bool(outbox_before) and not outbox_after
            )
            engine.store.update_message_status(
                local_id, "accepted" if recovered else "failed"
            )
        self.connectionChanged.emit(True, "端到端加密连接已建立")

    def _snapshot(self) -> dict[str, Any]:
        assert self.engine is not None
        engine = self.engine
        recent = [
            {
                "conv": conv,
                "sender": sender,
                "body": body,
                "ts": ts,
            }
            for conv, sender, body, ts in engine.store.recent_messages()
        ]
        sessions = {
            peer: state.dh_ratchet_count for peer, state in engine.sessions.items()
        }
        fingerprints = {
            peer: " ".join(fingerprint(keys[0]).split()[:8])
            for peer, keys in engine.peer_keys.items()
        }
        return {
            "username": engine.username,
            "connected": engine.connected,
            "online": sorted(engine.online_users),
            "groups": dict(engine.groups),
            "sessions": sessions,
            "fingerprints": fingerprints,
            "recent": recent,
            "unread": engine.store.load_unread(),
            "theme": engine.store.load_ui_value("theme", "telegram"),
            "reduce_motion": engine.store.load_ui_value("reduce_motion", "0") == "1",
            "current_conv": engine.store.load_ui_value("current_conv"),
            "pending": [
                {
                    "local_id": row[0],
                    "conv": row[1],
                    "body": row[2],
                    "state": row[3],
                    "ts": row[4],
                }
                for row in engine.store.pending_message_statuses()
            ],
        }

    async def _pump_inbox(self) -> None:
        while not self._stopping:
            assert self.engine is not None
            item = await self.engine.inbox.get()
            self.incoming.emit(asdict(item))
            if item.kind == "sys" and item.error == "连接断开":
                self.connectionChanged.emit(False, "连接断开，正在重连…")
                await self._reconnect()
            self.snapshot.emit(self._snapshot())

    async def _reconnect(self) -> None:
        old = self.engine
        if old is not None:
            await old.close()
        for attempt in range(1, 7):
            if self._stopping:
                return
            try:
                await asyncio.sleep(min(12, 0.5 * (2 ** (attempt - 1))))
                await self._open_engine()
                self.connectionChanged.emit(True, "已重新连接")
                return
            except Exception as exc:
                self.connectionChanged.emit(
                    False, f"重连失败（{attempt}/6）：{exc}"
                )
        self.fatalError.emit("无法重新连接服务器，请检查服务器地址")

    async def _pump_commands(self) -> None:
        assert self._commands is not None
        while True:
            action, payload = await self._commands.get()
            if action == "stop":
                self._stopping = True
                return
            try:
                await self._handle(action, payload)
            except Exception as exc:
                if action == "send":
                    local_id = str(payload.get("local_id", ""))
                    if self.engine is not None:
                        self.engine.store.update_message_status(local_id, "failed")
                    self.messageState.emit(local_id, "failed", str(exc))
                else:
                    self.actionResult.emit(action, False, str(exc))

    async def _handle(self, action: str, payload: dict[str, Any]) -> None:
        assert self.engine is not None
        engine = self.engine
        if action == "history":
            conv = str(payload["conv"])
            rows = [
                {"sender": s, "body": b, "ts": ts}
                for s, b, ts in engine.store.get_history(conv, limit=500)
            ]
            self.historyReady.emit(conv, rows)
        elif action == "search":
            rows = [
                {
                    "id": row[0],
                    "conv": row[1],
                    "sender": row[2],
                    "body": row[3],
                    "ts": row[4],
                }
                for row in engine.store.search_history(
                    str(payload.get("query", "")),
                    payload.get("conv"),
                    limit=80,
                )
            ]
            self.searchReady.emit(rows)
        elif action == "send":
            await self._send(payload)
        elif action == "open_chat":
            username = str(payload["username"])
            await engine.fetch_user(username)
            self.actionResult.emit(action, True, username)
            self.snapshot.emit(self._snapshot())
        elif action == "fingerprint":
            username = str(payload["username"])
            if username == engine.username:
                key = engine.identity.ik_sign_pub
            else:
                key, _ = await engine.fetch_user(username)
            self.actionResult.emit(
                action, True, {"username": username, "fingerprint": fingerprint(key)}
            )
        elif action == "users":
            result = await engine.list_users()
            self.actionResult.emit(action, True, result)
        elif action == "create_group":
            await engine.create_group(
                str(payload["name"]), list(payload.get("members", []))
            )
            self.actionResult.emit(action, True, str(payload["name"]))
            self.snapshot.emit(self._snapshot())
        elif action == "mark_read":
            unread = dict(payload.get("unread", {}))
            engine.store.save_unread(unread)
        elif action == "set_ui":
            for key in ("theme", "reduce_motion", "current_conv"):
                if key in payload:
                    engine.store.save_ui_value(key, str(payload[key]))
        elif action == "refresh":
            self.snapshot.emit(self._snapshot())
        else:
            raise ValueError(f"未知 GUI 操作：{action}")

    async def _send(self, payload: dict[str, Any]) -> None:
        assert self.engine is not None
        engine = self.engine
        local_id = str(payload["local_id"])
        conv = str(payload["conv"])
        text = str(payload["text"])
        engine.store.save_message_status(local_id, conv, text, "sending")
        if conv.startswith("dm:"):
            await engine.send_text(text, peer=conv[3:])
        elif conv.startswith("group:"):
            await engine.send_text(text, group=conv[6:])
        else:
            raise ValueError("会话 ID 无效")
        engine.store.update_message_status(local_id, "accepted")
        self.messageState.emit(local_id, "accepted", "")
        self.snapshot.emit(self._snapshot())

