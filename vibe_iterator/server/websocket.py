"""WebSocket connection manager — broadcasts scan events to all dashboard clients."""

from __future__ import annotations

from fastapi import WebSocket
from fastapi.websockets import WebSocketState


class WebSocketManager:
    """Manages active WebSocket connections and a replay buffer for reconnecting clients."""

    _BUFFER_MAX = 500

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._buffer: list[str] = []

    async def connect(self, ws: WebSocket) -> None:
        """Accept connection and replay buffered events so the client catches up."""
        await ws.accept()
        for message in list(self._buffer):
            try:
                await ws.send_text(message)
            except Exception:
                return
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, message: str) -> None:
        """Send a message to all connected clients and buffer it for future reconnects."""
        self._buffer.append(message)
        if len(self._buffer) > self._BUFFER_MAX:
            self._buffer.pop(0)

        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(message)
                else:
                    dead.append(ws)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def clear_buffer(self) -> None:
        """Clear the replay buffer — call before starting a new scan."""
        self._buffer.clear()

    @property
    def connection_count(self) -> int:
        return len(self._connections)
