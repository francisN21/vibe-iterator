"""Tests for WebSocketManager — connect, broadcast, replay buffer, disconnect."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from vibe_iterator.server.websocket import WebSocketManager
from fastapi.websockets import WebSocketState


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _mock_ws(connected: bool = True) -> MagicMock:
    ws = MagicMock()
    ws.client_state = WebSocketState.CONNECTED if connected else WebSocketState.DISCONNECTED
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.receive_text = AsyncMock(return_value="ping")
    return ws


# --------------------------------------------------------------------------- #
# Connect and broadcast                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_connect_adds_to_connections() -> None:
    manager = WebSocketManager()
    ws = _mock_ws()
    await manager.connect(ws)
    assert manager.connection_count == 1


@pytest.mark.asyncio
async def test_broadcast_sends_to_connected_client() -> None:
    manager = WebSocketManager()
    ws = _mock_ws()
    await manager.connect(ws)
    await manager.broadcast('{"type":"test","data":{}}')
    ws.send_text.assert_called_with('{"type":"test","data":{}}')


@pytest.mark.asyncio
async def test_broadcast_to_multiple_clients() -> None:
    manager = WebSocketManager()
    ws1, ws2 = _mock_ws(), _mock_ws()
    await manager.connect(ws1)
    await manager.connect(ws2)
    await manager.broadcast("hello")
    ws1.send_text.assert_called_with("hello")
    ws2.send_text.assert_called_with("hello")


# --------------------------------------------------------------------------- #
# Replay buffer                                                                #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_new_client_receives_buffered_events() -> None:
    manager = WebSocketManager()

    # Broadcast before any client connects
    await manager.broadcast('{"type":"scan_started"}')
    await manager.broadcast('{"type":"scanner_started"}')

    # New client connects — should receive both buffered events
    ws = _mock_ws()
    await manager.connect(ws)

    assert ws.send_text.call_count == 2
    calls = [c.args[0] for c in ws.send_text.call_args_list]
    assert any("scan_started" in c for c in calls)
    assert any("scanner_started" in c for c in calls)


@pytest.mark.asyncio
async def test_clear_buffer_removes_buffered_events() -> None:
    manager = WebSocketManager()
    await manager.broadcast('{"type":"old_event"}')
    manager.clear_buffer()

    ws = _mock_ws()
    await manager.connect(ws)
    ws.send_text.assert_not_called()


@pytest.mark.asyncio
async def test_buffer_respects_max_size() -> None:
    manager = WebSocketManager()
    manager._BUFFER_MAX = 5

    for i in range(10):
        await manager.broadcast(f'{{"type":"event_{i}"}}')

    # Buffer should only have last 5
    assert len(manager._buffer) == 5
    assert "event_9" in manager._buffer[-1]


# --------------------------------------------------------------------------- #
# Disconnect                                                                   #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_disconnect_removes_client() -> None:
    manager = WebSocketManager()
    ws = _mock_ws()
    await manager.connect(ws)
    assert manager.connection_count == 1
    manager.disconnect(ws)
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_dead_connection_removed_on_broadcast() -> None:
    manager = WebSocketManager()
    ws = _mock_ws()
    await manager.connect(ws)

    # Simulate send failure (dead connection)
    ws.send_text.side_effect = Exception("connection closed")
    await manager.broadcast("test")

    # Dead connection should be pruned
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_disconnect_idempotent() -> None:
    manager = WebSocketManager()
    ws = _mock_ws()
    await manager.connect(ws)
    manager.disconnect(ws)
    manager.disconnect(ws)  # second call must not raise
    assert manager.connection_count == 0
