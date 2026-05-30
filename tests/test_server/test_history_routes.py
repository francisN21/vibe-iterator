"""Tests for GET /api/history and GET /api/history/{filename}."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from tests.test_server.test_routes import _make_config, _make_scan_result
from vibe_iterator.history import save_result
from vibe_iterator.server.app import create_app


def _config_with_results_dir(results_dir: Path) -> MagicMock:
    cfg = _make_config()
    cfg.results_dir = results_dir
    return cfg


async def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ---------------------------------------------------------------------------
# GET /api/history
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_history_empty(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get("/api/history")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_get_history_with_results(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    save_result(_make_scan_result(), results_dir)
    save_result(_make_scan_result(), results_dir)

    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get("/api/history")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 2
    for item in items:
        assert "filename" in item
        assert "stage" in item
        assert "score" in item
        assert "finding_count" in item


# ---------------------------------------------------------------------------
# GET /api/history/{filename}
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_historical_result_ok(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    result = _make_scan_result()
    path = save_result(result, results_dir)

    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get(f"/api/history/{path.name}")
    assert r.status_code == 200
    data = r.json()
    assert data["scan_id"] == result.scan_id
    assert data["stage"] == result.stage
    assert "findings" in data


@pytest.mark.asyncio
async def test_get_historical_result_invalid_name(tmp_path: Path) -> None:
    app = create_app(_config_with_results_dir(tmp_path))
    async with await _client(app) as c:
        r = await c.get("/api/history/notaresult.json")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_get_historical_result_not_found(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get("/api/history/result-20260530-120000.json")
    assert r.status_code == 404
