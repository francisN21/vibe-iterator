# tests/test_engine/test_discover_stage_routing.py
"""Test that runner.run('discover') routes to discover_runner, not scanner pipeline."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from vibe_iterator.engine.discover_runner import DiscoveryResult
from vibe_iterator.engine.runner import ScanRunner


def _make_config() -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.pages = ["/"]
    cfg.spider_max_pages = 30
    cfg.spider_max_depth = 3
    cfg.stack.backend = "custom"
    cfg.stack.detection_source = "auto-detect"
    return cfg


def test_discover_stage_returns_completed_result():
    config = _make_config()
    runner = ScanRunner(config, on_event=lambda e: None, scan_id="test-123")

    mock_discovery = DiscoveryResult(
        pages=["/", "/about"],
        api_endpoints=["GET /api/users"],
        discovered_at="2026-01-01T00:00:00Z",
    )

    with patch("vibe_iterator.engine.runner.browser_mod") as mock_browser, \
         patch("vibe_iterator.engine.runner.run_discovery", return_value=mock_discovery), \
         patch("vibe_iterator.engine.runner.NetworkListener") as mock_net_cls:
        mock_session = MagicMock()
        mock_browser.launch.return_value = mock_session
        mock_network = MagicMock()
        mock_net_cls.return_value = mock_network

        result = asyncio.run(runner.run("discover"))

    assert result.stage == "discover"
    assert result.status == "completed"
    assert result.discovered_surface is not None
    assert result.discovered_surface.pages == ["/", "/about"]
    assert result.scanner_results == []  # no scanners run


def test_discover_stage_does_not_run_scanner_pipeline():
    config = _make_config()
    runner = ScanRunner(config, on_event=lambda e: None, scan_id="test-456")

    mock_discovery = DiscoveryResult(pages=[], api_endpoints=[], discovered_at="")

    with patch("vibe_iterator.engine.runner.browser_mod") as mock_browser, \
         patch("vibe_iterator.engine.runner.run_discovery", return_value=mock_discovery), \
         patch("vibe_iterator.engine.runner.NetworkListener") as mock_net_cls, \
         patch("vibe_iterator.engine.runner._load_scanner") as mock_load:
        mock_browser.launch.return_value = MagicMock()
        mock_net_cls.return_value = MagicMock()

        asyncio.run(runner.run("discover"))

    mock_load.assert_not_called()
