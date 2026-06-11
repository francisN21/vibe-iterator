"""Integration tests for API inventory wiring in normal scans."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vibe_iterator.api_inventory import ApiIntelligenceConfig, ApiInventory
from vibe_iterator.engine.runner import ScanRunner
from vibe_iterator.listeners.network import NetworkRequest


def _make_config() -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.test_email = "test@example.com"
    cfg.test_password = "password"
    cfg.second_account_configured = False
    cfg.stack = SimpleNamespace(backend="supabase", detection_source="manually-configured")
    cfg.pages = ["/", "/dashboard"]
    cfg.scanner_timeout_seconds = 10
    cfg.scanners_for_stage.return_value = ["api_exposure"]
    cfg.api_intelligence = ApiIntelligenceConfig()
    return cfg


@pytest.mark.asyncio
async def test_normal_scan_injects_api_inventory_into_scanner_and_result() -> None:
    cfg = _make_config()
    runner = ScanRunner(cfg, on_event=lambda event: None, scan_id="inventory-test")

    scanner = MagicMock()
    scanner.name = "api_exposure"
    scanner.category = "API Exposure"
    scanner.requires_stack = ["any"]
    scanner.requires_second_account = False
    scanner.run.return_value = []

    network = MagicMock()
    network.get_requests.return_value = [
        NetworkRequest(
            request_id="request-1",
            method="POST",
            url="http://localhost:3000/api/projects/123?include=owner",
            headers={"Content-Type": "application/json", "Authorization": "Bearer test"},
            post_data='{"role":"admin"}',
            timestamp=1.0,
            status_code=201,
            response_headers={"Content-Type": "application/json"},
        )
    ]
    network.summary.return_value = {"total": 1, "GET": 0, "POST": 1, "PUT": 0, "DELETE": 0, "PATCH": 0}

    pages = [
        SimpleNamespace(url="http://localhost:3000/", status_code=200),
        SimpleNamespace(url="http://localhost:3000/dashboard", status_code=200),
    ]

    with patch("vibe_iterator.engine.runner._load_scanner", return_value=scanner), \
            patch("vibe_iterator.engine.runner.browser_mod.launch", return_value=MagicMock()), \
            patch("vibe_iterator.crawler.auth.login"), \
            patch("vibe_iterator.crawler.navigator.crawl_pages", return_value=pages), \
            patch("vibe_iterator.engine.runner.NetworkListener", return_value=network), \
            patch("vibe_iterator.listeners.console.ConsoleListener"), \
            patch("vibe_iterator.listeners.storage.StorageListener"):
        result = await runner.run("dev")

    _, listeners, _ = scanner.run.call_args.args
    api_inventory = listeners["api_inventory"]

    assert isinstance(api_inventory, ApiInventory)
    assert api_inventory.endpoints[0].method == "POST"
    assert api_inventory.endpoints[0].normalized_path == "/api/projects/{id}"
    assert result.discovered_surface is not None
    assert result.discovered_surface.api_inventory is api_inventory
