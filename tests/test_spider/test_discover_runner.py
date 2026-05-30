# tests/test_spider/test_discover_runner.py
"""Tests for discover_runner.py — mocks all spider components, no browser."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from vibe_iterator.engine.discover_runner import load_sidecar, run_discovery


def _cfg(max_pages: int = 30, max_depth: int = 3) -> MagicMock:
    c = MagicMock()
    c.target = "http://localhost:3000"
    c.pages = ["/", "/login"]
    c.spider_max_pages = max_pages
    c.spider_max_depth = max_depth
    return c


def _run(cfg, tmp_path: Path, sitemap=None, dom=None, js=None, api=None):
    session = MagicMock()
    network = MagicMock()
    network.get_requests.return_value = []
    with patch("vibe_iterator.engine.discover_runner.fetch_sitemap_routes",
               return_value=sitemap or []), \
         patch("vibe_iterator.engine.discover_runner.crawl_dom",
               return_value=dom or []), \
         patch("vibe_iterator.engine.discover_runner.extract_js_routes",
               return_value=js or []), \
         patch("vibe_iterator.engine.discover_runner.harvest_endpoints",
               return_value=api or []):
        return run_discovery(cfg, session, network, yaml_dir=tmp_path)


def test_sidecar_written():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _run(_cfg(), tmp_path, sitemap=["/about"], dom=["/contact"], api=["GET /api/users"])
        assert (tmp_path / "vibe-iterator.discovered.yaml").exists()


def test_pages_merged_and_sorted():
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(_cfg(), Path(tmp), sitemap=["/about"], dom=["/contact"])
        assert "/about" in result.pages
        assert "/contact" in result.pages
        assert result.pages == sorted(result.pages)


def test_api_endpoints_returned():
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(_cfg(), Path(tmp), api=["GET /api/users", "POST /api/auth/login"])
        assert "GET /api/users" in result.api_endpoints


def test_sidecar_written_when_empty():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _run(_cfg(), tmp_path)
        assert (tmp_path / "vibe-iterator.discovered.yaml").exists()


def test_load_sidecar_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _run(_cfg(), tmp_path, sitemap=["/a"], api=["GET /api/x"])
        loaded = load_sidecar(tmp_path)
        assert loaded is not None
        assert "/a" in loaded.pages
        assert "GET /api/x" in loaded.api_endpoints


def test_load_sidecar_absent_returns_none():
    with tempfile.TemporaryDirectory() as tmp:
        assert load_sidecar(Path(tmp)) is None
