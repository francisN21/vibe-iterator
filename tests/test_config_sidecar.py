# tests/test_config_sidecar.py
"""Test that load_config merges vibe-iterator.discovered.yaml into config.pages."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import yaml
import pytest
from vibe_iterator.config import load_config


def _write_yaml(path: Path, data: dict) -> None:
    with path.open("w") as fh:
        yaml.dump(data, fh)


def test_sidecar_pages_merged_into_config():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Write minimal config YAML
        _write_yaml(tmp_path / "vibe-iterator.config.yaml", {
            "target": "http://localhost:3000",
            "pages": ["/", "/login"],
        })
        # Write sidecar with extra pages
        _write_yaml(tmp_path / "vibe-iterator.discovered.yaml", {
            "pages": ["/about", "/admin"],
            "api_endpoints": ["GET /api/users"],
            "discovered_at": "2026-01-01T00:00:00Z",
        })
        env = {
            "VIBE_ITERATOR_TEST_EMAIL": "test@example.com",
            "VIBE_ITERATOR_TEST_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env):
            cfg = load_config(yaml_path=tmp_path / "vibe-iterator.config.yaml")
        assert "/about" in cfg.pages
        assert "/admin" in cfg.pages
        assert "/" in cfg.pages
        assert "/login" in cfg.pages


def test_no_sidecar_leaves_pages_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write_yaml(tmp_path / "vibe-iterator.config.yaml", {
            "target": "http://localhost:3000",
            "pages": ["/", "/login"],
        })
        env = {
            "VIBE_ITERATOR_TEST_EMAIL": "test@example.com",
            "VIBE_ITERATOR_TEST_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env):
            cfg = load_config(yaml_path=tmp_path / "vibe-iterator.config.yaml")
        assert cfg.pages == ["/", "/login"]


def test_sidecar_does_not_duplicate_existing_pages():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write_yaml(tmp_path / "vibe-iterator.config.yaml", {
            "target": "http://localhost:3000",
            "pages": ["/", "/login"],
        })
        _write_yaml(tmp_path / "vibe-iterator.discovered.yaml", {
            "pages": ["/", "/about"],   # "/" already in config
            "api_endpoints": [],
            "discovered_at": "2026-01-01T00:00:00Z",
        })
        env = {
            "VIBE_ITERATOR_TEST_EMAIL": "test@example.com",
            "VIBE_ITERATOR_TEST_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env):
            cfg = load_config(yaml_path=tmp_path / "vibe-iterator.config.yaml")
        assert cfg.pages.count("/") == 1  # no duplicate
        assert "/about" in cfg.pages
