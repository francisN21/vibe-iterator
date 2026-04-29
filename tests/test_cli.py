"""Tests for CLI wiring — flags, output, error handling."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from vibe_iterator.cli import cli, _check_target_reachable


# --------------------------------------------------------------------------- #
# Headless scan — core wiring                                                  #
# --------------------------------------------------------------------------- #

def test_scan_accepts_hidden_headless_flag_and_runs_engine() -> None:
    """The legacy --headless flag should not crash and should run ScanRunner."""
    config = SimpleNamespace(target="http://localhost:3000")
    result_obj = SimpleNamespace(status="completed", findings=[], score=100)
    runner_instance = MagicMock()
    runner_instance.run = AsyncMock(return_value=result_obj)

    with patch("vibe_iterator.config.load_config", return_value=config), \
            patch("vibe_iterator.engine.runner.ScanRunner", return_value=runner_instance), \
            patch("vibe_iterator.cli._check_target_reachable", return_value=True):
        result = CliRunner().invoke(
            cli,
            ["scan", "--headless", "--target", "http://localhost:3000", "--stage", "dev"],
        )

    assert result.exit_code == 0, result.output
    runner_instance.run.assert_awaited_once_with("dev")
    assert "Complete: status=completed" in result.output


def test_scan_exits_1_when_target_unreachable() -> None:
    config = SimpleNamespace(target="http://localhost:3000")

    with patch("vibe_iterator.config.load_config", return_value=config), \
            patch("vibe_iterator.cli._check_target_reachable", return_value=False):
        result = CliRunner().invoke(
            cli, ["scan", "--target", "http://localhost:3000", "--stage", "dev"],
        )

    assert result.exit_code == 1
    assert "unreachable" in result.output.lower() or "unreachable" in (result.stderr or "").lower()


# --------------------------------------------------------------------------- #
# --output flag writes report file                                             #
# --------------------------------------------------------------------------- #

def test_scan_output_flag_writes_report(tmp_path) -> None:
    out_file = str(tmp_path / "report.html")
    config = SimpleNamespace(target="http://localhost:3000")
    result_obj = SimpleNamespace(status="completed", findings=[], score=100)
    runner_instance = MagicMock()
    runner_instance.run = AsyncMock(return_value=result_obj)

    with patch("vibe_iterator.config.load_config", return_value=config), \
            patch("vibe_iterator.engine.runner.ScanRunner", return_value=runner_instance), \
            patch("vibe_iterator.cli._check_target_reachable", return_value=True), \
            patch("vibe_iterator.report.generator.generate", return_value="<html>report</html>") as mock_gen:
        result = CliRunner().invoke(
            cli,
            ["scan", "--target", "http://localhost:3000", "--stage", "dev", "--output", out_file],
        )

    assert result.exit_code == 0, result.output
    mock_gen.assert_called_once_with(result_obj, output_path=out_file)
    assert "Report saved to" in result.output


# --------------------------------------------------------------------------- #
# --verbose flag                                                               #
# --------------------------------------------------------------------------- #

def test_scan_verbose_passes_event_handler() -> None:
    config = SimpleNamespace(target="http://localhost:3000")
    result_obj = SimpleNamespace(status="completed", findings=[], score=100)
    runner_instance = MagicMock()
    runner_instance.run = AsyncMock(return_value=result_obj)

    captured_kwargs = {}

    def mock_runner_cls(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return runner_instance

    with patch("vibe_iterator.config.load_config", return_value=config), \
            patch("vibe_iterator.engine.runner.ScanRunner", side_effect=mock_runner_cls), \
            patch("vibe_iterator.cli._check_target_reachable", return_value=True):
        result = CliRunner().invoke(
            cli,
            ["scan", "--target", "http://localhost:3000", "--stage", "dev", "--verbose"],
        )

    assert result.exit_code == 0, result.output
    assert "on_event" in captured_kwargs


# --------------------------------------------------------------------------- #
# Config error handling                                                        #
# --------------------------------------------------------------------------- #

def test_scan_exits_1_on_config_error() -> None:
    from vibe_iterator.config import ConfigError

    with patch("vibe_iterator.config.load_config", side_effect=ConfigError("Missing .env")):
        result = CliRunner().invoke(cli, ["scan", "--stage", "dev"])

    assert result.exit_code == 1
    assert "Missing .env" in result.output


# --------------------------------------------------------------------------- #
# _check_target_reachable helper                                               #
# --------------------------------------------------------------------------- #

def test_check_target_reachable_returns_true_on_http_error() -> None:
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        url="http://x", code=404, msg="Not Found", hdrs=None, fp=None
    )):
        assert _check_target_reachable("http://localhost:3000") is True


def test_check_target_reachable_returns_false_on_connection_error() -> None:
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError("refused")):
        assert _check_target_reachable("http://localhost:3000") is False


# --------------------------------------------------------------------------- #
# Version flag                                                                 #
# --------------------------------------------------------------------------- #

def test_version_flag_exits_0() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
