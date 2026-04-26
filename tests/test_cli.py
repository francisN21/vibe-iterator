"""Tests for CLI wiring."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from vibe_iterator.cli import cli


def test_scan_accepts_hidden_headless_flag_and_runs_engine() -> None:
    """The legacy --headless flag should not crash and should run ScanRunner."""
    config = SimpleNamespace(target="http://localhost:3000")
    result_obj = SimpleNamespace(status="completed", findings=[], score=100)
    runner_instance = MagicMock()
    runner_instance.run = AsyncMock(return_value=result_obj)

    with patch("vibe_iterator.config.load_config", return_value=config) as load_config, \
            patch("vibe_iterator.engine.runner.ScanRunner", return_value=runner_instance) as runner_cls:
        result = CliRunner().invoke(
            cli,
            ["scan", "--headless", "--target", "http://localhost:3000", "--stage", "dev"],
        )

    assert result.exit_code == 0, result.output
    load_config.assert_called_once_with(target_override="http://localhost:3000")
    assert runner_cls.call_args.kwargs["browser_headless"] is True
    runner_instance.run.assert_awaited_once_with("dev")
    assert "Complete: status=completed" in result.output
