"""Contracts for repository CI gates."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ci_runs_scanner_exposure_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python scripts/check_scanner_exposure.py" in workflow


def test_ci_runs_pytest_coverage_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "--cov=vibe_iterator" in workflow
    assert "--cov-fail-under=" in workflow
