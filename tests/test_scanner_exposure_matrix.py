"""Repo-wide scanner exposure contracts."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

from vibe_iterator.config import _DEFAULT_STAGES, _VALID_SCANNER_NAMES
from vibe_iterator.engine.runner import _SCANNER_MODULE_MAP
from vibe_iterator.server.routes import _SCANNER_META


REQUIRED_META_FIELDS = {
    "label",
    "category",
    "description",
    "est_seconds",
    "requires_stack",
    "requires_second_account",
    "mutates_state",
    "risk_level",
}

VALID_RISK_LEVELS = {"low", "medium", "high"}


def test_every_registered_scanner_is_exposed_through_config_and_server_metadata() -> None:
    registered = set(_SCANNER_MODULE_MAP)
    preset_names = {
        scanner_name
        for scanner_names in _DEFAULT_STAGES.values()
        for scanner_name in scanner_names
    }

    assert registered - preset_names == set()
    assert preset_names - registered == set()
    assert registered - set(_VALID_SCANNER_NAMES) == set()
    assert set(_VALID_SCANNER_NAMES) - preset_names == set()
    assert registered - set(_SCANNER_META) == set()
    assert set(_SCANNER_META) - registered == set()


def test_scanner_modules_are_importable_and_match_server_metadata() -> None:
    for scanner_name, module_path in _SCANNER_MODULE_MAP.items():
        scanner = importlib.import_module(module_path).Scanner()
        meta = _SCANNER_META[scanner_name]

        assert scanner.name == scanner_name
        assert scanner.category == meta["category"]
        assert scanner.requires_stack == meta["requires_stack"]
        assert scanner.requires_second_account == meta["requires_second_account"]


def test_scanner_metadata_has_dashboard_risk_fields() -> None:
    for scanner_name, meta in _SCANNER_META.items():
        assert REQUIRED_META_FIELDS - set(meta) == set(), scanner_name
        assert isinstance(meta["mutates_state"], bool), scanner_name
        assert meta["risk_level"] in VALID_RISK_LEVELS, scanner_name
        assert isinstance(meta["est_seconds"], int), scanner_name
        assert meta["est_seconds"] > 0, scanner_name


def test_scanner_exposure_script_passes() -> None:
    script = Path("scripts/check_scanner_exposure.py")

    result = subprocess.run(
        [sys.executable, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
