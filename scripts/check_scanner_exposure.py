"""Validate scanner registration, presets, metadata, and imports."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vibe_iterator.config import _DEFAULT_STAGES, _VALID_SCANNER_NAMES  # noqa: E402
from vibe_iterator.engine.runner import _SCANNER_MODULE_MAP  # noqa: E402
from vibe_iterator.server.routes import _SCANNER_META  # noqa: E402

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


def build_report() -> dict[str, Any]:
    registered = set(_SCANNER_MODULE_MAP)
    preset_names = {
        scanner_name
        for scanner_names in _DEFAULT_STAGES.values()
        for scanner_name in scanner_names
    }

    report: dict[str, Any] = {
        "registered": len(registered),
        "preset_names": len(preset_names),
        "missing_from_presets": sorted(registered - preset_names),
        "invalid_presets": sorted(preset_names - registered),
        "missing_valid": sorted(registered - set(_VALID_SCANNER_NAMES)),
        "valid_without_preset": sorted(set(_VALID_SCANNER_NAMES) - preset_names),
        "missing_meta": sorted(registered - set(_SCANNER_META)),
        "meta_without_module": sorted(set(_SCANNER_META) - registered),
        "metadata_gaps": {},
        "metadata_mismatches": {},
        "import_errors": {},
    }

    for scanner_name, meta in _SCANNER_META.items():
        missing_fields = sorted(REQUIRED_META_FIELDS - set(meta))
        invalid_risk = meta.get("risk_level") not in VALID_RISK_LEVELS
        invalid_mutation = not isinstance(meta.get("mutates_state"), bool)
        if missing_fields or invalid_risk or invalid_mutation:
            report["metadata_gaps"][scanner_name] = {
                "missing_fields": missing_fields,
                "invalid_risk_level": invalid_risk,
                "invalid_mutates_state": invalid_mutation,
            }

    for scanner_name, module_path in _SCANNER_MODULE_MAP.items():
        try:
            scanner = importlib.import_module(module_path).Scanner()
        except Exception as exc:  # pragma: no cover - exercised by script smoke
            report["import_errors"][scanner_name] = str(exc)
            continue

        meta = _SCANNER_META.get(scanner_name, {})
        mismatches = {}
        if scanner.name != scanner_name:
            mismatches["name"] = {"scanner": scanner.name, "expected": scanner_name}
        for field in ("category", "requires_stack", "requires_second_account"):
            if getattr(scanner, field) != meta.get(field):
                mismatches[field] = {
                    "scanner": getattr(scanner, field),
                    "server_meta": meta.get(field),
                }
        if mismatches:
            report["metadata_mismatches"][scanner_name] = mismatches

    return report


def report_has_failures(report: dict[str, Any]) -> bool:
    failure_keys = [
        "missing_from_presets",
        "invalid_presets",
        "missing_valid",
        "valid_without_preset",
        "missing_meta",
        "meta_without_module",
        "metadata_gaps",
        "metadata_mismatches",
        "import_errors",
    ]
    return any(report[key] for key in failure_keys)


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report_has_failures(report) else 0


if __name__ == "__main__":
    raise SystemExit(main())
