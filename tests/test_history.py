"""Tests for history.py — JSON serializer, file management helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vibe_iterator.engine.runner import ScannerResult, ScanResult
from vibe_iterator.history import (
    finding_dict,
    list_results,
    load_result,
    save_result,
    serialize_result,
)
from vibe_iterator.scanners.base import Finding, Severity


def _make_finding() -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint="fp-1",
        scanner="test_scanner",
        severity=Severity.HIGH,
        title="Test Finding",
        description="A test vulnerability.",
        evidence={"request": {"url": "http://localhost:3000/api/test"}},
        screenshots=[],
        llm_prompt="Fix this.",
        remediation="Apply a patch.",
        category="injection",
        page="http://localhost:3000/api/test",
        timestamp=datetime.now(timezone.utc).isoformat(),
        mark_status="none",
        mark_note=None,
    )


def _make_result(stage: str = "pre-deploy", score: int = 72) -> ScanResult:
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        stage=stage,
        target="http://localhost:3000",
        status="completed",
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        findings=[_make_finding()],
        scanner_results=[
            ScannerResult(
                scanner_name="auth_check",
                status="findings",
                findings_count=1,
                duration_seconds=2.1,
            ),
        ],
        finding_marks=[],
        score=score,
        score_grade="C",
        duration_seconds=5.3,
        pages_crawled=[{"url": "http://localhost:3000/", "status_code": 200}],
        requests_captured={"total": 10, "GET": 8, "POST": 2},
        stack_detected="custom",
        stack_detection_source="manually-configured",
        second_account_used=False,
        scanner_overrides_applied=None,
        discovered_surface=None,
    )


# ---------------------------------------------------------------------------
# finding_dict
# ---------------------------------------------------------------------------

def test_finding_dict_severity_is_string() -> None:
    f = _make_finding()
    d = finding_dict(f)
    assert d["severity"] == "high"
    assert isinstance(d["severity"], str)


def test_finding_dict_all_keys_present() -> None:
    f = _make_finding()
    d = finding_dict(f)
    for key in (
        "id", "fingerprint", "scanner", "severity", "title", "description",
        "evidence", "screenshots", "llm_prompt", "remediation", "category",
        "page", "timestamp", "mark_status", "mark_note",
    ):
        assert key in d, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# serialize_result
# ---------------------------------------------------------------------------

def test_serialize_result_structure() -> None:
    r = _make_result()
    d = serialize_result(r)
    for key in (
        "scan_id", "stage", "target", "status", "findings",
        "scanner_results", "finding_marks", "score", "score_grade",
        "discovered_surface",
    ):
        assert key in d, f"Missing top-level key: {key}"
    assert isinstance(d["findings"], list)
    assert d["findings"][0]["severity"] == "high"


def test_serialize_result_discovered_surface_none() -> None:
    r = _make_result()
    assert r.discovered_surface is None
    assert serialize_result(r)["discovered_surface"] is None


# ---------------------------------------------------------------------------
# save_result
# ---------------------------------------------------------------------------

def test_save_result_creates_file(tmp_path: Path) -> None:
    r = _make_result()
    path = save_result(r, tmp_path)
    assert path.exists()
    assert path.suffix == ".json"
    data = json.loads(path.read_text())
    assert data["scan_id"] == r.scan_id


def test_save_result_creates_directory(tmp_path: Path) -> None:
    results_dir = tmp_path / "vibe-iterator-results"
    assert not results_dir.exists()
    save_result(_make_result(), results_dir)
    assert results_dir.exists()


def test_save_result_filename_pattern(tmp_path: Path) -> None:
    import re
    path = save_result(_make_result(), tmp_path)
    assert re.match(r"result-\d{8}-\d{6}(-\d+)?\.json$", path.name)


def test_save_result_deduplication(tmp_path: Path, monkeypatch) -> None:
    # Two saves with the same mocked timestamp produce different filenames
    import vibe_iterator.history as hist_mod
    fixed_dt = datetime(2026, 5, 30, 14, 30, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(hist_mod, "_now", lambda: fixed_dt)
    r = _make_result()
    p1 = save_result(r, tmp_path)
    p2 = save_result(r, tmp_path)
    assert p1 != p2
    assert p2.stem.endswith("-2")


# ---------------------------------------------------------------------------
# list_results
# ---------------------------------------------------------------------------

def test_list_results_missing_directory(tmp_path: Path) -> None:
    assert list_results(tmp_path / "nonexistent") == []


def test_list_results_empty_directory(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    assert list_results(results_dir) == []


def test_list_results_sorted_newest_first(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    files = [
        ("result-20260530-100000.json", "2026-05-30T10:00:00Z"),
        ("result-20260530-120000.json", "2026-05-30T12:00:00Z"),
        ("result-20260530-080000.json", "2026-05-30T08:00:00Z"),
    ]
    for name, ts in files:
        (results_dir / name).write_text(json.dumps({
            "completed_at": ts,
            "stage": "dev",
            "target": "http://localhost:3000",
            "score": 80,
            "score_grade": "B",
            "findings": [],
            "status": "completed",
        }))
    items = list_results(results_dir)
    assert len(items) == 3
    assert items[0]["filename"] == "result-20260530-120000.json"
    assert items[2]["filename"] == "result-20260530-080000.json"


def test_list_results_skips_corrupt_file(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "result-20260530-100000.json").write_text(json.dumps({
        "completed_at": "2026-05-30T10:00:00Z",
        "stage": "dev",
        "target": "http://localhost:3000",
        "score": 80,
        "score_grade": "B",
        "findings": [],
        "status": "completed",
    }))
    (results_dir / "result-20260530-090000.json").write_text("NOT VALID JSON{{{{")
    items = list_results(results_dir)
    assert len(items) == 1
    assert items[0]["filename"] == "result-20260530-100000.json"


# ---------------------------------------------------------------------------
# load_result
# ---------------------------------------------------------------------------

def test_load_result_roundtrip(tmp_path: Path) -> None:
    r = _make_result()
    path = save_result(r, tmp_path)
    loaded = load_result(path.name, tmp_path)
    assert loaded["scan_id"] == r.scan_id
    assert loaded["stage"] == r.stage
    assert len(loaded["findings"]) == 1


def test_load_result_invalid_filename(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_result("../secrets.json", tmp_path)
    with pytest.raises(ValueError):
        load_result("notaresult.json", tmp_path)
    with pytest.raises(ValueError):
        load_result("result-bad.json", tmp_path)


def test_load_result_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_result("result-20260530-120000.json", tmp_path)
