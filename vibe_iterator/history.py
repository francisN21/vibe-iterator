"""Scan result persistence — JSON serializer, save/load helpers."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from vibe_iterator.engine.runner import ScanResult
from vibe_iterator.scanners.base import Finding

_FILENAME_RE = re.compile(r"^result-\d{8}-\d{6}(-\d+)?\.json$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "scanner": f.scanner,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "evidence": f.evidence,
        "screenshots": [{"label": s.label, "data": s.data} for s in f.screenshots],
        "llm_prompt": f.llm_prompt,
        "remediation": f.remediation,
        "category": f.category,
        "page": f.page,
        "timestamp": f.timestamp,
        "mark_status": f.mark_status,
        "mark_note": f.mark_note,
    }


def serialize_result(result: ScanResult) -> dict:
    return {
        "scan_id": result.scan_id,
        "stage": result.stage,
        "target": result.target,
        "status": result.status,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "findings": [finding_dict(f) for f in result.findings],
        "scanner_results": [
            {
                "scanner_name": sr.scanner_name,
                "status": sr.status,
                "findings_count": sr.findings_count,
                "duration_seconds": sr.duration_seconds,
                "skip_reason": sr.skip_reason,
            }
            for sr in result.scanner_results
        ],
        "finding_marks": [
            {"finding_id": m.finding_id, "status": m.status, "note": m.note}
            for m in result.finding_marks
        ],
        "score": result.score,
        "score_grade": result.score_grade,
        "duration_seconds": result.duration_seconds,
        "pages_crawled": result.pages_crawled,
        "requests_captured": result.requests_captured,
        "stack_detected": result.stack_detected,
        "stack_detection_source": result.stack_detection_source,
        "second_account_used": result.second_account_used,
        "scanner_overrides_applied": result.scanner_overrides_applied,
        "discovered_surface": {
            "pages": result.discovered_surface.pages,
            "api_endpoints": result.discovered_surface.api_endpoints,
            "discovered_at": result.discovered_surface.discovered_at,
        } if result.discovered_surface is not None else None,
    }


# ---------------------------------------------------------------------------
# File management
# ---------------------------------------------------------------------------

def save_result(result: ScanResult, results_dir: Path) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    base = _now().strftime("result-%Y%m%d-%H%M%S")
    candidate = results_dir / f"{base}.json"
    counter = 2
    while candidate.exists():
        candidate = results_dir / f"{base}-{counter}.json"
        counter += 1
    candidate.write_text(json.dumps(serialize_result(result), indent=2), encoding="utf-8")
    return candidate


def list_results(results_dir: Path) -> list[dict]:
    if not results_dir.exists():
        return []
    items: list[dict] = []
    for path in sorted(results_dir.glob("result-*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            items.append({
                "filename": path.name,
                "timestamp": data.get("completed_at") or data.get("started_at"),
                "stage": data.get("stage", ""),
                "target": data.get("target", ""),
                "score": data.get("score"),
                "score_grade": data.get("score_grade"),
                "finding_count": len(data.get("findings", [])),
                "status": data.get("status", ""),
            })
        except Exception as exc:
            print(f"[WARN] Skipping corrupt result file {path.name}: {exc}", file=sys.stderr)
    return items


def load_result(filename: str, results_dir: Path) -> dict:
    if not _FILENAME_RE.match(filename):
        raise ValueError(f"Invalid result filename: {filename!r}")
    path = results_dir / filename
    if not path.exists():
        raise FileNotFoundError(f"Result not found: {filename}")
    return json.loads(path.read_text(encoding="utf-8"))
