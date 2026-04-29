"""HTML report generator — builds a self-contained, exportable scan report."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from vibe_iterator.engine.runner import ScanResult

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_CSS_FILE = Path(__file__).parent.parent / "server" / "static" / "css" / "dashboard.css"

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate(result: ScanResult, *, output_path: str | None = None) -> str:
    """Render a self-contained HTML report for *result*.

    Returns the rendered HTML string. If *output_path* is supplied, also writes
    it to that file path.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")

    css = ""
    if _CSS_FILE.exists():
        css = _CSS_FILE.read_text(encoding="utf-8")

    context = _build_context(result, css)
    html = template.render(**context)

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html


def default_filename(result: ScanResult) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"vibe-iterator-report-{ts}.html"


# --------------------------------------------------------------------------- #
# Context builder                                                              #
# --------------------------------------------------------------------------- #

def _build_context(result: ScanResult, css: str) -> dict[str, Any]:
    findings_by_cat: dict[str, list[dict]] = {}
    for f in result.findings:
        cat = f.category or "Uncategorized"
        findings_by_cat.setdefault(cat, [])
        findings_by_cat[cat].append(_finding_ctx(f))

    # Sort categories by worst severity within each
    def _cat_sort_key(item: tuple[str, list]) -> int:
        sevs = [_SEV_ORDER.get(fd["severity"], 99) for fd in item[1]]
        return min(sevs) if sevs else 99

    sorted_categories = dict(sorted(findings_by_cat.items(), key=_cat_sort_key))

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in result.findings:
        key = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
        if key in sev_counts:
            sev_counts[key] += 1

    scanner_results = [
        {
            "name": sr.scanner_name,
            "status": sr.status,
            "findings_count": sr.findings_count,
            "duration": round(sr.duration_seconds, 1) if sr.duration_seconds else None,
            "skip_reason": sr.skip_reason,
        }
        for sr in result.scanner_results
    ]

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "css": css,
        "result": result,
        "target": result.target,
        "stage": result.stage.upper(),
        "status": result.status,
        "score": result.score,
        "score_grade": result.score_grade,
        "score_color": _grade_color(result.score_grade),
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration": round(result.duration_seconds, 1) if result.duration_seconds else None,
        "total_findings": len(result.findings),
        "sev_counts": sev_counts,
        "findings_by_cat": sorted_categories,
        "scanner_results": scanner_results,
        "pages_crawled": result.pages_crawled or [],
        "requests_captured": result.requests_captured or {},
        "stack_detected": result.stack_detected or "unknown",
        "generated_at": generated_at,
    }


def _finding_ctx(f: Any) -> dict:
    sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
    return {
        "id": f.id,
        "title": f.title,
        "severity": sev,
        "description": f.description,
        "remediation": f.remediation or "",
        "page": f.page or "",
        "scanner": f.scanner,
        "llm_prompt": f.llm_prompt or "",
        "evidence": f.evidence or {},
        "mark_status": getattr(f, "mark_status", None),
    }


def _grade_color(grade: str | None) -> str:
    return {
        "A": "#00ff41",
        "B": "#00d4ff",
        "C": "#ffb000",
        "D": "#ff6600",
        "F": "#ff0040",
    }.get(grade or "", "#888898")
