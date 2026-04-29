"""Tests for the HTML report generator."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vibe_iterator.engine.runner import ScanResult, ScannerResult
from vibe_iterator.report.generator import generate, default_filename
from vibe_iterator.scanners.base import Finding, Severity


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _make_result(
    findings: list | None = None,
    score: int = 85,
    grade: str = "B",
) -> ScanResult:
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        stage="pre-deploy",
        target="https://example.com",
        status="completed",
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        findings=findings or [],
        scanner_results=[
            ScannerResult("cors_check", "passed", 0, 1.2),
            ScannerResult("xss_check", "findings", 1, 2.5),
        ],
        finding_marks=[],
        score=score,
        score_grade=grade,
        duration_seconds=10.5,
        pages_crawled=[{"url": "https://example.com/", "status_code": 200}],
        requests_captured={"total": 5, "GET": 5, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0},
        stack_detected="supabase",
        stack_detection_source="manually-configured",
        second_account_used=False,
        scanner_overrides_applied=None,
    )


def _make_finding(title: str = "Test Finding", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint="abc123",
        scanner="xss_check",
        severity=severity,
        title=title,
        description="A test finding description.",
        evidence={"endpoint": "https://example.com/api", "test_performed": "header_check"},
        screenshots=[],
        llm_prompt="You are a security expert...",
        remediation="**What to fix:** Add the header.",
        category="Injection",
        page="https://example.com/",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# --------------------------------------------------------------------------- #
# Basic rendering                                                               #
# --------------------------------------------------------------------------- #

def test_generate_returns_html_string() -> None:
    result = _make_result()
    html = generate(result)
    assert isinstance(html, str)
    assert "<html" in html.lower()
    assert "</html>" in html.lower()


def test_generated_html_contains_target() -> None:
    result = _make_result()
    html = generate(result)
    assert "example.com" in html


def test_generated_html_contains_score() -> None:
    result = _make_result(score=85, grade="B")
    html = generate(result)
    assert "85" in html
    assert "B" in html


def test_generated_html_contains_stage() -> None:
    result = _make_result()
    html = generate(result)
    assert "PRE-DEPLOY" in html


# --------------------------------------------------------------------------- #
# Findings in report                                                            #
# --------------------------------------------------------------------------- #

def test_finding_title_in_report() -> None:
    finding = _make_finding(title="Missing HSTS Header")
    result = _make_result(findings=[finding])
    html = generate(result)
    assert "Missing HSTS Header" in html


def test_finding_severity_in_report() -> None:
    finding = _make_finding(severity=Severity.CRITICAL)
    result = _make_result(findings=[finding])
    html = generate(result)
    assert "critical" in html.lower()


def test_finding_remediation_in_report() -> None:
    finding = _make_finding()
    result = _make_result(findings=[finding])
    html = generate(result)
    assert "What to fix" in html


def test_no_findings_shows_clean_message() -> None:
    result = _make_result(findings=[])
    html = generate(result)
    assert "clean" in html.lower() or "no findings" in html.lower()


# --------------------------------------------------------------------------- #
# Self-contained check — no external resources                                  #
# --------------------------------------------------------------------------- #

def test_no_external_cdn_links() -> None:
    result = _make_result()
    html = generate(result)
    # Should not reference CDN URLs
    assert "cdn.jsdelivr.net" not in html
    assert "cdnjs.cloudflare.com" not in html
    assert "unpkg.com" not in html
    assert "googleapis.com/css" not in html


# --------------------------------------------------------------------------- #
# File output                                                                   #
# --------------------------------------------------------------------------- #

def test_generate_writes_to_file(tmp_path: Path) -> None:
    result = _make_result()
    out = str(tmp_path / "report.html")
    html = generate(result, output_path=out)
    written = Path(out).read_text(encoding="utf-8")
    assert written == html
    assert len(written) > 100


# --------------------------------------------------------------------------- #
# Default filename                                                               #
# --------------------------------------------------------------------------- #

def test_default_filename_format() -> None:
    result = _make_result()
    name = default_filename(result)
    assert name.startswith("vibe-iterator-report-")
    assert name.endswith(".html")


# --------------------------------------------------------------------------- #
# Multiple findings / categories                                                #
# --------------------------------------------------------------------------- #

def test_multiple_findings_in_different_categories() -> None:
    f1 = _make_finding("XSS Finding", Severity.HIGH)
    f1.category = "Injection"
    f2 = _make_finding("CORS Finding", Severity.MEDIUM)
    f2.category = "Misconfiguration"
    result = _make_result(findings=[f1, f2])
    html = generate(result)
    assert "XSS Finding" in html
    assert "CORS Finding" in html
    assert "Injection" in html
    assert "Misconfiguration" in html


def test_scanner_results_in_report() -> None:
    result = _make_result()
    html = generate(result)
    assert "cors_check" in html
    assert "xss_check" in html
