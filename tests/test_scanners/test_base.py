"""Tests for the Finding dataclass, BaseScanner contract, and helpers."""

from __future__ import annotations

import pytest

from vibe_iterator.scanners.base import (
    BaseScanner, Finding, Screenshot, ScanEvent, Severity,
)


class TestFindingDataclass:
    def test_finding_has_required_fields(self) -> None:
        f = Finding(
            id="abc", fingerprint="fp1", scanner="test_scanner",
            severity=Severity.HIGH, title="Test", description="desc",
            evidence={}, screenshots=[], llm_prompt="prompt",
            remediation="fix", category="Injection",
            page="http://localhost:3000/", timestamp="2024-01-01T00:00:00Z",
        )
        assert f.id == "abc"
        assert f.severity == Severity.HIGH
        assert f.mark_status == "none"
        assert f.mark_note is None

    def test_finding_mark_defaults(self) -> None:
        f = Finding(
            id="x", fingerprint="y", scanner="s", severity=Severity.LOW,
            title="T", description="D", evidence={}, screenshots=[],
            llm_prompt="p", remediation="r", category="C",
            page="http://localhost/", timestamp="2024-01-01T00:00:00Z",
        )
        assert f.mark_status == "none"
        assert f.mark_note is None

    def test_screenshot_dataclass(self) -> None:
        s = Screenshot(label="Before", data="data:image/png;base64,abc")
        assert s.label == "Before"
        assert s.data.startswith("data:image/png")


class TestBaseScannerContract:
    def test_run_raises_not_implemented(self) -> None:
        scanner = BaseScanner()
        with pytest.raises(NotImplementedError):
            scanner.run(None, {}, None)

    def test_make_fingerprint_is_stable(self) -> None:
        fp1 = BaseScanner.make_fingerprint("rls_bypass", "IDOR on profiles", "http://app.com/dashboard")
        fp2 = BaseScanner.make_fingerprint("rls_bypass", "IDOR on profiles", "http://app.com/dashboard")
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_make_fingerprint_differs_by_input(self) -> None:
        fp1 = BaseScanner.make_fingerprint("scanner_a", "Title", "http://a.com/")
        fp2 = BaseScanner.make_fingerprint("scanner_b", "Title", "http://a.com/")
        fp3 = BaseScanner.make_fingerprint("scanner_a", "Different Title", "http://a.com/")
        assert fp1 != fp2
        assert fp1 != fp3

    def test_new_finding_generates_id_and_fingerprint(self) -> None:
        f = BaseScanner.new_finding(
            scanner="data_leakage", severity=Severity.MEDIUM,
            title="JWT exposed", description="desc",
            evidence={"url": "http://app.com/api"},
            llm_prompt="prompt", remediation="fix",
            category="Data Leakage", page="http://app.com/api",
        )
        assert len(f.id) == 36   # uuid4 format
        assert len(f.fingerprint) == 16
        assert f.scanner == "data_leakage"
        assert f.screenshots == []
        assert f.mark_status == "none"

    def test_new_finding_fingerprint_matches_manual(self) -> None:
        f = BaseScanner.new_finding(
            scanner="auth_check", severity=Severity.HIGH,
            title="My Title", description="desc", evidence={},
            llm_prompt="", remediation="", category="Auth",
            page="http://app.com/",
        )
        expected = BaseScanner.make_fingerprint("auth_check", "My Title", "http://app.com/")
        assert f.fingerprint == expected

    def test_build_llm_prompt_structure(self) -> None:
        prompt = BaseScanner.build_llm_prompt(
            title="Test Vuln", severity=Severity.CRITICAL,
            scanner="test", page="http://app.com/", category="Injection",
            description="This is bad.", evidence_summary="Request: GET /api",
            stack="supabase",
        )
        assert "VULNERABILITY: Test Vuln" in prompt
        assert "SEVERITY: CRITICAL" in prompt
        assert "SCANNER: test" in prompt
        assert "WHAT WAS FOUND:" in prompt
        assert "EVIDENCE:" in prompt
        assert "MY STACK: SUPABASE" in prompt.upper()


class TestScanEvent:
    def test_scan_event_now(self) -> None:
        event = ScanEvent.now("scanner_started", {"scanner_name": "test"})
        assert event.type == "scanner_started"
        assert "T" in event.timestamp   # ISO 8601 contains T separator
        assert event.data["scanner_name"] == "test"

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
