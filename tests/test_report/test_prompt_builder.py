"""Tests for LLM fix prompt builder."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from vibe_iterator.report.prompt_builder import build_prompt, _format_evidence
from vibe_iterator.scanners.base import Finding, Severity


def _finding(**overrides) -> Finding:
    defaults = dict(
        id=str(uuid.uuid4()),
        fingerprint="abc123",
        scanner="cors_check",
        severity=Severity.HIGH,
        title="Test Vulnerability",
        description="An attacker can do bad things.",
        evidence={},
        screenshots=[],
        llm_prompt="",
        remediation="Fix it.",
        category="Misconfiguration",
        page="https://example.com/api",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --------------------------------------------------------------------------- #
# build_prompt structure                                                        #
# --------------------------------------------------------------------------- #

def test_prompt_contains_title() -> None:
    f = _finding(title="Missing HSTS Header")
    p = build_prompt(f, stack="supabase")
    assert "Missing HSTS Header" in p


def test_prompt_contains_severity() -> None:
    f = _finding(severity=Severity.CRITICAL)
    p = build_prompt(f, stack="supabase")
    assert "CRITICAL" in p


def test_prompt_contains_stack() -> None:
    f = _finding()
    p = build_prompt(f, stack="supabase")
    assert "supabase" in p.lower()


def test_prompt_contains_page() -> None:
    f = _finding(page="https://example.com/login")
    p = build_prompt(f, stack="nextjs")
    assert "https://example.com/login" in p


def test_prompt_contains_description() -> None:
    f = _finding(description="Sensitive data exposed in response.")
    p = build_prompt(f, stack="custom")
    assert "Sensitive data exposed" in p


def test_prompt_default_stack() -> None:
    f = _finding()
    p = build_prompt(f)
    assert "unknown" in p


# --------------------------------------------------------------------------- #
# _format_evidence — various evidence structures                                #
# --------------------------------------------------------------------------- #

def test_format_request_response() -> None:
    f = _finding(evidence={
        "request": {"method": "GET", "url": "https://example.com/api", "body": None},
        "response": {"status": 200, "body_excerpt": "sensitive data"},
    })
    ev = _format_evidence(f)
    assert "GET" in ev
    assert "https://example.com/api" in ev
    assert "sensitive data" in ev


def test_format_payload() -> None:
    f = _finding(evidence={
        "payload_used": "' OR 1=1--",
        "injection_point": "query_param:id",
    })
    ev = _format_evidence(f)
    assert "' OR 1=1--" in ev
    assert "query_param:id" in ev


def test_format_expected_actual() -> None:
    f = _finding(evidence={
        "expected_response": "401 Unauthorized",
        "actual_response": "200 OK",
        "action_attempted": "access without auth",
    })
    ev = _format_evidence(f)
    assert "401" in ev
    assert "200" in ev
    assert "access without auth" in ev


def test_format_auth_check_evidence() -> None:
    f = _finding(evidence={
        "check_name": "session_fixation",
        "observed_value": "same session after login",
        "expected_behavior": "new session ID after authentication",
    })
    ev = _format_evidence(f)
    assert "session_fixation" in ev
    assert "same session after login" in ev


def test_format_storage_tampering() -> None:
    f = _finding(evidence={
        "storage_key": "user_tier",
        "original_value": "free",
        "tampered_value": "premium",
    })
    ev = _format_evidence(f)
    assert "user_tier" in ev
    assert "free" in ev
    assert "premium" in ev


def test_format_data_leakage() -> None:
    f = _finding(evidence={
        "leak_type": "jwt_in_console",
        "leak_location": "console.log",
        "leaked_value_excerpt": "eyJ...",
    })
    ev = _format_evidence(f)
    assert "jwt_in_console" in ev
    assert "eyJ..." in ev


def test_format_cors_evidence() -> None:
    f = _finding(evidence={
        "test_origin_sent": "https://evil.com",
        "response_headers": {"Access-Control-Allow-Origin": "https://evil.com"},
    })
    ev = _format_evidence(f)
    assert "https://evil.com" in ev


def test_format_empty_evidence_fallback() -> None:
    f = _finding(evidence={})
    ev = _format_evidence(f)
    assert "full evidence" in ev.lower() or len(ev) > 0


def test_format_request_body_truncated() -> None:
    long_body = "x" * 500
    f = _finding(evidence={
        "request": {"method": "POST", "url": "https://x.com", "body": long_body},
        "response": {"status": 200},
    })
    ev = _format_evidence(f)
    assert len(ev) < 600  # body is truncated to 200 chars
