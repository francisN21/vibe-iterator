"""Tests for CORS scanner — wildcard, reflected origin, null origin, credentials."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vibe_iterator.scanners.cors_check import Scanner
from vibe_iterator.scanners.base import Severity


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _make_config(target: str = "https://example.com") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "supabase"
    return cfg


def _make_req(url: str = "https://example.com/api/data") -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.response_headers = {"content-type": "application/json"}
    return req


def _make_network(urls: list[str]) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = [_make_req(u) for u in urls]
    return net


def _run_scanner(headers_by_origin: dict, target: str = "https://example.com") -> list:
    scanner = Scanner()
    config = _make_config(target)
    listeners = {"network": _make_network([f"{target}/api/data"])}

    def fake_fetch(url, origin, timeout=5):
        return headers_by_origin.get(origin)

    with patch("vibe_iterator.scanners.cors_check._fetch_with_origin", side_effect=fake_fetch):
        return scanner.run(session=None, listeners=listeners, config=config)


# --------------------------------------------------------------------------- #
# Wildcard + credentials — CRITICAL                                            #
# --------------------------------------------------------------------------- #

def test_wildcard_with_credentials_is_critical() -> None:
    findings = _run_scanner({
        "https://evil-attacker.com": {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        "null": {},
    })
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "credentials" in findings[0].title.lower()


# --------------------------------------------------------------------------- #
# Reflected origin — HIGH                                                       #
# --------------------------------------------------------------------------- #

def test_reflected_origin_is_high() -> None:
    findings = _run_scanner({
        "https://evil-attacker.com": {
            "access-control-allow-origin": "https://evil-attacker.com",
        },
        "null": {},
    })
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "reflected" in findings[0].title.lower()


# --------------------------------------------------------------------------- #
# Wildcard only (no creds) — LOW                                               #
# --------------------------------------------------------------------------- #

def test_wildcard_no_credentials_is_low() -> None:
    findings = _run_scanner({
        "https://evil-attacker.com": {
            "access-control-allow-origin": "*",
        },
        "null": {},
    })
    severities = {f.severity for f in findings}
    assert Severity.LOW in severities
    assert Severity.CRITICAL not in severities


# --------------------------------------------------------------------------- #
# Null origin — MEDIUM                                                          #
# --------------------------------------------------------------------------- #

def test_null_origin_accepted_is_medium() -> None:
    findings = _run_scanner({
        "https://evil-attacker.com": {},
        "null": {"access-control-allow-origin": "null"},
    })
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "null" in findings[0].title.lower()


# --------------------------------------------------------------------------- #
# No CORS issues — clean                                                        #
# --------------------------------------------------------------------------- #

def test_no_cors_issues_returns_no_findings() -> None:
    findings = _run_scanner({
        "https://evil-attacker.com": {
            "access-control-allow-origin": "https://example.com",
        },
        "null": {},
    })
    assert findings == []


# --------------------------------------------------------------------------- #
# Network fetch failure — graceful                                              #
# --------------------------------------------------------------------------- #

def test_fetch_failure_returns_no_findings() -> None:
    findings = _run_scanner({
        "https://evil-attacker.com": None,
        "null": None,
    })
    assert findings == []


# --------------------------------------------------------------------------- #
# Deduplication                                                                 #
# --------------------------------------------------------------------------- #

def test_duplicate_findings_are_deduped() -> None:
    scanner = Scanner()
    config = _make_config()
    net = _make_network([
        "https://example.com/api/data",
        "https://example.com/api/data",  # same path, should dedup
    ])
    listeners = {"network": net}

    def fake_fetch(url, origin, timeout=5):
        if origin == "https://evil-attacker.com":
            return {"access-control-allow-origin": "https://evil-attacker.com"}
        return {}

    with patch("vibe_iterator.scanners.cors_check._fetch_with_origin", side_effect=fake_fetch):
        findings = scanner.run(session=None, listeners=listeners, config=config)

    # Same URL + same issue should produce exactly one finding
    reflected = [f for f in findings if "reflected" in f.title.lower()]
    assert len(reflected) == 1
