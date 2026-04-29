"""Tests for API exposure scanner — unauth access, headers, rate limiting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vibe_iterator.scanners.api_exposure import Scanner
from vibe_iterator.scanners.base import Severity


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _make_config(target: str = "https://example.com") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "supabase"
    return cfg


def _make_req(
    url: str = "https://example.com/api/data",
    method: str = "GET",
    response_headers: dict | None = None,
    auth_header: bool = False,
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.response_headers = response_headers or {"content-type": "application/json"}
    req.status_code = 200
    req.headers = {"Authorization": "Bearer token123"} if auth_header else {}
    return req


def _run(requests: list, fetch_result=None, target: str = "https://example.com") -> list:
    scanner = Scanner()
    config = _make_config(target)
    net = MagicMock()
    net.get_requests.return_value = requests

    if fetch_result is not None:
        with patch(
            "vibe_iterator.scanners.api_exposure._fetch_without_auth",
            return_value=fetch_result,
        ):
            return scanner.run(session=None, listeners={"network": net}, config=config)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# --------------------------------------------------------------------------- #
# Unauthenticated access                                                        #
# --------------------------------------------------------------------------- #

def test_unauth_access_200_is_high() -> None:
    req = _make_req(auth_header=True)
    findings = _run([req], fetch_result=(200, {"content-type": "application/json"}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert len(unauth) == 1
    assert unauth[0].severity == Severity.HIGH


def test_unauth_access_on_sensitive_path_is_critical() -> None:
    req = _make_req(url="https://example.com/api/admin", auth_header=True)
    findings = _run([req], fetch_result=(200, {"content-type": "application/json"}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert len(unauth) == 1
    assert unauth[0].severity == Severity.CRITICAL


def test_unauth_access_401_no_finding() -> None:
    req = _make_req(auth_header=True)
    findings = _run([req], fetch_result=(401, {}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


def test_unauth_check_skipped_when_no_auth_header() -> None:
    req = _make_req(auth_header=False)
    findings = _run([req], fetch_result=(200, {}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


def test_unauth_fetch_failure_no_finding() -> None:
    req = _make_req(auth_header=True)
    findings = _run([req], fetch_result=None)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


# --------------------------------------------------------------------------- #
# Security headers (passive)                                                   #
# --------------------------------------------------------------------------- #

def test_missing_hsts_is_medium() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    findings = _run([req])
    hsts = [f for f in findings if "strict-transport-security" in f.title.lower()]
    assert len(hsts) == 1
    assert hsts[0].severity == Severity.MEDIUM


def test_missing_x_frame_options_is_low() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    findings = _run([req])
    frame = [f for f in findings if "x-frame-options" in f.title.lower()]
    assert len(frame) == 1
    assert frame[0].severity == Severity.LOW


def test_missing_x_content_type_options_is_low() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    findings = _run([req])
    ct = [f for f in findings if "x-content-type-options" in f.title.lower()]
    assert len(ct) == 1
    assert ct[0].severity == Severity.LOW


def test_present_security_headers_no_header_findings() -> None:
    req = _make_req(response_headers={
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    })
    findings = _run([req])
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


def test_response_headers_none_skipped() -> None:
    req = _make_req()
    req.response_headers = None
    findings = _run([req])
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


def test_header_findings_are_deduped() -> None:
    reqs = [_make_req(response_headers={"content-type": "text/html"}) for _ in range(3)]
    findings = _run(reqs)
    hsts = [f for f in findings if "strict-transport-security" in f.title.lower()]
    assert len(hsts) == 1


# --------------------------------------------------------------------------- #
# Rate limiting on auth endpoints                                               #
# --------------------------------------------------------------------------- #

def test_auth_endpoint_no_rate_limit_is_medium() -> None:
    req = _make_req(
        url="https://example.com/api/login",
        response_headers={"content-type": "application/json"},
    )
    findings = _run([req])
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert len(rl) == 1
    assert rl[0].severity == Severity.MEDIUM


def test_auth_endpoint_with_rate_limit_header_no_finding() -> None:
    req = _make_req(
        url="https://example.com/api/login",
        response_headers={
            "content-type": "application/json",
            "x-ratelimit-limit": "60",
        },
    )
    findings = _run([req])
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_non_auth_endpoint_no_rate_limit_finding() -> None:
    req = _make_req(
        url="https://example.com/api/products",
        response_headers={"content-type": "application/json"},
    )
    findings = _run([req])
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_retry_after_header_satisfies_rate_limit() -> None:
    req = _make_req(
        url="https://example.com/auth/token",
        response_headers={
            "content-type": "application/json",
            "retry-after": "60",
        },
    )
    findings = _run([req])
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []
