"""API exposure scanner proof tests — run against the vulnerable fixture app (real HTTP, no Selenium)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.api_exposure import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    return cfg


def _make_req(
    url: str,
    method: str = "GET",
    response_headers: dict | None = None,
    request_headers: dict | None = None,
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.response_headers = response_headers or {"content-type": "application/json"}
    req.headers = request_headers or {}
    req.status_code = 200
    return req


def _run(vuln_app, requests: list) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = MagicMock()
    net.get_requests.return_value = requests
    return scanner.run(session=None, listeners={"network": net}, config=config)


# --------------------------------------------------------------------------- #
# Unauthenticated access — /api/protected (HIGH)                              #
# --------------------------------------------------------------------------- #

def test_unauth_access_protected_detected(vuln_app) -> None:
    reqs = [_make_req(
        vuln_app.base_url + "/api/protected",
        request_headers={"Authorization": "Bearer fake-jwt"},
    )]
    findings = _run(vuln_app, reqs)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert len(unauth) >= 1
    assert unauth[0].severity in (Severity.HIGH, Severity.CRITICAL)


# --------------------------------------------------------------------------- #
# Unauthenticated access — /api/admin (CRITICAL — sensitive path)             #
# --------------------------------------------------------------------------- #

def test_unauth_access_admin_is_critical(vuln_app) -> None:
    reqs = [_make_req(
        vuln_app.base_url + "/api/admin",
        request_headers={"Authorization": "Bearer fake-jwt"},
    )]
    findings = _run(vuln_app, reqs)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert len(unauth) >= 1
    assert unauth[0].severity == Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Missing security headers (passive)                                           #
# --------------------------------------------------------------------------- #

def test_missing_security_headers_detected(vuln_app) -> None:
    # Vulnerable app returns no X-Content-Type-Options, X-Frame-Options, or HSTS
    reqs = [_make_req(vuln_app.base_url + "/api/data")]
    findings = _run(vuln_app, reqs)
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert len(header_findings) >= 1


def test_x_content_type_options_missing(vuln_app) -> None:
    reqs = [_make_req(vuln_app.base_url + "/api/data")]
    findings = _run(vuln_app, reqs)
    xcto = [
        f for f in findings
        if "x-content-type-options" in f.title.lower()
    ]
    assert len(xcto) >= 1
    assert xcto[0].severity == Severity.LOW


# --------------------------------------------------------------------------- #
# Active rate-limit probe — /api/login returns no 429                         #
# --------------------------------------------------------------------------- #

def test_rate_limit_probe_no_429_detected(vuln_app) -> None:
    reqs = [_make_req(
        vuln_app.base_url + "/api/login",
        response_headers={"content-type": "application/json"},
    )]
    findings = _run(vuln_app, reqs)
    rate_findings = [f for f in findings if "rate limit" in f.title.lower()]
    assert len(rate_findings) >= 1
    assert rate_findings[0].severity == Severity.MEDIUM


# --------------------------------------------------------------------------- #
# No false positive on endpoint that has security headers                      #
# --------------------------------------------------------------------------- #

def test_no_unauth_finding_when_no_auth_header_in_original(vuln_app) -> None:
    # Request has no auth header — scanner should skip unauthenticated check
    reqs = [_make_req(
        vuln_app.base_url + "/api/data",
        request_headers={},
    )]
    findings = _run(vuln_app, reqs)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []
