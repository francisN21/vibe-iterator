"""rate_limit_check proof tests — real HTTP against VulnerableApp fixture, no Selenium."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.rate_limit_check import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="function")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str, deep_scan: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.rate_limit_deep_scan = deep_scan
    cfg.backend_url = None
    return cfg


def _run(vuln_app, deep_scan: bool = False, post_urls: list[str] | None = None) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url, deep_scan=deep_scan)
    network = MagicMock()
    reqs = []
    for url in (post_urls or []):
        r = MagicMock()
        r.method = "POST"
        r.url = url
        reqs.append(r)
    network.get_requests.return_value = reqs
    return scanner.run(session=None, listeners={"network": network}, config=config)


def test_proof_no_rate_limit_on_login(vuln_app) -> None:
    """/api/auth/login returns 401 10x with no 429 → Finding A for Login."""
    findings = _run(vuln_app)
    login_findings = [
        f for f in findings
        if "No rate limiting" in f.title and "Login" in f.title
    ]
    assert len(login_findings) >= 1
    assert login_findings[0].severity == Severity.MEDIUM


def test_proof_no_rate_limit_on_signup(vuln_app) -> None:
    """/api/auth/signup returns 200 10x with no 429 → Finding A for Signup."""
    findings = _run(vuln_app)
    signup_findings = [
        f for f in findings
        if "No rate limiting" in f.title and "Signup" in f.title
    ]
    assert len(signup_findings) >= 1
    assert signup_findings[0].severity == Severity.MEDIUM


def test_proof_lockout_on_forgot_password(vuln_app) -> None:
    """/api/auth/forgot-password switches 401→403 at attempt 5 → Finding B."""
    findings = _run(vuln_app)
    lockout_findings = [
        f for f in findings
        if "lockout" in f.title.lower()
    ]
    assert len(lockout_findings) >= 1
    f = lockout_findings[0]
    assert f.severity == Severity.LOW
    assert f.evidence["code_before"] == 401
    assert f.evidence["code_after"] == 403


def test_proof_negative_rate_limited_endpoint(vuln_app) -> None:
    """/api/auth/rate-limited-login returns 429+Retry-After → no finding for that endpoint."""
    findings = _run(
        vuln_app,
        deep_scan=True,
        post_urls=[vuln_app.base_url + "/api/auth/rate-limited-login"],
    )
    rl_login_findings = [
        f for f in findings
        if "rate-limited-login" in f.page
    ]
    assert rl_login_findings == []
