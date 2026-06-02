"""auth_check scanner proof tests — real HTTP against the vulnerable fixture app, no Selenium."""

from __future__ import annotations

from unittest.mock import MagicMock
import json
import urllib.error

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.auth_check import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_url = ""
    cfg.supabase_anon_key = ""
    cfg.test_email = "test@example.com"
    cfg.pages = []
    return cfg


def _make_storage() -> MagicMock:
    storage = MagicMock()
    storage.get_latest.return_value = None  # skip Group 1 token checks (requires real session)
    return storage


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_api_req(url: str, body: str = '{"data": "ok"}') -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = 200
    req.response_body = body
    req.post_data = None
    return req


def _run(vuln_app, network_requests=None) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests or [])
    storage = _make_storage()
    return scanner.run(session=None, listeners={"network": net, "storage": storage}, config=config)


# ---------------------------------------------------------------------------
# Group 3 — Brute-force / rate limiting
# ---------------------------------------------------------------------------

def test_no_rate_limiting_on_login_detected(vuln_app) -> None:
    # Scanner sends 10 rapid POSTs to /api/auth/login — fixture has no do_POST handler
    # (returns 501). 501 != 429, so scanner never sees rate limiting → MEDIUM finding.
    findings = _run(vuln_app)
    rate_limit = [f for f in findings if "rate limit" in f.title.lower()]
    assert len(rate_limit) >= 1
    assert rate_limit[0].severity == Severity.MEDIUM


def test_bruteforce_probe_uses_backend_url_with_frontend_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000")
    config.backend_url = "http://localhost:4001"
    requests_seen: list[tuple[str, str, dict, dict]] = []

    def fake_urlopen(req, timeout=0):
        body = json.loads(req.data.decode("utf-8"))
        requests_seen.append((req.full_url, req.get_method(), dict(req.header_items()), body))
        raise urllib.error.HTTPError(
            req.full_url,
            401,
            "Unauthorized",
            {},
            None,
        )

    monkeypatch.setattr("vibe_iterator.scanners.auth_check.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("vibe_iterator.scanners.auth_check._get_login_error_message", lambda *args: None)

    findings: list = []
    scanner._group3_login_security(
        session=None,
        config=config,
        findings=findings,
        stack="custom",
        network=_make_network([]),
    )

    assert len(requests_seen) == 10
    assert all(url == "http://localhost:4001/api/auth/login" for url, _, _, _ in requests_seen)
    assert all(method == "POST" for _, method, _, _ in requests_seen)
    assert all(headers["Origin"] == "http://localhost:3000" for _, _, headers, _ in requests_seen)
    assert all("email" in body and "password" in body for _, _, _, body in requests_seen)
    assert findings


# ---------------------------------------------------------------------------
# Group 5b — Unprotected API endpoints (replayed without auth header)
# ---------------------------------------------------------------------------

def test_unprotected_protected_endpoint_detected(vuln_app) -> None:
    # Mock a captured network request to /api/protected (200 with auth).
    # Scanner replays it without auth — fixture still returns 200 → HIGH.
    req = _make_api_req(
        url=vuln_app.base_url + "/api/protected",
        body='{"secret": "admin-token-abc123"}',
    )
    findings = _run(vuln_app, [req])
    bypass = [f for f in findings if "accessible without authentication" in f.title.lower()]
    assert len(bypass) >= 1
    assert bypass[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_unprotected_admin_endpoint_detected(vuln_app) -> None:
    # /api/admin is a sensitive path that returns 200 without any auth.
    req = _make_api_req(
        url=vuln_app.base_url + "/api/admin",
        body='{"users": ["alice", "bob"]}',
    )
    findings = _run(vuln_app, [req])
    bypass = [f for f in findings if "accessible without authentication" in f.title.lower()]
    assert len(bypass) >= 1
    assert bypass[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Negative — endpoint that returns 401 must not produce an auth-bypass finding
# ---------------------------------------------------------------------------

def test_protected_endpoint_returning_401_no_finding(vuln_app) -> None:
    req = _make_api_req(url=vuln_app.base_url + "/api/data")
    req.status_code = 401
    req.response_body = '{"error": "unauthorized"}'
    findings = _run(vuln_app, [req])
    bypass = [f for f in findings if "accessible without authentication" in f.title.lower()]
    assert bypass == []
