"""Info disclosure scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock
import urllib.error

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.info_disclosure import Scanner, _MAX_CONSECUTIVE_PROBE_FAILURES
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(url: str, status: int = 200, body: str = "", headers: dict | None = None) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = status
    req.response_body = body
    req.response_headers = headers or {}
    req.post_data = None
    return req


def _run(vuln_app, network_requests=None) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests or [])
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Group 1 — sensitive path probing (against live fixture)
# ---------------------------------------------------------------------------

def test_swagger_json_exposed(vuln_app) -> None:
    findings = _run(vuln_app)
    swagger = [f for f in findings if "swagger" in f.title.lower() or "api doc" in f.title.lower()]
    assert len(swagger) >= 1
    assert swagger[0].severity in (Severity.MEDIUM, Severity.HIGH)
    assert swagger[0].evidence["proof_quality"] == "api_documentation_response"


def test_env_file_exposed(vuln_app) -> None:
    findings = _run(vuln_app)
    env_f = [f for f in findings if ".env" in f.title.lower() or "environment" in f.title.lower()]
    assert len(env_f) >= 1
    assert env_f[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert env_f[0].evidence["proof_quality"] == "env_file_key_value_response"


def test_spa_fallback_200_is_not_sensitive_path_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()

    class AppShellResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def read(self, _limit):
            return (
                b'<!doctype html><html><head><title>App</title></head>'
                b'<body><div id="root"></div><script src="/assets/app.js"></script></body></html>'
            )

    monkeypatch.setattr(
        "vibe_iterator.scanners.info_disclosure.urllib.request.urlopen",
        lambda *args, **kwargs: AppShellResponse(),
    )

    findings: list = []
    scanner._probe_sensitive_paths("http://example.test", "custom", findings)

    assert findings == []


# ---------------------------------------------------------------------------
# Group 2 — version header detection (mock)
# ---------------------------------------------------------------------------

def test_version_header_server_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/api/data",
        headers={"Server": "Apache/2.4.41 (Ubuntu)", "Content-Type": "application/json"},
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    version = [f for f in findings if "version" in f.title.lower() or "server" in f.title.lower()]
    assert len(version) >= 1
    assert version[0].severity == Severity.LOW


def test_x_powered_by_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/api/data",
        headers={"X-Powered-By": "Express", "Content-Type": "application/json"},
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    powered = [f for f in findings if "powered" in f.title.lower() or "version" in f.title.lower()]
    assert len(powered) >= 1


# ---------------------------------------------------------------------------
# Group 3 — stack trace in 500 response (mock)
# ---------------------------------------------------------------------------

def test_stack_trace_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/api/error",
        status=500,
        body='{"error": "Traceback (most recent call last):\\n  File app.py line 42\\nValueError: bad input"}',
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    stack = [f for f in findings if "stack trace" in f.title.lower() or "traceback" in f.title.lower()]
    assert len(stack) >= 1
    assert stack[0].severity in (Severity.MEDIUM, Severity.HIGH)


# ---------------------------------------------------------------------------
# Group 4 — hardcoded secret in JS (mock)
# ---------------------------------------------------------------------------

def test_stripe_key_in_js_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/app.js",
        body="const stripeKey = 'sk_live_AbCdEfGhIjKlMnOpQrStUvWx';",
        headers={"Content-Type": "application/javascript"},
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    secret = [f for f in findings if "secret" in f.title.lower() or "key" in f.title.lower() or "stripe" in f.title.lower()]
    assert len(secret) >= 1
    assert secret[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Negative — clean responses produce no findings
# ---------------------------------------------------------------------------

def test_no_finding_on_clean_app() -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:19999")  # nothing listening — all probes fail
    net = _make_network([])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    # Path probes all fail (no server), no network traffic → no findings
    assert findings == []


def test_sensitive_path_probe_aborts_after_repeated_connection_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    calls = 0

    def fail_connect(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("vibe_iterator.scanners.info_disclosure.urllib.request.urlopen", fail_connect)

    findings: list = []
    scanner._probe_sensitive_paths("http://example.invalid", "custom", findings)

    assert findings == []
    assert calls == _MAX_CONSECUTIVE_PROBE_FAILURES


def test_local_closed_port_skips_sensitive_path_urlopen(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    calls = 0

    def fail_if_called(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("urlopen should not be called for a closed local port")

    monkeypatch.setattr("vibe_iterator.scanners.info_disclosure.urllib.request.urlopen", fail_if_called)

    findings: list = []
    scanner._probe_sensitive_paths("http://127.0.0.1:1", "custom", findings)

    assert findings == []
    assert calls == 0


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "info_disclosure"
    assert s.category == "Misconfiguration"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
