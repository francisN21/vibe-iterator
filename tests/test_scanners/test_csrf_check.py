"""CSRF scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.csrf_check import (
    Scanner,
    _discover_state_changing_requests,
    _has_state_change_success,
    _strip_csrf_headers,
)


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999", backend_url: str | None = None) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.backend_url = backend_url
    cfg.stack.backend = "custom"
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(
    url: str,
    *,
    method: str = "POST",
    headers: dict | None = None,
    post_data: str = '{"display_name":"Mallory"}',
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.status_code = 200
    req.response_body = ""
    req.post_data = post_data
    req.headers = headers or {
        "Content-Type": "application/json",
        "Cookie": "session=fixture-session",
        "X-CSRF-Token": "legit-token",
    }
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_csrf_detects_cross_site_state_change(vuln_app) -> None:
    req = _make_req(vuln_app.base_url + "/api/csrf-profile")

    findings = _run(vuln_app, [req])

    csrf = [f for f in findings if "csrf" in f.title.lower()]
    assert len(csrf) == 1
    assert csrf[0].severity == Severity.HIGH
    assert csrf[0].evidence["proof_quality"] == "cross_site_state_change_accepted"
    assert csrf[0].evidence["stripped_headers"] == ["x-csrf-token"]
    assert csrf[0].evidence["request"]["headers"]["Origin"] == "https://evil.example"


def test_no_finding_without_cookie_authenticated_context() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/csrf-profile", headers={"Content-Type": "application/json"})
    net = _make_network([req])

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_no_finding_for_rejected_cross_site_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/csrf-profile")
    net = _make_network([req])

    def fake_send(url, method, headers, body, timeout=5):
        return 403, {"content-type": "application/json"}, '{"error":"csrf required"}'

    monkeypatch.setattr("vibe_iterator.scanners.csrf_check._send_cross_site_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_no_finding_for_success_status_without_mutation_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/csrf-profile")
    net = _make_network([req])

    def fake_send(url, method, headers, body, timeout=5):
        return 200, {"content-type": "application/json"}, '{"preview":true}'

    monkeypatch.setattr("vibe_iterator.scanners.csrf_check._send_cross_site_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_csrf_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req("http://localhost:3000/api/csrf-profile")
    net = _make_network([req])
    calls: list[tuple[str, str, dict, bytes | None]] = []

    def fake_send(url, method, headers, body, timeout=5):
        calls.append((url, method, headers, body))
        return 200, {"content-type": "application/json"}, '{"updated":true}'

    monkeypatch.setattr("vibe_iterator.scanners.csrf_check._send_cross_site_probe", fake_send)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 1
    assert calls
    assert calls[0][0] == "http://localhost:4001/api/csrf-profile"
    assert calls[0][1] == "POST"
    assert calls[0][2]["Origin"] == "https://evil.example"
    assert "X-CSRF-Token" not in calls[0][2]


def test_discovery_filters_safe_static_duplicate_and_cookieless_requests() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_req(target + "/api/csrf-profile"),
        _make_req(target + "/api/csrf-profile", post_data='{"display_name":"Alice"}'),
        _make_req(target + "/api/csrf-profile", method="GET"),
        _make_req(target + "/app.js", headers={"Cookie": "session=x"}),
        _make_req(target + "/api/csrf-profile", headers={"Content-Type": "application/json"}),
        _make_req("https://third-party.example/api/csrf-profile", headers={"Cookie": "session=x"}),
    ]
    net = _make_network(requests)

    assert _discover_state_changing_requests(net, target) == [requests[0]]


def test_strip_csrf_headers_and_success_classifier() -> None:
    headers, stripped = _strip_csrf_headers({
        "Content-Type": "application/json",
        "Cookie": "session=x",
        "X-CSRF-Token": "abc",
        "X-XSRF-Token": "def",
        "Origin": "http://localhost:3000",
    })

    assert stripped == ["x-csrf-token", "x-xsrf-token"]
    assert headers["Origin"] == "https://evil.example"
    assert "X-CSRF-Token" not in headers
    assert _has_state_change_success('{"updated":true}') == ("updated", True)
    assert _has_state_change_success('{"data":{"deleted":true}}') == ("data.deleted", True)
    assert _has_state_change_success('{"preview":true}') is None


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "csrf_check"
    assert s.category == "API Security"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
