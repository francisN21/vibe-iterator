"""SSRF scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory, ApiParameter
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.ssrf_check import (
    Scanner,
    _discover_ssrf_params,
    _fetch_no_redirect,
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


def _make_get_req(url: str) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = 200
    req.response_body = ""
    req.post_data = None
    req.headers = {}
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_ssrf_detects_server_side_callback(vuln_app) -> None:
    req = _make_get_req(vuln_app.base_url + "/api/fetch?url=https://example.com/avatar.png")

    findings = _run(vuln_app, [req])

    ssrf = [f for f in findings if "ssrf" in f.title.lower()]
    assert len(ssrf) == 1
    assert ssrf[0].severity == Severity.HIGH
    assert ssrf[0].evidence["proof_quality"] == "ssrf_callback_received"
    assert ssrf[0].evidence["callback"]["received"] is True
    assert ssrf[0].evidence["injection_point"] == "query_param:url"


def test_no_finding_when_probe_does_not_trigger_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/api/echo?url=https://example.com/avatar.png")
    net = _make_network([req])

    def fake_fetch(url, origin=None, timeout=5):
        return 200, {}, "echo only"

    monkeypatch.setattr("vibe_iterator.scanners.ssrf_check._fetch_no_redirect", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_no_finding_for_redirect_to_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/api/fetch?url=https://example.com/avatar.png")
    net = _make_network([req])

    def fake_fetch(url, origin=None, timeout=5):
        return 302, {"location": "http://127.0.0.1:7777/vibe-ssrf-proof"}, ""

    monkeypatch.setattr("vibe_iterator.scanners.ssrf_check._fetch_no_redirect", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_backend_url_routes_ssrf_probe_with_frontend_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_get_req("http://localhost:3000/api/fetch?url=https://example.com/avatar.png")
    net = _make_network([req])
    calls: list[tuple[str, str | None]] = []

    class FakeCallback:
        url = "http://127.0.0.1:7777/vibe-ssrf-proof"
        received = False
        received_path = None
        received_headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def wait(self, timeout=0.4):
            return self.received

    fake_callback = FakeCallback()

    def fake_start_callback_server():
        return fake_callback

    def fake_fetch(url, origin=None, timeout=5):
        calls.append((url, origin))
        fake_callback.received = True
        fake_callback.received_path = "/vibe-ssrf-proof"
        return 200, {}, "ok"

    monkeypatch.setattr("vibe_iterator.scanners.ssrf_check._start_callback_server", fake_start_callback_server)
    monkeypatch.setattr("vibe_iterator.scanners.ssrf_check._fetch_no_redirect", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 1
    assert calls
    assert calls[0][0] == "http://localhost:4001/api/fetch?url=http%3A%2F%2F127.0.0.1%3A7777%2Fvibe-ssrf-proof"
    assert calls[0][1] == "http://localhost:3000"


def test_ssrf_uses_inventory_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("https://example.com")
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/fetch",
                origin="https://example.com",
                path="/api/fetch",
                normalized_path="/api/fetch",
                parameters=[ApiParameter("url", "query", [], "inferred", "needs_review", False)],
                sources=["network"],
                risk_tags=["ssrf"],
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 1},
        warnings=[],
    )

    class FakeCallback:
        url = "http://127.0.0.1:7777/vibe-ssrf-proof"
        received_path = "/vibe-ssrf-proof"
        received_headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def wait(self, timeout=0.4):
            return True

    monkeypatch.setattr("vibe_iterator.scanners.ssrf_check._start_callback_server", FakeCallback)
    monkeypatch.setattr(
        "vibe_iterator.scanners.ssrf_check._fetch_no_redirect",
        lambda *args, **kwargs: (200, {}, "ok"),
    )

    findings = scanner.run(
        session=None,
        listeners={"network": _make_network([]), "api_inventory": inv},
        config=config,
    )

    assert any(f.evidence.get("inventory_parameters_used") == ["url"] for f in findings)
    assert findings[0].evidence["inventory_endpoint"] == "GET /api/fetch"
    assert findings[0].evidence["inventory_source"] == "network"


def test_discovery_filters_static_non_get_unknown_and_duplicate_params() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_get_req(target + "/api/fetch?url=https://example.com/a.png"),
        _make_get_req(target + "/api/fetch?url=https://example.com/b.png"),
        _make_get_req(target + "/app.js?url=https://example.com/a.png"),
        _make_get_req(target + "/api/fetch?name=https://example.com/a.png"),
        _make_get_req("https://third-party.example/api/fetch?url=https://example.com/a.png"),
    ]
    requests[3].method = "POST"
    net = _make_network(requests)

    assert _discover_ssrf_params(net, target) == [
        (target + "/api/fetch?url=https://example.com/a.png", "url")
    ]


def test_fetch_no_redirect_does_not_follow_location(vuln_app) -> None:
    status, headers, body = _fetch_no_redirect(
        vuln_app.base_url + "/api/redirect?next=https://example.com/phish",
        origin="http://localhost:3000",
    )

    assert status == 302
    assert headers["location"] == "https://example.com/phish"
    assert body == ""


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "ssrf_check"
    assert s.category == "API Security"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
