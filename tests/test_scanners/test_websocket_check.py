"""WebSocket auth/origin scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.websocket_check import (
    Scanner,
    _discover_websocket_targets,
    _rewrite_ws_to_backend,
    _strip_auth_headers,
    _websocket_handshake,
    _with_untrusted_origin,
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


def _make_req(url: str, *, headers: dict | None = None, method: str = "GET") -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.status_code = 101
    req.response_body = ""
    req.post_data = None
    req.headers = headers if headers is not None else {
        "Upgrade": "websocket",
        "Authorization": "Bearer test-token",
        "Origin": "http://localhost:9999",
    }
    req.response_mime_type = ""
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_websocket_detects_unauthenticated_and_untrusted_origin_acceptance(vuln_app) -> None:
    ws_url = vuln_app.base_url.replace("http://", "ws://") + "/socket"
    req = _make_req(ws_url)

    findings = _run(vuln_app, [req])

    proof_qualities = {f.evidence["proof_quality"] for f in findings}
    assert proof_qualities == {
        "unauthenticated_websocket_accepted",
        "untrusted_origin_websocket_accepted",
    }
    assert all(f.severity in {Severity.HIGH, Severity.MEDIUM} for f in findings)


def test_no_finding_when_handshakes_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("ws://localhost:9999/socket")
    net = _make_network([req])

    def fake_handshake(url, headers=None, timeout=5):
        return 403, {"content-type": "text/plain"}

    monkeypatch.setattr("vibe_iterator.scanners.websocket_check._websocket_handshake", fake_handshake)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_websocket_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req("ws://localhost:3000/socket")
    net = _make_network([req])
    calls: list[tuple[str, dict | None]] = []

    def fake_handshake(url, headers=None, timeout=5):
        calls.append((url, headers))
        return 101, {"upgrade": "websocket"}

    monkeypatch.setattr("vibe_iterator.scanners.websocket_check._websocket_handshake", fake_handshake)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 2
    assert calls
    assert calls[0][0] == "ws://localhost:4001/socket"
    assert calls[0][1] == {"Origin": "http://localhost:3000"}


def test_discovery_filters_static_non_websocket_third_party_and_duplicates() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_req("ws://localhost:9999/socket"),
        _make_req("ws://localhost:9999/socket"),
        _make_req("http://localhost:9999/socket", headers={"Upgrade": "websocket"}),
        _make_req("http://localhost:9999/app.js", headers={"Upgrade": "websocket"}),
        _make_req("http://localhost:9999/api/data", headers={}),
        _make_req("ws://third-party.example/socket"),
    ]
    net = _make_network(requests)

    assert _discover_websocket_targets(net, target) == ["ws://localhost:9999/socket"]


def test_header_helpers_and_backend_rewrite() -> None:
    headers = _strip_auth_headers({
        "Authorization": "Bearer token",
        "Cookie": "session=x",
        "Origin": "http://localhost:3000",
        "X-Trace": "abc",
    }, origin="http://localhost:3000")

    assert headers == {"Origin": "http://localhost:3000", "X-Trace": "abc"}
    assert _with_untrusted_origin(headers)["Origin"] == "https://evil.example"
    assert _rewrite_ws_to_backend("ws://localhost:3000/socket", _make_config("http://localhost:3000", "http://localhost:4001")) == "ws://localhost:4001/socket"
    assert _rewrite_ws_to_backend("wss://app.example/socket", _make_config("https://app.example", "https://api.example")) == "wss://api.example/socket"


def test_raw_websocket_handshake_accepts_fixture(vuln_app) -> None:
    ws_url = vuln_app.base_url.replace("http://", "ws://") + "/socket"

    status, headers = _websocket_handshake(ws_url, headers={"Origin": "https://evil.example"})

    assert status == 101
    assert headers["upgrade"].lower() == "websocket"


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "websocket_check"
    assert s.category == "API Security"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
