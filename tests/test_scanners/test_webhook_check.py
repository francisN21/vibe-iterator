"""Webhook signature scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.webhook_check import (
    Scanner,
    _body_bytes,
    _discover_webhook_endpoints,
    _has_webhook_acceptance,
    _invalid_signature_headers,
    _strip_signature_headers,
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
    post_data: str = '{"type":"invoice.paid","id":"evt_fixture"}',
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.status_code = 200
    req.response_body = ""
    req.post_data = post_data
    req.headers = headers or {
        "Content-Type": "application/json",
        "Stripe-Signature": "t=1,v1=valid",
    }
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_webhook_detects_unsigned_event_acceptance(vuln_app) -> None:
    req = _make_req(vuln_app.base_url + "/api/webhooks/stripe")

    findings = _run(vuln_app, [req])

    webhook = [f for f in findings if "webhook" in f.title.lower()]
    assert len(webhook) == 1
    assert webhook[0].severity == Severity.HIGH
    assert webhook[0].evidence["proof_quality"] == "unsigned_webhook_accepted"
    assert webhook[0].evidence["stripped_headers"] == ["stripe-signature"]
    assert webhook[0].evidence["acceptance_evidence"]["json_path"] == "received"


def test_invalid_signature_checked_after_missing_signature_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/webhooks/stripe")
    net = _make_network([req])
    calls: list[dict] = []

    def fake_send(url, headers, body, timeout=5):
        calls.append(headers)
        if len(calls) == 1:
            return 401, {"content-type": "application/json"}, '{"error":"missing signature"}'
        return 200, {"content-type": "application/json"}, '{"processed":true}'

    monkeypatch.setattr("vibe_iterator.scanners.webhook_check._send_webhook_probe", fake_send)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 1
    assert findings[0].evidence["proof_quality"] == "invalid_webhook_signature_accepted"
    assert calls[1]["Stripe-Signature"] == "t=0,v1=invalid"


def test_no_finding_for_rejected_unsigned_and_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/webhooks/stripe")
    net = _make_network([req])

    def fake_send(url, headers, body, timeout=5):
        return 403, {"content-type": "application/json"}, '{"error":"bad signature"}'

    monkeypatch.setattr("vibe_iterator.scanners.webhook_check._send_webhook_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_no_finding_for_accepted_status_without_processing_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/webhooks/stripe")
    net = _make_network([req])

    def fake_send(url, headers, body, timeout=5):
        return 200, {"content-type": "application/json"}, '{"preview":true}'

    monkeypatch.setattr("vibe_iterator.scanners.webhook_check._send_webhook_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_webhook_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req("http://localhost:3000/api/webhooks/stripe")
    net = _make_network([req])
    calls: list[tuple[str, dict, bytes | None]] = []

    def fake_send(url, headers, body, timeout=5):
        calls.append((url, headers, body))
        return 200, {"content-type": "application/json"}, '{"received":true}'

    monkeypatch.setattr("vibe_iterator.scanners.webhook_check._send_webhook_probe", fake_send)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 1
    assert calls
    assert calls[0][0] == "http://localhost:4001/api/webhooks/stripe"
    assert "Stripe-Signature" not in calls[0][1]
    assert calls[0][2] == b'{"type":"invoice.paid","id":"evt_fixture"}'


def test_discovery_filters_static_non_post_third_party_and_duplicates() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_req(target + "/api/webhooks/stripe"),
        _make_req(target + "/api/webhooks/stripe", post_data='{"type":"customer.created"}'),
        _make_req(target + "/api/webhooks/stripe", method="GET"),
        _make_req(target + "/app.js"),
        _make_req("https://third-party.example/api/webhooks/stripe"),
    ]
    net = _make_network(requests)

    assert _discover_webhook_endpoints(net, target) == [requests[0]]


def test_discovery_allows_configured_backend_url() -> None:
    target = "http://localhost:3000"
    backend = "http://localhost:4001"
    req = _make_req(backend + "/api/webhooks/stripe")
    net = _make_network([req])

    assert _discover_webhook_endpoints(net, target, backend_url=backend) == [req]


def test_signature_stripping_and_acceptance_classifier() -> None:
    headers, stripped = _strip_signature_headers({
        "Content-Type": "application/json",
        "Stripe-Signature": "t=1,v1=valid",
        "X-Hub-Signature-256": "sha256=valid",
    })

    assert stripped == ["stripe-signature", "x-hub-signature-256"]
    assert headers == {"Content-Type": "application/json"}
    assert _has_webhook_acceptance('{"received":true}') == ("received", True)
    assert _has_webhook_acceptance('{"data":{"processed":true}}') == ("data.processed", True)
    assert _has_webhook_acceptance('{"events":[{"accepted":true}]}') == ("events[0].accepted", True)
    assert _has_webhook_acceptance('{"preview":true}') is None
    assert _has_webhook_acceptance("not json") is None


def test_invalid_signature_defaults_and_body_bytes() -> None:
    assert _invalid_signature_headers({"Content-Type": "application/json"}, []) == {
        "Content-Type": "application/json",
        "Stripe-Signature": "t=0,v1=invalid",
    }
    assert _invalid_signature_headers({}, ["x-slack-signature"]) == {"X-Slack-Signature": "t=0,v1=invalid"}
    assert _body_bytes(None) is None
    assert _body_bytes(b"raw-body") == b"raw-body"
    assert _body_bytes({"type": "invoice.paid"}) == b"{'type': 'invoice.paid'}"


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "webhook_check"
    assert s.category == "API Security"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
