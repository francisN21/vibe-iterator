"""Unsafe payload scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.unsafe_payload_check import (
    Scanner,
    _body_bytes,
    _discover_unsafe_payload_targets,
    _has_parser_error_signature,
    _has_ssti_evaluation,
    _inject_json_field,
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
    post_data: str = '{"template":"Hello {{name}}","payload":"fixture"}',
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.status_code = 200
    req.response_body = ""
    req.post_data = post_data
    req.headers = headers if headers is not None else {"Content-Type": "application/json"}
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_unsafe_payload_detects_ssti_and_parser_error(vuln_app) -> None:
    req = _make_req(vuln_app.base_url + "/api/render")

    findings = _run(vuln_app, [req])

    proof_qualities = {f.evidence["proof_quality"] for f in findings}
    assert proof_qualities == {
        "ssti_marker_evaluated",
        "unsafe_parser_error_signature",
    }
    ssti = next(f for f in findings if f.evidence["proof_quality"] == "ssti_marker_evaluated")
    assert ssti.severity == Severity.HIGH
    assert ssti.evidence["evaluation_evidence"]["expected_value"] == "49"
    parser = next(f for f in findings if f.evidence["proof_quality"] == "unsafe_parser_error_signature")
    assert parser.evidence["parser_error_evidence"]["signature"] == "pickle.UnpicklingError"


def test_no_finding_when_template_reflects_literal_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/render", post_data='{"template":"Hello {{name}}"}')
    net = _make_network([req])

    def fake_send(url, headers, body, timeout=5):
        return 200, {"content-type": "application/json"}, '{"rendered":"Hello {{7*7}}"}'

    monkeypatch.setattr("vibe_iterator.scanners.unsafe_payload_check._send_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_no_finding_for_generic_400_or_safe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/render")
    net = _make_network([req])

    def fake_send(url, headers, body, timeout=5):
        return 400, {"content-type": "application/json"}, '{"error":"invalid request"}'

    monkeypatch.setattr("vibe_iterator.scanners.unsafe_payload_check._send_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_unsafe_payload_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req("http://localhost:3000/api/render")
    net = _make_network([req])
    calls: list[tuple[str, dict, bytes | None]] = []

    def fake_send(url, headers, body, timeout=5):
        calls.append((url, headers, body))
        if body and b"{{7*7}}" in body:
            return 200, {}, '{"rendered":"49"}'
        return 500, {}, '{"error":"pickle.UnpicklingError: invalid load key"}'

    monkeypatch.setattr("vibe_iterator.scanners.unsafe_payload_check._send_probe", fake_send)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 2
    assert calls
    assert calls[0][0] == "http://localhost:4001/api/render"
    assert calls[0][1] == {"Content-Type": "application/json", "Origin": "http://localhost:3000"}


def test_discovery_filters_static_non_post_third_party_duplicates_and_unknown_paths() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_req(target + "/api/render"),
        _make_req(target + "/api/render", post_data='{"template":"x"}'),
        _make_req(target + "/api/render", method="GET"),
        _make_req(target + "/app.js"),
        _make_req(target + "/api/profile"),
        _make_req("https://third-party.example/api/render"),
    ]
    net = _make_network(requests)

    assert _discover_unsafe_payload_targets(net, target) == [requests[0]]


def test_payload_helpers_and_classifiers() -> None:
    body = _inject_json_field('{"template":"Hello","payload":"fixture"}', "template", "{{7*7}}")
    assert body == b'{"template": "{{7*7}}", "payload": "fixture"}'
    assert _inject_json_field("not json", "template", "{{7*7}}") is None
    assert _body_bytes(None) is None
    assert _body_bytes(b"raw") == b"raw"
    assert _body_bytes("raw") == b"raw"
    assert _has_ssti_evaluation('{"rendered":"Hello 49"}') == ("49", "arithmetic_marker_evaluated")
    assert _has_ssti_evaluation('{"rendered":"Hello {{7*7}}"}') is None
    assert _has_parser_error_signature("pickle.UnpicklingError: invalid load key") == "pickle.UnpicklingError"
    assert _has_parser_error_signature("safe validation error") is None


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "unsafe_payload_check"
    assert s.category == "Injection"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
