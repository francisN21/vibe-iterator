"""Open redirect scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory, ApiParameter
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.open_redirect_check import (
    Scanner,
    _discover_redirect_targets,
    _external_redirect_proof_quality,
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


def test_open_redirect_detected_with_external_location(vuln_app) -> None:
    req = _make_get_req(vuln_app.base_url + "/api/redirect?next=/dashboard")

    findings = _run(vuln_app, [req])

    redirects = [f for f in findings if "open redirect" in f.title.lower()]
    assert len(redirects) == 1
    assert redirects[0].severity == Severity.HIGH
    assert redirects[0].evidence["proof_quality"] == "external_absolute_location_header"
    assert redirects[0].evidence["response"]["location"] == "https://evil.example/vibe-redirect-proof"


def test_no_finding_for_same_origin_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/api/redirect?next=/dashboard")
    net = _make_network([req])

    def fake_fetch(url, origin=None, timeout=5):
        return 302, {"location": "http://localhost:9999/dashboard"}

    monkeypatch.setattr("vibe_iterator.scanners.open_redirect_check._fetch_no_redirect", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_no_finding_for_non_redirect_response(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/api/redirect?next=/dashboard")
    net = _make_network([req])

    def fake_fetch(url, origin=None, timeout=5):
        return 200, {}

    monkeypatch.setattr("vibe_iterator.scanners.open_redirect_check._fetch_no_redirect", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_backend_url_routes_redirect_probe_with_frontend_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_get_req("http://localhost:3000/api/redirect?next=/dashboard")
    net = _make_network([req])
    calls: list[tuple[str, str | None]] = []

    def fake_fetch(url, origin=None, timeout=5):
        calls.append((url, origin))
        return 302, {"location": "https://evil.example/vibe-redirect-proof"}

    monkeypatch.setattr("vibe_iterator.scanners.open_redirect_check._fetch_no_redirect", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 1
    assert calls
    assert calls[0][0] == "http://localhost:4001/api/redirect?next=https%3A%2F%2Fevil.example%2Fvibe-redirect-proof"
    assert calls[0][1] == "http://localhost:3000"


def test_open_redirect_uses_inventory_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
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
                url="https://example.com/api/redirect",
                origin="https://example.com",
                path="/api/redirect",
                normalized_path="/api/redirect",
                parameters=[ApiParameter("next", "query", [], "inferred", "needs_review", False)],
                sources=["network"],
                risk_tags=["redirect"],
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 1},
        warnings=[],
    )

    monkeypatch.setattr(
        "vibe_iterator.scanners.open_redirect_check._fetch_no_redirect",
        lambda *args, **kwargs: (302, {"location": "https://evil.example/vibe-redirect-proof"}),
    )

    findings = scanner.run(
        session=None,
        listeners={"network": _make_network([]), "api_inventory": inv},
        config=config,
    )

    assert any(f.evidence.get("inventory_parameters_used") == ["next"] for f in findings)
    assert findings[0].evidence["inventory_endpoint"] == "GET /api/redirect"
    assert findings[0].evidence["inventory_source"] == "network"


def test_no_finding_for_static_asset() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/app.js?next=/dashboard")
    net = _make_network([req])

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_discovery_filters_non_get_static_unknown_and_duplicate_params() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_get_req(target + "/api/redirect?next=/dashboard"),
        _make_get_req(target + "/api/redirect?next=/settings"),
        _make_get_req(target + "/app.js?next=/dashboard"),
        _make_get_req(target + "/api/redirect?foo=/dashboard"),
        _make_get_req("https://third-party.example/api/redirect?next=/dashboard"),
    ]
    requests[2].url = target + "/app.js"
    requests[3].method = "POST"
    net = _make_network(requests)

    assert _discover_redirect_targets(net, target) == [
        (target + "/api/redirect?next=/dashboard", "next")
    ]


def test_fetch_no_redirect_returns_headers_for_plain_200_with_origin(vuln_app) -> None:
    status, headers = _fetch_no_redirect(vuln_app.base_url + "/api/data", origin="http://localhost:3000")

    assert status == 200
    assert headers["content-type"] == "application/json"


def test_external_redirect_proof_quality_classifies_non_fixture_external_location() -> None:
    proof = _external_redirect_proof_quality(
        "https://attacker.example/login",
        "http://app.example",
        None,
        302,
    )

    assert proof == "external_absolute_redirect_to_untrusted_origin"


def test_external_redirect_proof_quality_rejects_relative_and_non_redirect_locations() -> None:
    assert _external_redirect_proof_quality("/dashboard", "http://app.example", None, 302) is None
    assert _external_redirect_proof_quality("https://evil.example/x", "http://app.example", None, 200) is None


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "open_redirect_check"
    assert s.category == "Misconfiguration"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
