"""Path traversal scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory, ApiParameter
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.path_traversal_check import (
    Scanner,
    _detect_sensitive_file,
    _discover_file_params,
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


def _make_get_req(url: str, body: str = "") -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = 200
    req.response_body = body
    req.post_data = None
    req.headers = {}
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_path_traversal_detects_env_file_read(vuln_app) -> None:
    req = _make_get_req(vuln_app.base_url + "/api/file?path=profile.txt")

    findings = _run(vuln_app, [req])

    traversal = [f for f in findings if "path traversal" in f.title.lower()]
    assert len(traversal) == 1
    assert traversal[0].severity == Severity.CRITICAL
    assert traversal[0].evidence["proof_quality"] == "env_file_disclosed_via_traversal"
    assert traversal[0].evidence["sensitive_file_type"] == "env"


def test_no_finding_for_safe_file_response(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/api/file?path=profile.txt")
    net = _make_network([req])

    def fake_fetch(url, origin=None, timeout=5):
        return 200, "public profile"

    monkeypatch.setattr("vibe_iterator.scanners.path_traversal_check._fetch", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_no_finding_for_403_or_404(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_get_req("http://localhost:9999/api/file?path=profile.txt")
    net = _make_network([req])

    def fake_fetch(url, origin=None, timeout=5):
        return 403, "forbidden"

    monkeypatch.setattr("vibe_iterator.scanners.path_traversal_check._fetch", fake_fetch)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_path_probe_with_frontend_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_get_req("http://localhost:3000/api/file?path=profile.txt")
    net = _make_network([req])
    calls: list[tuple[str, str | None]] = []

    def fake_fetch(url, origin=None, timeout=5):
        calls.append((url, origin))
        return 403, "forbidden"

    monkeypatch.setattr("vibe_iterator.scanners.path_traversal_check._fetch", fake_fetch)

    scanner.run(session=None, listeners={"network": net}, config=config)

    assert calls
    assert calls[0][0] == "http://localhost:4001/api/file?path=..%2F..%2F.env"
    assert calls[0][1] == "http://localhost:3000"


def test_path_traversal_uses_inventory_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
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
                url="https://example.com/api/file",
                origin="https://example.com",
                path="/api/file",
                normalized_path="/api/file",
                parameters=[ApiParameter("path", "query", [], "inferred", "needs_review", False)],
                sources=["network"],
                risk_tags=["file"],
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 1},
        warnings=[],
    )

    monkeypatch.setattr(
        "vibe_iterator.scanners.path_traversal_check._fetch",
        lambda *args, **kwargs: (200, "DATABASE_URL=postgres://fixture\nSECRET_KEY=fixture"),
    )

    findings = scanner.run(
        session=None,
        listeners={"network": _make_network([]), "api_inventory": inv},
        config=config,
    )

    assert any(f.evidence.get("inventory_parameters_used") == ["path"] for f in findings)
    assert findings[0].evidence["inventory_endpoint"] == "GET /api/file"
    assert findings[0].evidence["inventory_source"] == "network"


def test_discovery_filters_static_non_get_unknown_and_duplicate_params() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_get_req(target + "/api/file?path=profile.txt"),
        _make_get_req(target + "/api/file?path=avatar.txt"),
        _make_get_req(target + "/app.js?path=profile.txt"),
        _make_get_req(target + "/api/file?name=profile.txt"),
        _make_get_req("https://third-party.example/api/file?path=profile.txt"),
    ]
    requests[3].method = "POST"
    net = _make_network(requests)

    assert _discover_file_params(net, target) == [
        (target + "/api/file?path=profile.txt", "path")
    ]


def test_detect_sensitive_file_classifies_env_and_passwd_signatures() -> None:
    assert _detect_sensitive_file("DATABASE_URL=postgres://x\nSECRET_KEY=y") == ("env", "env_file_disclosed_via_traversal")
    assert _detect_sensitive_file("root:x:0:0:root:/root:/bin/bash") == ("passwd", "passwd_file_disclosed_via_traversal")
    assert _detect_sensitive_file("<!doctype html><div id='root'></div>") is None


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "path_traversal_check"
    assert s.category == "Access Control"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
