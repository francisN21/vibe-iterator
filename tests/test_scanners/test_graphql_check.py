"""GraphQL scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.graphql_check import (
    Scanner,
    _build_depth_query,
    _discover_graphql_endpoints,
    _has_depth_accepted,
    _has_introspection_schema,
    _has_sensitive_graphql_data,
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
    post_data: str = '{"query":"query { viewer { id email role } }"}',
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.status_code = 200
    req.response_body = ""
    req.post_data = post_data
    req.headers = headers or {"Content-Type": "application/json", "Authorization": "Bearer test-token"}
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_graphql_detects_introspection_auth_bypass_and_depth(vuln_app) -> None:
    req = _make_req(vuln_app.base_url + "/graphql")

    findings = _run(vuln_app, [req])

    proof_qualities = {f.evidence["proof_quality"] for f in findings}
    assert proof_qualities == {
        "unauthenticated_graphql_introspection",
        "unauthenticated_graphql_sensitive_data",
        "graphql_depth_query_accepted",
    }
    assert all(f.severity in {Severity.MEDIUM, Severity.HIGH} for f in findings)
    auth_bypass = next(f for f in findings if f.evidence["proof_quality"] == "unauthenticated_graphql_sensitive_data")
    assert auth_bypass.evidence["sensitive_data_evidence"]["json_path"] == "data.viewer.email"
    assert auth_bypass.evidence["request"]["headers"] == {"Content-Type": "application/json"}


def test_no_finding_when_graphql_returns_only_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/graphql")
    net = _make_network([req])

    def fake_post(url, query, headers=None, timeout=5):
        return 200, {"content-type": "application/json"}, '{"errors":[{"message":"disabled"}]}'

    monkeypatch.setattr("vibe_iterator.scanners.graphql_check._post_graphql", fake_post)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_graphql_probe_without_auth_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req("http://localhost:3000/graphql", headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer test-token",
        "Cookie": "session=fixture-session",
    })
    net = _make_network([req])
    calls: list[tuple[str, str, dict | None]] = []

    def fake_post(url, query, headers=None, timeout=5):
        calls.append((url, query, headers))
        return 200, {"content-type": "application/json"}, '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query"}]}}}'

    monkeypatch.setattr("vibe_iterator.scanners.graphql_check._post_graphql", fake_post)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) >= 1
    assert calls
    assert calls[0][0] == "http://localhost:4001/graphql"
    assert calls[0][2] == {"Content-Type": "application/json"}


def test_graphql_uses_inventory_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("https://example.com")
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="POST",
                url="https://example.com/graphql",
                origin="https://example.com",
                path="/graphql",
                normalized_path="/graphql",
                sources=["route_wordlist"],
                risk_tags=["graphql"],
                confidence="confirmed",
            )
        ],
        summary={"endpoints": 1},
        warnings=[],
    )

    def fake_post(url, query, headers=None, timeout=5):
        return 200, {"content-type": "application/json"}, (
            '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query"}]}}}'
        )

    monkeypatch.setattr("vibe_iterator.scanners.graphql_check._post_graphql", fake_post)

    findings = scanner.run(
        session=None,
        listeners={"network": _make_network([]), "api_inventory": inv},
        config=config,
    )

    assert any(f.evidence.get("inventory_endpoint") == "POST /graphql" for f in findings)
    assert findings[0].evidence["inventory_source"] == "route_wordlist"
    assert findings[0].evidence["inventory_parameters_used"] == []


def test_discovery_filters_static_non_graphql_third_party_and_duplicates() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_req(target + "/graphql"),
        _make_req(target + "/graphql", post_data='{"query":"query { me { id } }"}'),
        _make_req(target + "/api/search", post_data='{"query":"graphql text but not endpoint"}'),
        _make_req(target + "/app.js", method="GET"),
        _make_req("https://third-party.example/graphql"),
    ]
    net = _make_network(requests)

    assert _discover_graphql_endpoints(net, target) == [requests[0]]


def test_graphql_classifiers() -> None:
    assert _has_introspection_schema('{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}') == (
        "__schema",
        "Query",
        1,
    )
    assert _has_sensitive_graphql_data('{"data":{"viewer":{"email":"victim@example.com","role":"admin"}}}') == (
        "data.viewer.email",
        "victim@example.com",
    )
    assert _has_sensitive_graphql_data('{"data":{"viewer":{"id":"public-user"}}}') is None
    assert _has_depth_accepted('{"data":{"node":{"node":{"node":{"node":{"node":{"id":"leaf"}}}}}}}') == 5
    assert _has_depth_accepted('{"errors":[{"message":"depth limit exceeded"}]}') is None


def test_build_depth_query_is_bounded_and_deterministic() -> None:
    query = _build_depth_query(depth=5)

    assert query == "query VibeIteratorDepthProbe { node { node { node { node { node { id } } } } } }"
    assert query.count("node") == 5


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "graphql_check"
    assert s.category == "API Security"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
