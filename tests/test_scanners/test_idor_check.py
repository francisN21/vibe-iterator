"""IDOR check scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.idor_check import Scanner


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999", backend_url: str | None = None) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.backend_url = backend_url
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(url: str, status: int = 200, body: str = '{"id":1,"data":"mine"}') -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = status
    req.response_body = body
    req.post_data = None
    req.headers = {"Authorization": "Bearer fake-token"}
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Positive — IDOR on numeric ID endpoint
# ---------------------------------------------------------------------------

def test_idor_numeric_id_detected(vuln_app) -> None:
    # Captured request shows /api/items/1 was accessed (user's own resource)
    req = _make_req(url=vuln_app.base_url + "/api/items/1")
    findings = _run(vuln_app, [req])
    idor = [f for f in findings if "idor" in f.title.lower() or "insecure direct" in f.title.lower()]
    assert len(idor) >= 1
    assert idor[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert idor[0].evidence["proof_quality"] == "response_id_matches_probed_id"


# ---------------------------------------------------------------------------
# Negative — no numeric ID in URL → no finding
# ---------------------------------------------------------------------------

def test_no_finding_for_non_id_endpoint(vuln_app) -> None:
    req = _make_req(url=vuln_app.base_url + "/api/data")
    findings = _run(vuln_app, [req])
    idor = [f for f in findings if "idor" in f.title.lower()]
    assert idor == []


def test_no_finding_when_alternate_id_returns_403(vuln_app) -> None:
    # If we try /api/admin (which is 200 but has no numeric id variation), no IDOR
    req = _make_req(url=vuln_app.base_url + "/api/admin")
    findings = _run(vuln_app, [req])
    idor = [f for f in findings if "idor" in f.title.lower()]
    assert idor == []


def test_backend_url_routes_idor_probe_with_frontend_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req(url="http://localhost:3000/api/items/1")
    net = _make_network([req])
    calls: list[tuple[str, dict]] = []

    def fake_fetch(url, headers, timeout=5):
        calls.append((url, headers))
        return "", 403

    monkeypatch.setattr("vibe_iterator.scanners.idor_check._fetch", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []
    assert calls
    assert all(url.startswith("http://localhost:4001/api/items/") for url, _ in calls)
    assert all(headers["Origin"] == "http://localhost:3000" for _, headers in calls)


def test_no_idor_when_probe_returns_spa_html_200(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(url="http://localhost:9999/api/items/1")
    net = _make_network([req])

    def fake_fetch(url, headers, timeout=5):
        return "<!doctype html><div id='root'></div>", 200

    monkeypatch.setattr("vibe_iterator.scanners.idor_check._fetch", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_no_idor_when_probe_returns_generic_json_200(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(url="http://localhost:9999/api/items/1")
    net = _make_network([req])

    def fake_fetch(url, headers, timeout=5):
        return '{"ok": true}', 200

    monkeypatch.setattr("vibe_iterator.scanners.idor_check._fetch", fake_fetch)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []


def test_idor_uses_inventory_numeric_id_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("https://example.com")
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="safe",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/users/123",
                origin="https://example.com",
                path="/api/users/123",
                normalized_path="/api/users/{id}",
                auth_observed=True,
                sources=["network"],
                confidence="confirmed",
            )
        ],
    )

    def fake_fetch(url, headers, timeout=5):
        assert headers == {}
        assert url == "https://example.com/api/users/124"
        return '{"id":124,"email":"other@example.com"}', 200

    monkeypatch.setattr("vibe_iterator.scanners.idor_check._fetch", fake_fetch)

    findings = scanner.run(
        session=None,
        listeners={"network": _make_network([]), "api_inventory": inv},
        config=config,
    )

    assert findings
    assert findings[0].evidence["inventory_endpoint"] == "GET /api/users/{id}"
    assert findings[0].evidence["inventory_source"] == "network"
    assert findings[0].evidence["inventory_confidence"] == "confirmed"


def test_idor_prefers_matching_network_context_over_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("https://example.com")
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="safe",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/users/123",
                origin="https://example.com",
                path="/api/users/123",
                normalized_path="/api/users/{id}",
                auth_observed=True,
                sources=["network"],
                confidence="confirmed",
            )
        ],
    )
    network_req = _make_req(
        url="https://example.com/api/users/123",
        body='{"id":123,"email":"mine@example.com"}',
    )
    calls: list[tuple[str, dict]] = []

    def fake_fetch(url, headers, timeout=5):
        calls.append((url, headers))
        assert headers["Authorization"] == "Bearer fake-token"
        return '{"id":124,"email":"other@example.com"}', 200

    monkeypatch.setattr("vibe_iterator.scanners.idor_check._fetch", fake_fetch)

    findings = scanner.run(
        session=None,
        listeners={"network": _make_network([network_req]), "api_inventory": inv},
        config=config,
    )

    assert findings
    assert calls == [("https://example.com/api/users/124", {"Authorization": "Bearer fake-token"})]
    assert findings[0].evidence["request"]["headers"]["Authorization"] == "Bearer fake-token"
    assert findings[0].evidence["inventory_endpoint"] == "GET /api/users/{id}"
    assert findings[0].evidence["inventory_source"] == "network"
    assert findings[0].evidence["inventory_confidence"] == "confirmed"


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "idor_check"
    assert s.category == "Access Control"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
