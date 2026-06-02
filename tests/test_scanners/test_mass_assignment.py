"""Mass assignment scanner tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.mass_assignment import Scanner
from vibe_iterator.scanners.base import Severity


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


def _make_post_req(url: str, body: dict, status: int = 200) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "POST"
    req.status_code = status
    req.response_body = json.dumps(body)
    req.post_data = json.dumps({"name": "alice"})
    req.headers = {"Content-Type": "application/json"}
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Positive: injected role field echoed back → finding
# ---------------------------------------------------------------------------

def test_mass_assignment_role_detected(vuln_app) -> None:
    req = _make_post_req(
        url=vuln_app.base_url + "/api/profile",
        body={"id": 42, "name": "alice"},
    )
    findings = _run(vuln_app, [req])
    ma = [f for f in findings if "mass assignment" in f.title.lower()]
    assert len(ma) >= 1
    assert ma[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert "role" in ma[0].title.lower() or "is_admin" in ma[0].title.lower() or "admin" in ma[0].title.lower()


def test_mass_assignment_credits_critical(vuln_app) -> None:
    # credits/balance fields → CRITICAL severity (financial impact)
    req = _make_post_req(
        url=vuln_app.base_url + "/api/profile",
        body={"id": 42, "name": "alice"},
    )
    findings = _run(vuln_app, [req])
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    # fixture echoes credits=99999 back → CRITICAL finding expected
    assert len(critical) >= 1


# ---------------------------------------------------------------------------
# Negative: no POST body → no finding
# ---------------------------------------------------------------------------

def test_no_finding_when_no_post_requests() -> None:
    scanner = Scanner()
    config = _make_config()
    net = _make_network([])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []


def test_no_finding_when_get_only() -> None:
    req = MagicMock()
    req.method = "GET"
    req.url = "http://localhost:9999/api/data"
    req.post_data = None
    scanner = Scanner()
    config = _make_config()
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []


def test_backend_url_routes_mass_assignment_probe_with_frontend_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_post_req("http://localhost:3000/api/profile", {"id": 42, "name": "alice"})
    net = _make_network([req])
    calls: list[tuple[str, str, dict]] = []

    def fake_request(url, method, data, headers, timeout=6):
        calls.append((url, method, headers))
        return "", 403, 0.01

    monkeypatch.setattr("vibe_iterator.scanners.mass_assignment._make_request", fake_request)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert findings == []
    assert calls
    assert all(url == "http://localhost:4001/api/profile" for url, _, _ in calls)
    assert all(method == "POST" for _, method, _ in calls)
    assert all(headers["Origin"] == "http://localhost:3000" for _, _, headers in calls)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "mass_assignment"
    assert s.category == "Access Control"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
