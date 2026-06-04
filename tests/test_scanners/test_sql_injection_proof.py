"""sql_injection scanner proof tests — real HTTP against the vulnerable fixture app, no Selenium."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.sql_injection import Scanner


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_url = ""
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(url: str, status: int = 200, body: str = "", post_data=None) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = status
    req.response_body = body
    req.post_data = post_data
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Group 1 — Passive analysis detects SQL error already in captured response
# ---------------------------------------------------------------------------

def test_passive_sql_error_in_response_detected(vuln_app) -> None:
    # Pre-bake the captured response with a SQL error body (as if the app already
    # leaked it during crawl). Group 1 passive scan should flag it.
    sql_error = '{"error": "syntax error at or near: SELECT * FROM items WHERE name = test"}'
    req = _make_req(
        url=vuln_app.base_url + "/api/search?q=%27",
        status=500,
        body=sql_error,
    )
    findings = _run(vuln_app, [req])
    sql_findings = [f for f in findings if "sql" in f.title.lower() or "error" in f.title.lower()]
    assert len(sql_findings) >= 1
    assert any(f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL) for f in sql_findings)


# ---------------------------------------------------------------------------
# Group 3 — Active injection: scanner replays /api/search with SQLi payloads
# ---------------------------------------------------------------------------

def test_active_sqli_url_param_detected(vuln_app) -> None:
    # Mock a clean captured request to /api/search?q=test.
    # Scanner injects `' OR 1=1--` into the `q` param and replays against the
    # real running fixture — fixture returns 500 with SQL error → CRITICAL.
    req = _make_req(
        url=vuln_app.base_url + "/api/search?q=test",
        status=200,
        body='{"results": []}',
    )
    findings = _run(vuln_app, [req])
    sqli = [f for f in findings if "sql injection" in f.title.lower()]
    assert len(sqli) >= 1
    assert any(f.severity == Severity.CRITICAL for f in sqli)


# ---------------------------------------------------------------------------
# Negative — endpoint with no query params produces no injection finding
# ---------------------------------------------------------------------------

def test_no_sqli_finding_for_paramless_endpoint(vuln_app) -> None:
    req = _make_req(
        url=vuln_app.base_url + "/api/data",
        status=200,
        body='{"items": [{"id": 1, "value": "secret"}]}',
    )
    findings = _run(vuln_app, [req])
    sqli = [f for f in findings if "sql injection" in f.title.lower()]
    assert sqli == []


def test_expired_deadline_prevents_active_group_http_requests(monkeypatch: pytest.MonkeyPatch, vuln_app) -> None:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    deadline = 0.0
    rest_req = _make_req(
        url=vuln_app.base_url + "/rest/v1/items?name=eq.test",
        status=200,
        body="[]",
    )
    query_req = _make_req(
        url=vuln_app.base_url + "/api/search?q=test",
        status=200,
        body='{"results": []}',
    )
    network = _make_network([rest_req, query_req])
    findings: list = []

    def fail_request(*args, **kwargs):
        raise AssertionError("expired SQLi deadline should prevent active HTTP probes")

    monkeypatch.setattr("vibe_iterator.scanners.sql_injection._make_request", fail_request)

    scanner._group2_postgrest_injection(network, config, findings, "custom", deadline)
    scanner._group3_classic_injection(network, config, findings, "custom", deadline)
    scanner._group4_blind_injection(network, config, findings, "custom", deadline)

    assert findings == []


def test_active_sqli_rewrites_frontend_api_request_to_backend_url(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000")
    config.backend_url = "http://localhost:4001"
    req = _make_req(
        url="http://localhost:3000/api/search?q=test",
        status=200,
        body='{"results": []}',
    )
    network = _make_network([req])
    requested_urls: list[str] = []

    def fake_request(url, method, data, headers, timeout=4):
        requested_urls.append(url)
        return "", 401, 0.01

    monkeypatch.setattr("vibe_iterator.scanners.sql_injection._make_request", fake_request)

    findings: list = []
    scanner._group3_classic_injection(
        network,
        config,
        findings,
        "custom",
        deadline=999999999.0,
    )

    assert requested_urls
    assert all(url.startswith("http://localhost:4001/api/search?") for url in requested_urls)
