"""HTTP method tampering scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.http_method_tampering import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
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
    req.response_body = '{"resource":"data"}'
    req.post_data = None
    req.headers = {}
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_delete_accepted_on_get_endpoint(vuln_app) -> None:
    req = _make_get_req(url=vuln_app.base_url + "/api/resource")
    findings = _run(vuln_app, [req])
    method = [f for f in findings if "delete" in f.title.lower() or "method" in f.title.lower()]
    assert len(method) >= 1
    assert method[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_method_override_accepted(vuln_app) -> None:
    req = _make_get_req(url=vuln_app.base_url + "/api/resource")
    findings = _run(vuln_app, [req])
    override = [f for f in findings if "override" in f.title.lower() or "x-http-method" in f.title.lower()]
    assert len(override) >= 1


def test_no_finding_when_no_requests() -> None:
    scanner = Scanner()
    config = _make_config()
    net = _make_network([])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []


def test_no_finding_for_static_assets(vuln_app) -> None:
    req = _make_get_req(url=vuln_app.base_url + "/app.js")
    findings = _run(vuln_app, [req])
    method = [f for f in findings if "method" in f.title.lower()]
    assert method == []


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "http_method_tampering"
    assert s.category == "Misconfiguration"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
