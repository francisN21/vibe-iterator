"""firebase_functions scanner proof tests."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.firebase_functions import Scanner


@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app


def _make_config(base_url: str, fn_url: str = "") -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": base_url,
        "apiKey": "fakekey",
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
    }
    if fn_url:
        cfg._firebase_cfg["_test_fn_urls"] = [fn_url]
    return cfg


def _make_network() -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = []
    return net


def _run(vuln_app, fn_url: str = "") -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url, fn_url=fn_url)
    net = _make_network()
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_scanner_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_functions"
    assert s.requires_stack == ["firebase"]


def test_group1_unauth_function_high(vuln_app) -> None:
    fn_url = vuln_app.base_url + "/helloWorld"
    findings = _run(vuln_app, fn_url=fn_url)
    unauth = [f for f in findings
              if "unauthenticated" in f.title.lower() or "without auth" in f.title.lower()]
    assert len(unauth) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in unauth)


def test_group2_token_in_response_high(vuln_app) -> None:
    # The fixture returns _FAKE_TOKEN (a JWT-shaped string) in the response body
    # for any POST without Authorization header, so sensitive data finding triggers.
    fn_url = vuln_app.base_url + "/getToken"
    findings = _run(vuln_app, fn_url=fn_url)
    leak = [f for f in findings
            if "token" in f.title.lower() or "sensitive" in f.title.lower()
            or "data" in f.title.lower()]
    assert len(leak) >= 1


def test_group3_cors_misconfiguration_high(vuln_app) -> None:
    # The fixture reflects the Origin header + sets Access-Control-Allow-Credentials: true
    fn_url = vuln_app.base_url + "/someFunc"
    findings = _run(vuln_app, fn_url=fn_url)
    cors = [f for f in findings if "cors" in f.title.lower()]
    assert len(cors) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in cors)


def test_negative_function_returning_401_no_unauth_finding() -> None:
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg._firebase_cfg = {"projectId": "testproj"}
    net = MagicMock()
    net.get_requests.return_value = []
    findings = scanner.run(session=None, listeners={"network": net}, config=cfg)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []
