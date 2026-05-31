"""firebase_auth scanner proof tests."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.firebase_auth import Scanner


@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app


def _make_config(base_url: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "apiKey": "fakekey",
        "databaseURL": base_url,
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
        # Redirect Identity Toolkit calls to the local fixture (/v1 prefix)
        "_toolkit_base": base_url + "/v1",
    }
    return cfg


def _make_network() -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = []
    return net


def _run(vuln_app) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network()
    storage = MagicMock()
    storage.get_snapshot.return_value = {}
    return scanner.run(session=None, listeners={"network": net, "storage": storage}, config=config)


def test_scanner_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_auth"
    assert s.requires_stack == ["firebase"]


def test_group1_anonymous_auth_high(vuln_app) -> None:
    findings = _run(vuln_app)
    anon = [f for f in findings if "anonymous" in f.title.lower()]
    assert len(anon) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in anon)


def test_group2_email_enumeration_low(vuln_app) -> None:
    # The fixture returns registered=True for @example.com and False for other domains
    findings = _run(vuln_app)
    enum = [f for f in findings if "enumerat" in f.title.lower()
            or "email" in f.title.lower()]
    assert len(enum) >= 1
    assert any(f.severity in (Severity.LOW, Severity.MEDIUM) for f in enum)


def test_negative_anonymous_disabled() -> None:
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "apiKey": "fakekey",
        # Points to unreachable port -> all requests fail -> no findings
        "_toolkit_base": "http://localhost:1/v1",
    }
    net = MagicMock()
    net.get_requests.return_value = []
    storage = MagicMock()
    storage.get_snapshot.return_value = {}
    findings = scanner.run(session=None, listeners={"network": net, "storage": storage}, config=cfg)
    anon = [f for f in findings if "anonymous" in f.title.lower()]
    assert anon == []


def test_unreachable_local_toolkit_skips_http_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "apiKey": "fakekey",
        "_toolkit_base": "http://localhost:1/v1",
    }
    net = MagicMock()
    net.get_requests.return_value = []
    storage = MagicMock()
    storage.get_snapshot.return_value = {}
    calls = 0

    def fail_if_called(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("urlopen should not be called for a closed local Firebase Auth endpoint")

    monkeypatch.setattr("vibe_iterator.scanners.firebase_auth.urllib.request.urlopen", fail_if_called)

    findings = scanner.run(session=None, listeners={"network": net, "storage": storage}, config=cfg)

    assert findings == []
    assert calls == 0


def test_group4_token_exposure_medium() -> None:
    # Build a fake URL with a JWT-shaped token in the query string
    fake_token = (
        "eyJhbGciOiJSUzI1NiJ9"
        ".eyJzdWIiOiJ1aWQxMjMiLCJpYXQiOjE2MDAwMDAwMDB9"
        ".fakesignature"
    )
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "apiKey": "fakekey",
        "_toolkit_base": "http://localhost:1/v1",  # unreachable → signUp/createAuthUri fail silently
    }
    req = MagicMock()
    req.url = f"http://localhost:1/api/data?id_token={fake_token}"
    net = MagicMock()
    net.get_requests.return_value = [req]
    storage = MagicMock()
    storage.get_snapshot.return_value = {}
    findings = scanner.run(session=None, listeners={"network": net, "storage": storage}, config=cfg)
    token_findings = [f for f in findings if "token" in f.title.lower() and "url" in f.title.lower()]
    assert len(token_findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in token_findings)
