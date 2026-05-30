"""firebase_rtdb scanner proof tests."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.firebase_rtdb import Scanner


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
        "databaseURL": base_url,
        "apiKey": "fakekey",
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
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
    return scanner.run(session=None, listeners={"network": net}, config=config)

def test_firebase_rtdb_importable() -> None:
    s = Scanner()
    assert s.name == "firebase_rtdb"
    assert s.requires_stack == ["firebase"]

def test_group1_unauth_read_critical(vuln_app) -> None:
    findings = _run(vuln_app)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()
              and "read" in f.title.lower()]
    assert len(unauth) >= 1
    assert any(f.severity == Severity.CRITICAL for f in unauth)

def test_group2_unauth_write_critical(vuln_app) -> None:
    findings = _run(vuln_app)
    write = [f for f in findings if "write" in f.title.lower()]
    assert len(write) >= 1
    assert any(f.severity == Severity.CRITICAL for f in write)

def test_group3_shallow_enumeration_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    enum = [f for f in findings if "enumerat" in f.title.lower()
            or "structure" in f.title.lower()]
    assert len(enum) >= 1
    assert any(f.severity == Severity.MEDIUM for f in enum)

def test_group1_secured_path_no_finding(vuln_app) -> None:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    # Override databaseURL to force only the secured path
    config._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": vuln_app.base_url + "/secured",
        "apiKey": "fakekey",
    }
    net = _make_network()
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []
