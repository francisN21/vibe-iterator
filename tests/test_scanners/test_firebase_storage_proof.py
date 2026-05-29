"""firebase_storage scanner proof tests."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.firebase_storage import Scanner
from vibe_iterator.scanners.base import Severity

@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app

def _make_config(base_url: str, second_account: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = second_account
    # The fixture serves Storage routes on the same base_url.
    # We use the host:port part as the bucket so REST calls hit the fixture.
    host_port = base_url.replace("http://", "")
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": base_url,
        "apiKey": "fakekey",
        "storageBucket": host_port,
        "authDomain": "testproj.firebaseapp.com",
    }
    return cfg

def _make_network() -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = []
    return net

def _run(vuln_app, second_account: bool = False) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url, second_account)
    net = _make_network()
    return scanner.run(session=None, listeners={"network": net}, config=config)

def test_firebase_storage_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_storage"
    assert s.requires_stack == ["firebase"]

def test_group1_unauth_download_high(vuln_app) -> None:
    findings = _run(vuln_app)
    dl = [f for f in findings if "download" in f.title.lower()
          or "read" in f.title.lower()]
    assert len(dl) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in dl)

def test_group2_unauth_upload_high(vuln_app) -> None:
    findings = _run(vuln_app)
    ul = [f for f in findings if "upload" in f.title.lower()
          or "write" in f.title.lower()]
    assert len(ul) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in ul)

def test_group4_bucket_listing_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    lst = [f for f in findings if "list" in f.title.lower()
           or "enumerat" in f.title.lower()]
    assert len(lst) >= 1
    assert any(f.severity == Severity.MEDIUM for f in lst)

def test_negative_unreachable_host() -> None:
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    # Point at a non-listening host -> all REST calls fail -> no findings
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "storageBucket": "127.0.0.1:1",
        "databaseURL": "http://localhost:1",
    }
    net = MagicMock()
    net.get_requests.return_value = []
    findings = scanner.run(session=None, listeners={"network": net}, config=cfg)
    dl = [f for f in findings if "download" in f.title.lower()]
    assert dl == []
