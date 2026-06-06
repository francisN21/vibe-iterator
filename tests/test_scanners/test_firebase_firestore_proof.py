"""firebase_firestore scanner proof tests."""
from __future__ import annotations

import urllib.error
import urllib.request
from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.firebase_firestore import Scanner


@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app


def _make_config(base_url: str, second_account: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = second_account
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": base_url,
        "apiKey": "fakekey",
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
        # Redirect Firestore REST calls to the local fixture
        "_firestore_base": base_url,
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


def test_scanner_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_firestore"
    assert s.requires_stack == ["firebase"]
    assert s.requires_second_account is False


def test_group1_unauth_read_high(vuln_app) -> None:
    findings = _run(vuln_app)
    unauth = [f for f in findings
              if "unauthenticated" in f.title.lower() and "read" in f.title.lower()]
    assert len(unauth) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in unauth)


def test_group3_mass_assignment_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    mass = [f for f in findings if "mass" in f.title.lower()
            or "privilege" in f.title.lower()]
    assert len(mass) >= 1
    assert any(f.severity == Severity.MEDIUM for f in mass)


def test_group4_collection_enum_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    enum = [f for f in findings if "enumerat" in f.title.lower()
            or "collection" in f.title.lower()]
    assert len(enum) >= 1
    assert any(f.severity == Severity.MEDIUM for f in enum)


def test_negative_secured_collection_no_finding() -> None:
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    # projectId present but no reachable firestore_base -> all requests fail -> no findings
    cfg._firebase_cfg = {"projectId": "noproject"}
    net = MagicMock()
    net.get_requests.return_value = []
    findings = scanner.run(session=None, listeners={"network": net}, config=cfg)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()
              and "read" in f.title.lower()]
    assert unauth == []


def test_fixture_denies_secured_firestore_patch_and_delete(vuln_app) -> None:
    url = f"{vuln_app.base_url}/v1/projects/proj/databases/(default)/documents/secured/doc1"
    patch_req = urllib.request.Request(url, data=b'{"fields":{}}', method="PATCH")
    delete_req = urllib.request.Request(url, method="DELETE")

    with pytest.raises(urllib.error.HTTPError) as patch_err:
        urllib.request.urlopen(patch_req, timeout=3)
    assert patch_err.value.code == 403

    with pytest.raises(urllib.error.HTTPError) as delete_err:
        urllib.request.urlopen(delete_req, timeout=3)
    assert delete_err.value.code == 403
