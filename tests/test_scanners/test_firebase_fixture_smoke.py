"""Smoke test: fixture starts, routes respond, fixture stops cleanly."""
from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp


def test_fixture_starts_and_serves_rtdb_root() -> None:
    with FirebaseVulnerableApp() as app:
        url = app.base_url + "/.json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200

def test_fixture_secured_path_returns_401() -> None:
    with FirebaseVulnerableApp() as app:
        url = app.base_url + "/secured/.json"
        try:
            urllib.request.urlopen(url, timeout=5)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 401


def test_firebase_fixture_denies_secured_firestore_and_rtdb() -> None:
    import urllib.error
    import urllib.request

    with FirebaseVulnerableApp() as app:
        with pytest.raises(urllib.error.HTTPError) as rtdb_err:
            urllib.request.urlopen(f"{app.base_url}/secured.json", timeout=3)
        assert rtdb_err.value.code == 401

        firestore_url = (
            f"{app.base_url}/v1/projects/proj/databases/(default)/documents/secured/doc1"
        )
        with pytest.raises(urllib.error.HTTPError) as fs_err:
            urllib.request.urlopen(firestore_url, timeout=3)
        assert fs_err.value.code == 403


def test_firebase_fixture_secured_firestore_denial_body_is_firebase_shaped() -> None:
    import json
    import urllib.error
    import urllib.request

    with FirebaseVulnerableApp() as app:
        url = f"{app.base_url}/v1/projects/proj/databases/(default)/documents/secured/doc1"
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(url, timeout=3)
        body = json.loads(err.value.read().decode())
        assert err.value.code == 403
        assert body == {
            "error": {
                "code": 403,
                "message": "Permission denied",
                "status": "PERMISSION_DENIED",
            }
        }


def test_firebase_fixture_denies_secured_rtdb_delete() -> None:
    import urllib.error
    import urllib.request

    with FirebaseVulnerableApp() as app:
        req = urllib.request.Request(f"{app.base_url}/secured.json", method="DELETE")
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(req, timeout=3)
        assert err.value.code == 401


def test_firebase_fixture_denies_secured_storage_upload_and_delete() -> None:
    import urllib.error
    import urllib.request

    with FirebaseVulnerableApp() as app:
        upload = urllib.request.Request(
            f"{app.base_url}/v0/b/proj.appspot.com/o?name=secured/file.txt",
            data=b"probe",
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as upload_err:
            urllib.request.urlopen(upload, timeout=3)
        assert upload_err.value.code == 403

        delete = urllib.request.Request(
            f"{app.base_url}/v0/b/proj.appspot.com/o/secured%2Ffile.txt",
            method="DELETE",
        )
        with pytest.raises(urllib.error.HTTPError) as delete_err:
            urllib.request.urlopen(delete, timeout=3)
        assert delete_err.value.code == 403


def test_firebase_fixture_accepts_probe_prefixed_storage_upload() -> None:
    import urllib.request

    with FirebaseVulnerableApp() as app:
        req = urllib.request.Request(
            f"{app.base_url}/v0/b/proj.appspot.com/o?name=vibe_iterator_probe_file.txt",
            data=b"probe",
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode()
        assert resp.status == 200
        assert "vibe_iterator_probe_file.txt" in body
