"""Smoke test: fixture starts, routes respond, fixture stops cleanly."""
from __future__ import annotations

import urllib.error
import urllib.request

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
