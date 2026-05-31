"""Smoke tests for the generic vulnerable fixture app."""

from __future__ import annotations

import urllib.request

from tests.fixtures.vulnerable_app.app import VulnerableApp


def test_vulnerable_app_serves_login_form_and_dashboard_api_traffic() -> None:
    with VulnerableApp() as app:
        with urllib.request.urlopen(app.base_url + "/login", timeout=5) as resp:
            login_html = resp.read().decode("utf-8")

        with urllib.request.urlopen(app.base_url + "/dashboard", timeout=5) as resp:
            dashboard_html = resp.read().decode("utf-8")

    assert resp.status == 200
    assert "input type=\"email\"" in login_html
    assert "input type=\"password\"" in login_html
    assert "/api/protected" in dashboard_html
    assert "Authorization" in dashboard_html
