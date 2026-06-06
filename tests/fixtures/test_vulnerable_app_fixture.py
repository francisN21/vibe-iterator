"""Smoke tests for the generic vulnerable fixture app."""

from __future__ import annotations

import urllib.request
import urllib.error

from tests.fixtures.vulnerable_app.app import VulnerableApp


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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


def test_vulnerable_app_models_open_redirect() -> None:
    opener = urllib.request.build_opener(_NoRedirect)

    with VulnerableApp() as app:
        req = urllib.request.Request(app.base_url + "/api/redirect?next=https://evil.example/phish")
        try:
            opener.open(req, timeout=5)
        except urllib.error.HTTPError as exc:
            status = exc.code
            location = exc.headers["Location"]

    assert status == 302
    assert location == "https://evil.example/phish"
