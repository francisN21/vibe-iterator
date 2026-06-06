"""Smoke tests for the generic vulnerable fixture app."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
import socket

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


def test_vulnerable_app_models_path_traversal_file_read() -> None:
    with VulnerableApp() as app:
        url = app.base_url + "/api/file?path=../../.env"
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert "DATABASE_URL=" in body
    assert "SECRET_KEY=" in body


def test_vulnerable_app_models_ssrf_fetch_proxy() -> None:
    with VulnerableApp() as app:
        internal_url = urllib.parse.quote(app.base_url + "/api/user", safe="")
        url = app.base_url + f"/api/fetch?url={internal_url}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert "fetched_body" in body
    assert "victim@example.com" in body


def test_vulnerable_app_models_csrf_state_change() -> None:
    with VulnerableApp() as app:
        req = urllib.request.Request(
            app.base_url + "/api/csrf-profile",
            data=b'{"display_name":"Mallory"}',
            headers={
                "Content-Type": "application/json",
                "Cookie": "session=fixture-session",
                "Origin": "https://evil.example",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert '"updated": true' in body
    assert "Mallory" in body


def test_vulnerable_app_models_graphql_exposures() -> None:
    with VulnerableApp() as app:
        introspection = urllib.request.Request(
            app.base_url + "/graphql",
            data=b'{"query":"query { __schema { queryType { name } types { name } } }"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(introspection, timeout=5) as resp:
            introspection_body = resp.read().decode("utf-8")

        unauth_data = urllib.request.Request(
            app.base_url + "/graphql",
            data=b'{"query":"query { viewer { id email role } }"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(unauth_data, timeout=5) as resp:
            unauth_body = resp.read().decode("utf-8")

        deep = urllib.request.Request(
            app.base_url + "/graphql",
            data=b'{"query":"query { node { node { node { node { node { id } } } } } }"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(deep, timeout=5) as resp:
            deep_body = resp.read().decode("utf-8")

    assert "__schema" in introspection_body
    assert "victim@example.com" in unauth_body
    assert '"depth": 5' in deep_body


def test_vulnerable_app_models_unsigned_webhook_acceptance() -> None:
    with VulnerableApp() as app:
        req = urllib.request.Request(
            app.base_url + "/api/webhooks/stripe",
            data=b'{"type":"invoice.paid","id":"evt_fixture"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert '"received": true' in body
    assert "invoice.paid" in body


def test_vulnerable_app_models_websocket_unauthenticated_origin_acceptance() -> None:
    with VulnerableApp() as app:
        parsed = urllib.parse.urlparse(app.base_url)
        request = (
            "GET /socket HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Origin: https://evil.example\r\n"
            "\r\n"
        ).encode("ascii")
        with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
            sock.sendall(request)
            response = sock.recv(1024).decode("iso-8859-1")

    assert "101 Switching Protocols" in response
    assert "Sec-WebSocket-Accept" in response
