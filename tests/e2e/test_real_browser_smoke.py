"""Opt-in Selenium/CDP smoke test against a real local HTTP app.

Run with:
    $env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; python -m pytest tests/e2e
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.config import Config, StackConfig
from vibe_iterator.crawler import browser
from vibe_iterator.engine.runner import ScanRunner
from vibe_iterator.listeners.network import NetworkListener


class _SmokeApp(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/dashboard"):
            self._send_html("<!doctype html><title>Dashboard</title><h1>private dashboard</h1>")
            return
        if self.path.startswith("/api/user"):
            self._send_json(b'{"id":"user-1","email":"test@example.com"}')
            return
        self._send_html(
            """<!doctype html>
            <title>Login</title>
            <form action="/dashboard" method="get">
              <input type="email" name="email">
              <input type="password" name="password">
              <button type="submit">Sign in</button>
            </form>
            <script>fetch('/api/user')</script>
            """
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_html(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def smoke_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SmokeApp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _run_scan(
    base_url: str,
    scanners: list[str],
    stack: StackConfig,
    pages: list[str],
    scan_id: str,
    firebase_cfg: dict | None = None,
):
    events = []
    config = Config(
        target=base_url,
        test_email="tester@example.com",
        test_password="password123",
        test_email_2=None,
        test_password_2=None,
        supabase_url=None,
        supabase_anon_key=None,
        pages=pages,
        stages={scan_id: scanners},
        stack=stack,
        port=3001,
        scanner_timeout_seconds=30,
    )
    if firebase_cfg is not None:
        config._firebase_cfg = firebase_cfg
    runner = ScanRunner(
        config=config,
        on_event=events.append,
        scanner_overrides=None,
        browser_headless=True,
        scan_id=scan_id,
    )
    return asyncio.run(runner.run(scan_id)), events


@pytest.mark.skipif(
    os.getenv("VIBE_ITERATOR_RUN_E2E_SMOKE") != "1",
    reason="Set VIBE_ITERATOR_RUN_E2E_SMOKE=1 to run the real Selenium/CDP smoke test.",
)
def test_real_chrome_cdp_captures_local_app(smoke_server: str) -> None:
    session = browser.launch(headless=True)
    network = NetworkListener()
    try:
        network.attach(session)
        session.navigate(smoke_server)
        time.sleep(1.0)

        urls = [request.url for request in network.get_requests()]
        assert any(url == smoke_server + "/" or url == smoke_server for url in urls)
        assert any(url.endswith("/api/user") for url in urls)
    finally:
        network.detach()
        session.quit()


@pytest.mark.skipif(
    os.getenv("VIBE_ITERATOR_RUN_E2E_SMOKE") != "1",
    reason="Set VIBE_ITERATOR_RUN_E2E_SMOKE=1 to run the real Selenium/CDP vulnerable-app scan.",
)
def test_real_scan_runner_finds_vulnerable_fixture_issues() -> None:
    with VulnerableApp() as app:
        result, events = _run_scan(
            app.base_url,
            ["xss_check", "cors_check", "api_exposure", "info_disclosure"],
            StackConfig(backend="custom", auth="custom", storage="custom"),
            ["/", "/dashboard", "/api/data", "/api/user", "/api/protected", "/api/login"],
            "phase6-e2e-proof",
        )

    titles = [finding.title.lower() for finding in result.findings]

    assert result.status == "completed"
    assert result.requests_captured["total"] > 0
    assert {r.scanner_name for r in result.scanner_results} == {
        "xss_check",
        "cors_check",
        "api_exposure",
        "info_disclosure",
    }
    assert any("unauthenticated access" in title for title in titles)
    assert any("cors" in title and "reflected" in title for title in titles)
    assert any("sensitive path exposed" in title for title in titles)
    assert any(event.type == "scan_completed" for event in events)


@pytest.mark.skipif(
    os.getenv("VIBE_ITERATOR_RUN_E2E_SMOKE") != "1",
    reason="Set VIBE_ITERATOR_RUN_E2E_SMOKE=1 to run the real Selenium/CDP generic matrix.",
)
def test_real_scan_runner_finds_generic_fixture_matrix() -> None:
    scanners = [
        "auth_check",
        "api_exposure",
        "cors_check",
        "info_disclosure",
        "sql_injection",
        "xss_check",
        "mass_assignment",
        "idor_check",
        "http_method_tampering",
        "rate_limit_check",
    ]
    pages = [
        "/",
        "/login",
        "/dashboard",
        "/api/data",
        "/api/user",
        "/api/protected",
        "/api/admin",
        "/api/search?q=test",
        "/api/profile",
        "/api/items/1",
        "/api/resource",
    ]
    with VulnerableApp() as app:
        result, events = _run_scan(
            app.base_url,
            scanners,
            StackConfig(backend="custom", auth="custom", storage="custom"),
            pages,
            "phase7b-generic-e2e",
        )

    titles = [finding.title.lower() for finding in result.findings]
    scanner_results = {scanner_result.scanner_name for scanner_result in result.scanner_results}
    scanner_names = {finding.scanner for finding in result.findings}

    assert result.status == "completed"
    assert result.requests_captured["total"] > 0
    assert any(event.type == "scan_completed" for event in events)
    assert scanner_results == set(scanners)
    assert "auth_check" in scanner_names
    assert "cors_check" in scanner_names
    assert "info_disclosure" in scanner_names
    assert any("sql" in title for title in titles)
    assert any("mass assignment" in title for title in titles)
    assert any("idor" in title or "object reference" in title for title in titles)


@pytest.mark.skipif(
    os.getenv("VIBE_ITERATOR_RUN_E2E_SMOKE") != "1",
    reason="Set VIBE_ITERATOR_RUN_E2E_SMOKE=1 to run the real Selenium/CDP Firebase matrix.",
)
def test_real_scan_runner_finds_firebase_fixture_matrix() -> None:
    scanners = [
        "firebase_auth",
        "firebase_firestore",
        "firebase_rtdb",
        "firebase_storage",
        "firebase_functions",
    ]
    pages = ["/", "/users.json", "/v0/b/proj.appspot.com/o", "/helloFunction"]
    with FirebaseVulnerableApp() as app:
        result, events = _run_scan(
            app.base_url,
            scanners,
            StackConfig(backend="firebase", auth="firebase-auth", storage="firebase"),
            pages,
            "phase7b-firebase-e2e",
            firebase_cfg={
                "projectId": "testproj",
                "apiKey": "fakekey",
                "databaseURL": app.base_url,
                "storageBucket": app.base_url.removeprefix("http://"),
                "authDomain": "testproj.firebaseapp.com",
                "_toolkit_base": app.base_url + "/v1",
            },
        )

    assert result.status == "completed"
    assert any(event.type == "scan_completed" for event in events)
    assert result.requests_captured["total"] > 0
    assert {r.scanner_name for r in result.scanner_results} == set(scanners)
