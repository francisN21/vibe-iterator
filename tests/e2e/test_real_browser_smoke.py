"""Opt-in Selenium/CDP smoke test against a real local HTTP app.

Run with:
    $env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; python -m pytest tests/e2e
"""

from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vibe_iterator.crawler import browser
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
