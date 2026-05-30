"""Intentionally vulnerable HTTP fixture app for integration/proof tests.

Vulnerabilities baked in (all deliberate, local-only):
  - /api/data       — no auth required, wildcard CORS (ACAO: *)
  - /api/user       — reflects Origin header in ACAO (reflected origin CORS)
  - /api/protected  — authenticated in original request but 200 without auth
  - /api/login      — auth endpoint with no rate-limit headers
  - /api/search     — returns SQL error string when ' injected in ?q=
  - /               — page with innerHTML DOM sink + no security headers
  - All responses   — no X-Content-Type-Options, no X-Frame-Options, no CSP
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/data":
            self._respond_json(
                200,
                {"items": [{"id": 1, "value": "secret"}]},
                extra_headers={"Access-Control-Allow-Origin": "*"},
            )
        elif path == "/api/user":
            origin = self.headers.get("Origin", "")
            acao = origin if origin else "*"
            self._respond_json(
                200,
                {"id": "user-42", "email": "victim@example.com"},
                extra_headers={
                    "Access-Control-Allow-Origin": acao,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        elif path == "/api/protected":
            # Should require auth but doesn't
            self._respond_json(200, {"secret": "admin-token-abc123"})
        elif path == "/api/admin":
            # Sensitive path — also unprotected
            self._respond_json(200, {"users": ["alice", "bob"]})
        elif path == "/api/login":
            # No rate limiting headers
            self._respond_json(200, {"token": "fake-jwt"})
        elif path == "/api/search":
            q = query.get("q", [""])[0]
            if "'" in q or '"' in q or "--" in q:
                self._respond_json(
                    500,
                    {"error": f"syntax error at or near \"{q}\": SELECT * FROM items WHERE name = '{q}'"},
                )
            else:
                self._respond_json(200, {"results": []})
        elif path == "/":
            self._respond_html(200, _INDEX_HTML)
        elif path == "/dashboard":
            self._respond_html(200, _DASHBOARD_HTML)
        else:
            self._respond_json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        origin = self.headers.get("Origin", "")

        if path == "/api/user":
            # Reflects origin in OPTIONS preflight too
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin or "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

    def log_message(self, *args: object) -> None:
        return  # suppress request logs in test output

    def _respond_json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        # Deliberately omit security headers
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _respond_html(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        # No CSP, no X-Frame-Options, no X-Content-Type-Options
        self.end_headers()
        self.wfile.write(data)


_INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>Vulnerable App</title></head>
<body>
  <div id="output"></div>
  <script>
    // DOM XSS sink: reads location.hash and writes to innerHTML
    var hash = location.hash.slice(1);
    document.getElementById('output').innerHTML = decodeURIComponent(hash);

    // Also uses document.write
    if (hash.startsWith('write:')) {
      document.write(hash.slice(6));
    }

    fetch('/api/data').then(r => r.json()).then(d => {
      document.getElementById('output').innerHTML += JSON.stringify(d);
    });
  </script>
</body>
</html>"""

_DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body><h1>Private Dashboard</h1></body>
</html>"""


# --------------------------------------------------------------------------- #
# Context-manager server for use in tests                                      #
# --------------------------------------------------------------------------- #

class VulnerableApp:
    """Start the vulnerable app on a random free port; use as context manager."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""

    def start(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
        port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "VulnerableApp":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
