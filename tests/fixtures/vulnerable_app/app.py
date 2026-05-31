"""Intentionally vulnerable HTTP fixture app for integration/proof tests.

Vulnerabilities baked in (all deliberate, local-only):
  - /api/data       — no auth required, wildcard CORS (ACAO: *)
  - /api/user       — reflects Origin header in ACAO (reflected origin CORS)
  - /api/protected  — authenticated in original request but 200 without auth
  - /api/login      — auth endpoint with no rate-limit headers
  - /api/search     — returns SQL error string when ' injected in ?q=
  - /api/profile    — POST/PATCH echoes all fields including injected ones (mass assignment)
  - /api/items/{id} — returns items for any numeric ID without auth check (IDOR)
  - /swagger.json   — exposed API docs (info disclosure)
  - /.env           — exposed env file (info disclosure)
  - /api/resource   — GET-only resource but accepts DELETE (method tampering)
  - /login          — permissive test login form for e2e scan runner
  - /               — page with innerHTML DOM sink + no security headers
  - All responses   — no X-Content-Type-Options, no X-Frame-Options, no CSP
"""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Module-level attempt counter — reset by VulnerableApp.start()
_attempt_counts: dict[str, int] = {}


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
            self._respond_json(200, {"secret": "admin-token-abc123"})
        elif path == "/api/admin":
            self._respond_json(200, {"users": ["alice", "bob"]})
        elif path == "/api/login":
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
        elif re.match(r"^/api/items/(\d+)$", path):
            # IDOR: returns data for any numeric ID without auth check
            item_id = re.match(r"^/api/items/(\d+)$", path).group(1)
            self._respond_json(200, {"id": int(item_id), "owner_id": 1, "data": "sensitive-value"})
        elif path == "/api/resource":
            self._respond_json(200, {"resource": "data"})
        elif path == "/swagger.json":
            # Info disclosure: exposed API docs
            self._respond_json(200, {
                "openapi": "3.0.0",
                "info": {"title": "Vulnerable API", "version": "1.0.0"},
                "paths": {
                    "/api/admin": {"get": {"summary": "Admin endpoint"}},
                    "/api/profile": {"post": {"summary": "Create/update profile"}},
                },
            })
        elif path == "/.env":
            # Info disclosure: exposed env file
            data = b"DATABASE_URL=postgresql://admin:s3cr3t@localhost/db\nSECRET_KEY=super-secret-key-12345\nSTRIPE_SECRET=sk_live_abc123def456\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/":
            self._respond_html(200, _INDEX_HTML)
        elif path == "/login":
            self._respond_html(200, _LOGIN_HTML)
        elif path == "/dashboard":
            self._respond_html(200, _DASHBOARD_HTML)
        else:
            self._respond_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length else b""

        # Check for method override header
        override = self.headers.get("X-HTTP-Method-Override", "") or self.headers.get("X-Method-Override", "")
        if override.upper() == "DELETE" and path == "/api/resource":
            self._respond_json(200, {"deleted": True, "message": "resource deleted via override"})
            return

        if path == "/api/profile":
            try:
                submitted = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                submitted = {}
            self._respond_json(201, {"id": 42, **submitted})

        elif path == "/api/auth/login":
            # No rate limiting — always 401 (triggers Finding A)
            self._respond_json(401, {"error": "invalid credentials"})

        elif path == "/api/auth/signup":
            # No rate limiting — always 200 (triggers Finding A)
            self._respond_json(200, {"message": "registered"})

        elif path == "/api/auth/forgot-password":
            # Lockout: attempts 1-4 → 401, attempt 5+ → 403 (triggers Finding B)
            _attempt_counts[path] = _attempt_counts.get(path, 0) + 1
            n = _attempt_counts[path]
            if n < 5:
                self._respond_json(401, {"error": "invalid credentials"})
            else:
                self._respond_json(403, {"error": "account locked"})

        elif path == "/api/auth/rate-limited-login":
            # Properly rate-limited: attempt 2+ → 429 + Retry-After (negative control)
            _attempt_counts[path] = _attempt_counts.get(path, 0) + 1
            n = _attempt_counts[path]
            if n == 1:
                self._respond_json(401, {"error": "invalid credentials"})
            else:
                data = json.dumps({"error": "Too many attempts."}).encode()
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Retry-After", "30")
                self.end_headers()
                self.wfile.write(data)

        else:
            self._respond_json(404, {"error": "not found"})

    def do_PATCH(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length else b""

        if path == "/api/profile":
            # Mass assignment: echoes ALL submitted fields back (vulnerable)
            try:
                submitted = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                submitted = {}
            self._respond_json(200, {"id": 42, **submitted})
        else:
            self._respond_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/resource":
            # Method tampering: should be 405 Method Not Allowed but returns 200
            self._respond_json(200, {"deleted": True})
        else:
            self._respond_json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        origin = self.headers.get("Origin", "")

        if path == "/api/user":
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
        return

    def _respond_json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _respond_html(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


_INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>Vulnerable App</title></head>
<body>
  <div id="output"></div>
  <script>
    var hash = location.hash.slice(1);
    document.getElementById('output').innerHTML = decodeURIComponent(hash);
    if (hash.startsWith('write:')) {
      document.write(hash.slice(6));
    }
    fetch('/api/data').then(r => r.json()).then(d => {
      document.getElementById('output').innerHTML += JSON.stringify(d);
    });
  </script>
</body>
</html>"""

_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <form action="/dashboard" method="get">
    <input type="email" name="email" autocomplete="email">
    <input type="password" name="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body>
</html>"""

_DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
  <h1>Private Dashboard</h1>
  <script>
    fetch('/api/user');
    fetch('/api/login');
    fetch('/api/protected', {headers: {'Authorization': 'Bearer fake-jwt'}});
  </script>
</body>
</html>"""


class VulnerableApp:
    """Start the vulnerable app on a random free port; use as context manager."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""

    def start(self) -> str:
        _attempt_counts.clear()          # reset per test session
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
