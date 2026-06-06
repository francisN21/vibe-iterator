"""Firebase-shaped vulnerable HTTP fixture for proof tests.

All vulnerabilities are deliberate and local-only (127.0.0.1).
Routes simulate an open Firebase project (no Security Rules enforced):
  - RTDB:       GET/PUT/DELETE /{path}.json
  - Firestore:  GET/PATCH/DELETE /v1/projects/{pid}/databases/(default)/documents/{coll}/{doc}
  - Storage:    GET/POST/DELETE /v0/b/{bucket}/o[/{enc_path}]
  - Auth:       POST /v1/accounts:signUp, POST /v1/accounts:createAuthUri
  - Functions:  POST/GET/OPTIONS /{fn_name}  (any path not matched above)
  - Negative controls: secured Firestore/RTDB/Storage routes return denied responses
  - Positive probe controls: probe-prefixed writes/uploads return shaped success responses
  - Auth controls: anonymous signup enabled and disabled paths are modeled separately
  - Functions controls: unauthenticated execution and reflected credentialed CORS are separate
"""
from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_FAKE_TOKEN = (
    "eyJhbGciOiJSUzI1NiJ9"
    ".eyJzdWIiOiJ1aWQxMjMiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ"
    ".fakesig"
)


class FirebaseHandler(BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        qs = urllib.parse.parse_qs(p.query)

        if path == "/":
            self._html(200, """<!doctype html><title>Firebase Fixture</title>
            <script>
            fetch('/users.json');
            fetch('/v0/b/proj.appspot.com/o');
            fetch('/helloFunction', {method:'POST', body:'{}'});
            </script>""")
            return

        if path == "/login":
            self._html(200, """<!doctype html><title>Login</title>
            <form action="/dashboard" method="get">
              <input type="email" name="email" autocomplete="email">
              <input type="password" name="password" autocomplete="current-password">
              <button type="submit">Sign in</button>
            </form>""")
            return

        if path == "/dashboard":
            self._html(200, """<!doctype html><title>Dashboard</title>
            <script>
            fetch('/users.json');
            fetch('/v0/b/proj.appspot.com/o');
            fetch('/helloFunction', {method:'POST', body:'{}'});
            </script>""")
            return

        # RTDB: secured path -> 401
        if path.startswith("/secured/") or path == "/secured.json":
            self._json(401, {"error": "Permission denied"})
            return

        # RTDB: root or path.json
        if path.endswith(".json"):
            rtdb_path = path[:-5] or "/"
            if rtdb_path in ("/", ""):
                if "shallow" in qs:
                    self._json(200, {"users": True, "config": True, "admin": True})
                else:
                    self._json(200, {"users": {"uid1": {"name": "alice"}},
                                     "config": {"plan": "free"}})
                return
            self._json(200, {"data": "open", "path": rtdb_path})
            return

        # Storage: list objects
        if "/v0/b/" in path and path.endswith("/o"):
            self._json(200, {"items": [
                {"name": "avatars/user1.png"},
                {"name": "uploads/doc.pdf"},
            ]})
            return

        # Storage: download
        if "/v0/b/" in path and "/o/" in path and "alt=media" in p.query:
            parts = path.split("/o/", 1)
            file_path = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            if "private" in file_path and "Authorization" not in self.headers:
                self._json(403, {"error": "Permission denied"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            data = b"file-content-bytes"
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Firestore: GET doc
        if "/databases/(default)/documents/" in path:
            parts = path.split("/documents/", 1)
            doc_path = parts[1] if len(parts) > 1 else ""
            # secured collection
            if doc_path.startswith("secured/"):
                self._permission_denied()
                return
            self._json(200, {"fields": {
                "name": {"stringValue": "alice"},
                "role": {"stringValue": "user"},
            }})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}

        # Auth: anonymous sign-up (signUp with no email = anonymous)
        if path.endswith("accounts:signUp"):
            if body.get("disableAnonymous") is True:
                self._json(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
                return
            if not body.get("email"):
                self._json(200, {
                    "kind": "identitytoolkit#SignupNewUserResponse",
                    "localId": "anonUid999",
                    "idToken": _FAKE_TOKEN,
                    "refreshToken": "fake-refresh",
                })
                return
            self._json(400, {"error": {"message": "ANONYMOUS_SIGN_IN_DISABLED"}})
            return

        # Auth: createAuthUri (email enumeration)
        if path.endswith("accounts:createAuthUri"):
            identifier = body.get("identifier", "")
            if "@example.com" in identifier:
                self._json(200, {"registered": True, "allProviders": ["password"]})
            else:
                self._json(200, {"registered": False, "allProviders": []})
            return

        # Storage: upload
        if "/v0/b/" in path and path.endswith("/o"):
            name = urllib.parse.parse_qs(p.query).get("name", [""])[0]
            if name.startswith("secured/"):
                self._permission_denied()
                return
            if name:
                self.server._store[name] = raw
            self._json(200, {"name": name, "bucket": "proj.appspot.com"})
            return

        # Firestore: write
        if "/databases/(default)/documents/" in path:
            self.server._store[path] = raw.decode()
            self._json(200, {"name": path, "fields": {}})
            return

        # Functions: any POST to unknown path -> 200 (unauthenticated function)
        if not self.headers.get("Authorization"):
            self._json(200, {"result": "ok", "token": _FAKE_TOKEN,
                             "message": "Function executed without auth"})
            return
        self._json(200, {"result": "ok"})

    def do_PUT(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""

        # RTDB write
        if path.endswith(".json"):
            # secured path -> 401
            rtdb_path = path[:-5]
            if rtdb_path.startswith("/secured") or rtdb_path == "/secured":
                self._json(401, {"error": "Permission denied"})
                return
            self.server._store[rtdb_path] = raw.decode()
            try:
                parsed = json.loads(raw) if raw else {}
            except (json.JSONDecodeError, ValueError):
                parsed = {}
            self._json(200, parsed)
            return

        self._json(404, {"error": "not found"})

    def do_PATCH(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""

        if "/databases/(default)/documents/" in path:
            doc_path = path.split("/documents/", 1)[1]
            if doc_path.startswith("secured/"):
                self._permission_denied()
                return
            self.server._store[path] = raw.decode()
            self._json(200, {"name": path, "fields": {}})
            return

        self._json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        self.server._store.pop(path, None)

        if path.endswith(".json"):
            rtdb_path = path[:-5]
            if rtdb_path.startswith("/secured") or rtdb_path == "/secured":
                self._json(401, {"error": "Permission denied"})
                return
            self._json(200, {})
            return

        if "/databases/(default)/documents/" in path:
            doc_path = path.split("/documents/", 1)[1]
            if doc_path.startswith("secured/"):
                self._permission_denied()
                return
            self._json(200, {"name": path, "fields": {}})
            return

        if "/v0/b/" in path:
            file_path = ""
            if "/o/" in path:
                file_path = urllib.parse.unquote(path.split("/o/", 1)[1])
            if file_path.startswith("secured/"):
                self._permission_denied()
                return
            self._json(200, {})
            return

        self._json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin", "https://evil.example")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        return

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _permission_denied(self, status: int = 403) -> None:
        self._json(status, {
            "error": {
                "code": status,
                "message": "Permission denied",
                "status": "PERMISSION_DENIED",
            }
        })


class FirebaseVulnerableApp:
    """Start the Firebase fixture on a random free port; use as context manager."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""

    def start(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), FirebaseHandler)
        self._server._store: dict = {}
        port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()

    def __enter__(self) -> "FirebaseVulnerableApp":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
