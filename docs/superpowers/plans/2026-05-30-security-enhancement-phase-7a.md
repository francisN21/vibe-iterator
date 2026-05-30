# Security Enhancement Phase 7A — New Scanners

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four new security scanners (mass_assignment, info_disclosure, idor_check, http_method_tampering) identified by cross-referencing OWASP API Top 10 and secskills methodology against existing scanner coverage.

**Architecture:** Each scanner follows the established `BaseScanner` pattern (name, stages, category, `run()` → `list[Finding]`), uses mock-friendly listeners for unit tests, and extends the vulnerable fixture app for proof tests. All four are registered in `_SCANNER_MODULE_MAP` in `runner.py`.

**Tech Stack:** Python 3.11+, pytest, urllib (no new deps), existing `vibe_iterator.scanners.base`, `vibe_iterator.utils.supabase_helpers.truncate`

---

## File Map

**New files:**
- `vibe_iterator/scanners/mass_assignment.py`
- `vibe_iterator/scanners/info_disclosure.py`
- `vibe_iterator/scanners/idor_check.py`
- `vibe_iterator/scanners/http_method_tampering.py`
- `tests/test_scanners/test_mass_assignment.py`
- `tests/test_scanners/test_info_disclosure.py`
- `tests/test_scanners/test_idor_check.py`
- `tests/test_scanners/test_http_method_tampering.py`

**Modified files:**
- `tests/fixtures/vulnerable_app/app.py` — add POST/PATCH/DELETE handlers + new paths
- `vibe_iterator/engine/runner.py:94-111` — add 4 entries to `_SCANNER_MODULE_MAP`
- `docs/SCANNERS.md` — add 4 registry rows

---

## Task 1: Extend VulnerableApp fixture with new vulnerable endpoints

**Files:**
- Modify: `tests/fixtures/vulnerable_app/app.py`

The fixture currently has only `do_GET` and `do_OPTIONS`. We need POST/PATCH/DELETE handlers and several new paths:
- `POST /api/profile` — echoes all submitted fields back (mass assignment vuln)
- `PATCH /api/profile` — same
- `GET /api/items/{id}` — returns item data for any numeric ID (IDOR vuln)
- `GET /swagger.json` — returns swagger doc (info disclosure)
- `GET /.env` — returns env content (info disclosure)
- `GET /api/resource` — read-only endpoint
- `DELETE /api/resource` — should be 405 but returns 200 (method tampering)
- `POST /api/resource` with `X-HTTP-Method-Override: DELETE` — also returns 200

- [ ] **Step 1: Add new handler methods to VulnerableHandler**

Open `tests/fixtures/vulnerable_app/app.py`. Replace the entire file content with:

```python
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
  - /               — page with innerHTML DOM sink + no security headers
  - All responses   — no X-Content-Type-Options, no X-Frame-Options, no CSP
"""

from __future__ import annotations

import json
import re
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
            # Method tampering: should reject override but doesn't
            self._respond_json(200, {"deleted": True, "message": "resource deleted via override"})
            return

        if path == "/api/profile":
            # Mass assignment: echoes ALL submitted fields back (vulnerable)
            try:
                submitted = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                submitted = {}
            self._respond_json(201, {"id": 42, **submitted})
        elif path == "/api/auth/login":
            self._respond_json(401, {"error": "invalid credentials"})
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

_DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body><h1>Private Dashboard</h1></body>
</html>"""


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
```

- [ ] **Step 2: Verify existing proof tests still pass**

```bash
pytest tests/test_scanners/test_auth_check_proof.py tests/test_scanners/test_sql_injection_proof.py -v
```
Expected: all 7 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/vulnerable_app/app.py
git commit -m "test: extend VulnerableApp fixture with mass-assignment, IDOR, info-disclosure, method-tampering endpoints"
```

---

## Task 2: mass_assignment scanner

**Files:**
- Create: `vibe_iterator/scanners/mass_assignment.py`
- Create: `tests/test_scanners/test_mass_assignment.py`

**What it does:** Replays captured POST/PUT/PATCH requests with extra privilege fields injected into the JSON body. A finding is raised if the server echoes the injected field back in the response (proving it was stored/processed).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scanners/test_mass_assignment.py`:

```python
"""Mass assignment scanner tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.mass_assignment import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_post_req(url: str, body: dict, status: int = 200) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "POST"
    req.status_code = status
    req.response_body = json.dumps(body)
    req.post_data = json.dumps({"name": "alice"})
    req.headers = {"Content-Type": "application/json"}
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Positive: injected role field echoed back → finding
# ---------------------------------------------------------------------------

def test_mass_assignment_role_detected(vuln_app) -> None:
    req = _make_post_req(
        url=vuln_app.base_url + "/api/profile",
        body={"id": 42, "name": "alice"},
    )
    findings = _run(vuln_app, [req])
    ma = [f for f in findings if "mass assignment" in f.title.lower()]
    assert len(ma) >= 1
    assert ma[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert "role" in ma[0].title.lower() or "is_admin" in ma[0].title.lower() or "admin" in ma[0].title.lower()


def test_mass_assignment_credits_critical(vuln_app) -> None:
    # credits/balance fields → CRITICAL severity (financial impact)
    req = _make_post_req(
        url=vuln_app.base_url + "/api/profile",
        body={"id": 42, "name": "alice"},
    )
    findings = _run(vuln_app, [req])
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    # fixture echoes credits=99999 back → CRITICAL finding expected
    assert len(critical) >= 1


# ---------------------------------------------------------------------------
# Negative: no POST body → no finding
# ---------------------------------------------------------------------------

def test_no_finding_when_no_post_requests() -> None:
    scanner = Scanner()
    config = _make_config()
    net = _make_network([])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []


def test_no_finding_when_get_only() -> None:
    req = MagicMock()
    req.method = "GET"
    req.url = "http://localhost:9999/api/data"
    req.post_data = None
    scanner = Scanner()
    config = _make_config()
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "mass_assignment"
    assert s.category == "Access Control"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scanners/test_mass_assignment.py -v
```
Expected: ImportError — `mass_assignment` does not exist yet.

- [ ] **Step 3: Implement the scanner**

Create `vibe_iterator/scanners/mass_assignment.py`:

```python
"""Mass assignment scanner — tests POST/PUT/PATCH endpoints for unfiltered field acceptance."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# (field_name, value, is_financial)
_PRIVILEGE_FIELDS: list[tuple[str, Any, bool]] = [
    ("role", "admin", False),
    ("is_admin", True, False),
    ("isAdmin", True, False),
    ("admin", True, False),
    ("user_role", "admin", False),
    ("permissions", ["admin"], False),
    ("credits", 99999, True),
    ("balance", 99999, True),
    ("price", 0, True),
    ("discount", 100, True),
    ("account_type", "enterprise", False),
    ("subscription", "premium", False),
    ("verified", True, False),
    ("email_verified", True, False),
]

_WRITE_METHODS = {"POST", "PUT", "PATCH"}


class Scanner(BaseScanner):
    """Replays write endpoints with injected privilege fields to detect mass assignment."""

    name = "mass_assignment"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        token = _get_auth_headers(config)

        tested: set[str] = set()

        for req in network.get_requests():
            if req.method not in _WRITE_METHODS:
                continue
            if not req.post_data:
                continue
            if not req.url.startswith("http"):
                continue
            if any(skip in req.url for skip in ["/static/", ".js", ".css", "/auth/", "/login"]):
                continue

            endpoint_key = f"{req.method}:{req.url}"
            if endpoint_key in tested:
                continue
            tested.add(endpoint_key)

            try:
                original_body = json.loads(req.post_data)
                if not isinstance(original_body, dict):
                    continue
            except (json.JSONDecodeError, TypeError):
                continue

            for field_name, field_value, is_financial in _PRIVILEGE_FIELDS:
                if field_name in original_body:
                    continue

                injected_body = {**original_body, field_name: field_value}
                resp_body, status, _ = _make_request(
                    req.url, req.method,
                    json.dumps(injected_body).encode(),
                    token,
                )

                if status not in (200, 201) or not resp_body:
                    continue

                try:
                    resp_data = json.loads(resp_body)
                except (json.JSONDecodeError, ValueError):
                    continue

                if not isinstance(resp_data, dict):
                    continue

                if field_name not in resp_data:
                    continue

                returned_val = resp_data[field_name]
                if str(returned_val).lower() != str(field_value).lower():
                    continue

                sev = Severity.CRITICAL if is_financial else Severity.HIGH
                desc = (
                    f"The endpoint `{req.method} {req.url}` accepted and echoed back "
                    f"the injected field `{field_name}={field_value}`. "
                    "The server does not filter unexpected fields from the request body. "
                    "An attacker can escalate privileges or manipulate protected attributes "
                    "(such as account role or pricing) by adding extra fields to legitimate API requests."
                )
                findings.append(self.new_finding(
                    scanner=self.name,
                    severity=sev,
                    title=f"Mass assignment: server accepted `{field_name}` in {req.method} {req.url}",
                    description=desc,
                    evidence={
                        "request": {
                            "method": req.method,
                            "url": req.url,
                            "body": truncate(json.dumps(injected_body), 300),
                        },
                        "response": {"status": status, "body_excerpt": truncate(resp_body, 300)},
                        "injected_field": field_name,
                        "injected_value": str(field_value),
                        "returned_value": str(returned_val),
                        "payload_used": json.dumps({field_name: field_value}),
                        "payload_type": "mass_assignment",
                        "injection_point": f"json_body:{field_name}",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Mass assignment: server accepted `{field_name}`",
                        severity=sev,
                        scanner=self.name,
                        page=req.url,
                        category=self.category,
                        description=desc,
                        evidence_summary=(
                            f"{req.method} {req.url}\n"
                            f"Injected: {field_name}={field_value}\n"
                            f"Response echoed: {field_name}={returned_val}"
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{field_name}` field is accepted from the client and "
                        "stored/processed without an allowlist filter.\n\n"
                        "**How to fix:** Use an explicit allowlist of permitted fields before saving. "
                        "Never use `Object.assign(record, req.body)` or `model.create(req.body)` directly. "
                        "In JavaScript: `const safe = pick(req.body, ['name', 'email'])`. "
                        "For Supabase: use column-level grants — "
                        f"`REVOKE UPDATE ({field_name}) ON profiles FROM authenticated;`\n\n"
                        "**Verify the fix:** Re-run mass_assignment scanner — injected field must not appear in response."
                    ),
                    category=self.category,
                    page=req.url,
                ))
                break  # one finding per endpoint is enough to prove the issue

        return findings


def _make_request(
    url: str, method: str, data: bytes | None, headers: dict, timeout: int = 6
) -> tuple[str, int | None, float]:
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(50_000).decode("utf-8", errors="replace")
            return body, resp.status, time.monotonic() - start
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(50_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return body, e.code, time.monotonic() - start
    except Exception:
        return "", None, time.monotonic() - start


def _get_auth_headers(config: Any) -> dict:
    headers: dict = {"Content-Type": "application/json"}
    anon_key = getattr(config, "supabase_anon_key", None)
    if anon_key:
        headers["apikey"] = anon_key
        headers["Authorization"] = f"Bearer {anon_key}"
    return headers
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_scanners/test_mass_assignment.py -v
```
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add vibe_iterator/scanners/mass_assignment.py tests/test_scanners/test_mass_assignment.py
git commit -m "feat: add mass_assignment scanner — detects unfiltered field acceptance in POST/PATCH"
```

---

## Task 3: info_disclosure scanner

**Files:**
- Create: `vibe_iterator/scanners/info_disclosure.py`
- Create: `tests/test_scanners/test_info_disclosure.py`

**What it does:**
- Group 1: Probes common sensitive paths (swagger, .env, debug endpoints, .git)
- Group 2: Scans response headers for version disclosure (Server, X-Powered-By)
- Group 3: Scans captured 5xx responses for stack traces
- Group 4: Scans captured JS file responses for hardcoded secrets (Stripe keys, AWS keys, etc.)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scanners/test_info_disclosure.py`:

```python
"""Info disclosure scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.info_disclosure import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(url: str, status: int = 200, body: str = "", headers: dict | None = None) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = status
    req.response_body = body
    req.response_headers = headers or {}
    req.post_data = None
    return req


def _run(vuln_app, network_requests=None) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests or [])
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Group 1 — sensitive path probing (against live fixture)
# ---------------------------------------------------------------------------

def test_swagger_json_exposed(vuln_app) -> None:
    findings = _run(vuln_app)
    swagger = [f for f in findings if "swagger" in f.title.lower() or "api doc" in f.title.lower()]
    assert len(swagger) >= 1
    assert swagger[0].severity in (Severity.MEDIUM, Severity.HIGH)


def test_env_file_exposed(vuln_app) -> None:
    findings = _run(vuln_app)
    env_f = [f for f in findings if ".env" in f.title.lower() or "environment" in f.title.lower()]
    assert len(env_f) >= 1
    assert env_f[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Group 2 — version header detection (mock)
# ---------------------------------------------------------------------------

def test_version_header_server_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/api/data",
        headers={"Server": "Apache/2.4.41 (Ubuntu)", "Content-Type": "application/json"},
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    version = [f for f in findings if "version" in f.title.lower() or "server" in f.title.lower()]
    assert len(version) >= 1
    assert version[0].severity == Severity.LOW


def test_x_powered_by_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/api/data",
        headers={"X-Powered-By": "Express", "Content-Type": "application/json"},
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    powered = [f for f in findings if "powered" in f.title.lower() or "version" in f.title.lower()]
    assert len(powered) >= 1


# ---------------------------------------------------------------------------
# Group 3 — stack trace in 500 response (mock)
# ---------------------------------------------------------------------------

def test_stack_trace_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/api/error",
        status=500,
        body='{"error": "Traceback (most recent call last):\\n  File app.py line 42\\nValueError: bad input"}',
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    stack = [f for f in findings if "stack trace" in f.title.lower() or "traceback" in f.title.lower()]
    assert len(stack) >= 1
    assert stack[0].severity in (Severity.MEDIUM, Severity.HIGH)


# ---------------------------------------------------------------------------
# Group 4 — hardcoded secret in JS (mock)
# ---------------------------------------------------------------------------

def test_stripe_key_in_js_detected() -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req(
        url="http://localhost:9999/app.js",
        body="const stripeKey = 'sk_live_AbCdEfGhIjKlMnOpQrStUvWx';",
        headers={"Content-Type": "application/javascript"},
    )
    net = _make_network([req])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    secret = [f for f in findings if "secret" in f.title.lower() or "key" in f.title.lower() or "stripe" in f.title.lower()]
    assert len(secret) >= 1
    assert secret[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Negative — clean responses produce no findings
# ---------------------------------------------------------------------------

def test_no_finding_on_clean_app() -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:19999")  # nothing listening — all probes fail
    net = _make_network([])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    # Path probes all fail (no server), no network traffic → no findings
    assert findings == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "info_disclosure"
    assert s.category == "Misconfiguration"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scanners/test_info_disclosure.py -v
```
Expected: ImportError — module does not exist.

- [ ] **Step 3: Implement the scanner**

Create `vibe_iterator/scanners/info_disclosure.py`:

```python
"""Information disclosure scanner — exposes debug endpoints, docs, secrets, and version headers."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# (path, label, severity)
_SENSITIVE_PATHS: list[tuple[str, str, Severity]] = [
    ("/.env", "Environment file", Severity.CRITICAL),
    ("/.env.local", "Environment file", Severity.CRITICAL),
    ("/.env.production", "Environment file", Severity.CRITICAL),
    ("/.env.development", "Environment file", Severity.HIGH),
    ("/swagger.json", "API documentation", Severity.MEDIUM),
    ("/swagger.yaml", "API documentation", Severity.MEDIUM),
    ("/openapi.json", "API documentation", Severity.MEDIUM),
    ("/openapi.yaml", "API documentation", Severity.MEDIUM),
    ("/api-docs", "API documentation", Severity.MEDIUM),
    ("/api-docs.json", "API documentation", Severity.MEDIUM),
    ("/v1/api-docs", "API documentation", Severity.MEDIUM),
    ("/swagger-ui/", "Swagger UI", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI", Severity.MEDIUM),
    ("/redoc", "API documentation", Severity.MEDIUM),
    ("/__debug__", "Debug endpoint", Severity.HIGH),
    ("/debug", "Debug endpoint", Severity.HIGH),
    ("/debug-info", "Debug endpoint", Severity.HIGH),
    ("/actuator/env", "Spring Actuator env", Severity.HIGH),
    ("/actuator/health", "Health endpoint", Severity.LOW),
    ("/actuator", "Spring Actuator", Severity.MEDIUM),
    ("/.git/config", "Git repository", Severity.HIGH),
    ("/.git/HEAD", "Git repository", Severity.HIGH),
    ("/phpinfo.php", "PHP info", Severity.HIGH),
    ("/server-status", "Apache server status", Severity.MEDIUM),
    ("/console", "Admin console", Severity.HIGH),
]

_VERSION_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"}

# Patterns that indicate version numbers in header values
_VERSION_PATTERN = re.compile(r"\d+\.\d+")

_STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at \S+\.\S+\([\w.]+:\d+\)"),  # Java/JS stack
    re.compile(r"java\.lang\.\w+Exception", re.I),
    re.compile(r"System\.Exception", re.I),
    re.compile(r"in .*?\.php on line \d+", re.I),
    re.compile(r"RuntimeError|AttributeError|TypeError|ValueError", re.I),
]

# (compiled_pattern, label, severity)
_SECRET_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"sk_live_[a-zA-Z0-9]{24,}"), "Stripe live secret key", Severity.CRITICAL),
    (re.compile(r"sk_test_[a-zA-Z0-9]{24,}"), "Stripe test secret key", Severity.HIGH),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID", Severity.CRITICAL),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token", Severity.CRITICAL),
    (re.compile(r"xoxb-[0-9]+-[a-zA-Z0-9-]+"), "Slack bot token", Severity.HIGH),
    (re.compile(r"xoxp-[0-9]+-[a-zA-Z0-9-]+"), "Slack user token", Severity.HIGH),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key", Severity.HIGH),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})", re.I), "Hardcoded password", Severity.HIGH),
    (re.compile(r"(?:secret_?key|SECRET_?KEY)\s*[=:]\s*['\"]([^'\"]{8,})", re.I), "Hardcoded secret key", Severity.HIGH),
]

_JS_CONTENT_TYPES = {"application/javascript", "text/javascript", "application/x-javascript"}


class Scanner(BaseScanner):
    """Four-group information disclosure audit."""

    name = "info_disclosure"
    category = "Misconfiguration"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target.rstrip("/")

        self._probe_sensitive_paths(target, stack, findings)
        self._check_version_headers(network, target, stack, findings)
        self._check_stack_traces(network, target, stack, findings)
        self._check_js_secrets(network, target, stack, findings)

        return findings

    # ------------------------------------------------------------------ #
    # Group 1 — Probe sensitive paths                                      #
    # ------------------------------------------------------------------ #

    def _probe_sensitive_paths(
        self, target: str, stack: str, findings: list[Finding]
    ) -> None:
        ctx = ssl._create_unverified_context()
        seen_fps: set[str] = set()

        for path, label, severity in _SENSITIVE_PATHS:
            url = target + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "vibe-iterator/info-check"})
                with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                    status = resp.status
                    body = resp.read(2048).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                continue  # 401/403/404 — expected, not exposed
            except Exception:
                continue

            if status != 200:
                continue

            fp = self.make_fingerprint(self.name, f"Sensitive path exposed: {path}", target)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)

            desc = (
                f"The path `{path}` ({label}) returned HTTP 200 and is accessible without authentication. "
                "Exposed documentation, configuration files, or debug endpoints can reveal API structure, "
                "internal credentials, or server configuration to attackers."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=severity,
                title=f"Sensitive path exposed: {path} ({label})",
                description=desc,
                evidence={
                    "request": {"method": "GET", "url": url},
                    "response": {"status": status, "body_excerpt": truncate(body, 300)},
                    "payload_type": "path_probe",
                    "payload_used": path,
                    "injection_point": "url_path",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"Sensitive path exposed: {path}",
                    severity=severity, scanner=self.name, page=url,
                    category=self.category, description=desc,
                    evidence_summary=f"GET {url} → HTTP {status}\nContent: {truncate(body, 200)}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** `{path}` is publicly accessible.\n\n"
                    "**How to fix:** "
                    "For `.env` files: ensure your web server never serves them. "
                    "In nginx: `location ~ /\\.env { deny all; }`. "
                    "For swagger/api-docs: require authentication middleware on documentation routes. "
                    "For debug endpoints: disable them in production via environment variables.\n\n"
                    "**Verify the fix:** Re-run info_disclosure scanner — path should return 401 or 404."
                ),
                category=self.category, page=url,
            ))

    # ------------------------------------------------------------------ #
    # Group 2 — Version disclosure in response headers                    #
    # ------------------------------------------------------------------ #

    def _check_version_headers(
        self, network: Any, target: str, stack: str, findings: list[Finding]
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            if req.response_headers is None:
                continue
            lowered = {k.lower(): v for k, v in req.response_headers.items()}

            for header_key in _VERSION_HEADERS:
                val = lowered.get(header_key, "")
                if not val:
                    continue
                # Only flag if it contains a version number
                if not _VERSION_PATTERN.search(val):
                    # Still flag X-Powered-By even without version (leaks tech stack)
                    if header_key != "x-powered-by":
                        continue

                fp = self.make_fingerprint(self.name, f"Version disclosure: {header_key}", target)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                desc = (
                    f"The `{header_key}: {val}` response header reveals the server software and version. "
                    "Attackers use version information to look up known vulnerabilities (CVEs) for the "
                    "specific version in use and craft targeted exploits."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.LOW,
                    title=f"Version disclosure via `{header_key}` header",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": getattr(req, "status_code", "?"), "headers": {header_key: val}},
                        "payload_type": "header_inspection",
                        "payload_used": f"{header_key}: {val}",
                        "injection_point": f"response_header:{header_key}",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Version disclosure via `{header_key}`",
                        severity=Severity.LOW, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"Header: {header_key}: {val}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** Remove or redact the `{header_key}` header.\n\n"
                        "**How to fix:** "
                        "For nginx: `server_tokens off;`. "
                        "For Express/Node.js: `app.disable('x-powered-by')` or use `helmet`. "
                        "For Apache: `ServerTokens Prod; ServerSignature Off`.\n\n"
                        "**Verify the fix:** Re-run info_disclosure scanner."
                    ),
                    category=self.category, page=req.url,
                ))

    # ------------------------------------------------------------------ #
    # Group 3 — Stack traces in error responses                           #
    # ------------------------------------------------------------------ #

    def _check_stack_traces(
        self, network: Any, target: str, stack: str, findings: list[Finding]
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            if req.status_code not in (500, 502, 503):
                continue
            body = req.response_body or ""
            if not body:
                continue

            for pattern in _STACK_TRACE_PATTERNS:
                m = pattern.search(body)
                if not m:
                    continue

                fp = self.make_fingerprint(self.name, "Stack trace in error response", req.url)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                desc = (
                    f"A server error response from `{req.url}` contains a stack trace or verbose error message. "
                    "Stack traces reveal internal file paths, library versions, function names, and line numbers — "
                    "information that significantly aids attackers in understanding the system's architecture."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Stack trace / verbose error exposed in HTTP response",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": req.status_code, "body_excerpt": truncate(body, 400)},
                        "payload_type": "passive_analysis",
                        "payload_used": "none (passive)",
                        "injection_point": "response_body",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title="Stack trace exposed in HTTP response",
                        severity=Severity.MEDIUM, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"Stack trace in {req.method} {req.url} 500 response:\n{truncate(body, 200)}",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Verbose error details and stack traces are returned in HTTP responses.\n\n"
                        "**How to fix:** Return generic error messages in production: `{'error': 'Internal server error'}`. "
                        "Log full stack traces server-side only. "
                        "For Express: use a global error handler that omits stack traces in non-dev environments. "
                        "For Next.js: disable `productionBrowserSourceMaps`.\n\n"
                        "**Verify the fix:** Re-run info_disclosure scanner."
                    ),
                    category=self.category, page=req.url,
                ))
                break  # one finding per request

    # ------------------------------------------------------------------ #
    # Group 4 — Hardcoded secrets in JavaScript files                    #
    # ------------------------------------------------------------------ #

    def _check_js_secrets(
        self, network: Any, target: str, stack: str, findings: list[Finding]
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            ct = ""
            if req.response_headers:
                ct = req.response_headers.get("Content-Type", req.response_headers.get("content-type", ""))
            if not any(js_ct in ct for js_ct in _JS_CONTENT_TYPES) and not req.url.endswith(".js"):
                continue

            body = req.response_body or ""
            if not body:
                continue

            for pattern, label, severity in _SECRET_PATTERNS:
                m = pattern.search(body)
                if not m:
                    continue

                fp = self.make_fingerprint(self.name, f"Secret in JS: {label}", req.url)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                matched_text = m.group(0)
                desc = (
                    f"A {label} was found in the JavaScript file at `{req.url}`. "
                    "Any user who visits your application can read this file and extract the secret. "
                    "This can lead to immediate compromise of the associated service."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=severity,
                    title=f"Hardcoded secret in JavaScript: {label}",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {
                            "status": getattr(req, "status_code", "?"),
                            "body_excerpt": truncate(matched_text, 80) + "...",
                        },
                        "payload_type": "passive_analysis",
                        "payload_used": "none (passive — pattern match)",
                        "injection_point": "response_body:js_file",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Hardcoded secret: {label}",
                        severity=severity, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"{label} found in {req.url}:\n{truncate(matched_text, 80)}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** A {label} is hardcoded in a client-side JavaScript file.\n\n"
                        "**How to fix:** Move all secrets to server-side environment variables. "
                        "Never bundle API keys in frontend code. "
                        "If exposed: rotate the key immediately in the provider dashboard. "
                        "Use a secrets manager (Vault, AWS Secrets Manager) for production credentials.\n\n"
                        "**Verify the fix:** Re-run info_disclosure scanner — no secrets in JS files."
                    ),
                    category=self.category, page=req.url,
                ))
                break  # one finding per JS file
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_scanners/test_info_disclosure.py -v
```
Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add vibe_iterator/scanners/info_disclosure.py tests/test_scanners/test_info_disclosure.py
git commit -m "feat: add info_disclosure scanner — sensitive paths, version headers, stack traces, JS secrets"
```

---

## Task 4: idor_check scanner

**Files:**
- Create: `vibe_iterator/scanners/idor_check.py`
- Create: `tests/test_scanners/test_idor_check.py`

**What it does:** Discovers API endpoints with numeric IDs in URL paths, then probes adjacent IDs (±1, ±2, a random high number) using the current auth token. If a different ID returns data, it's an IDOR.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scanners/test_idor_check.py`:

```python
"""IDOR check scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.idor_check import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(url: str, status: int = 200, body: str = '{"id":1,"data":"mine"}') -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = status
    req.response_body = body
    req.post_data = None
    req.headers = {"Authorization": "Bearer fake-token"}
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Positive — IDOR on numeric ID endpoint
# ---------------------------------------------------------------------------

def test_idor_numeric_id_detected(vuln_app) -> None:
    # Captured request shows /api/items/1 was accessed (user's own resource)
    req = _make_req(url=vuln_app.base_url + "/api/items/1")
    findings = _run(vuln_app, [req])
    idor = [f for f in findings if "idor" in f.title.lower() or "insecure direct" in f.title.lower()]
    assert len(idor) >= 1
    assert idor[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Negative — no numeric ID in URL → no finding
# ---------------------------------------------------------------------------

def test_no_finding_for_non_id_endpoint(vuln_app) -> None:
    req = _make_req(url=vuln_app.base_url + "/api/data")
    findings = _run(vuln_app, [req])
    idor = [f for f in findings if "idor" in f.title.lower()]
    assert idor == []


def test_no_finding_when_alternate_id_returns_403(vuln_app) -> None:
    # If we try /api/admin (which is 200 but has no numeric id variation), no IDOR
    req = _make_req(url=vuln_app.base_url + "/api/admin")
    findings = _run(vuln_app, [req])
    idor = [f for f in findings if "idor" in f.title.lower()]
    assert idor == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "idor_check"
    assert s.category == "Access Control"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scanners/test_idor_check.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement the scanner**

Create `vibe_iterator/scanners/idor_check.py`:

```python
"""IDOR check scanner — tests numeric-ID URL parameters for insecure direct object reference."""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# Matches paths like /api/users/42 or /api/items/7 — captures the numeric segment
_NUMERIC_ID_RE = re.compile(r"^(https?://[^/]+)(.*/)(\d+)(/.*)?$")

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".jpg", ".gif", ".map"}


def _is_static(url: str) -> bool:
    return any(url.endswith(ext) for ext in _STATIC_EXTS)


class Scanner(BaseScanner):
    """Detects IDOR by probing adjacent numeric IDs on discovered API endpoints."""

    name = "idor_check"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]

        tested_patterns: set[str] = set()

        for req in network.get_requests():
            if req.method != "GET":
                continue
            if _is_static(req.url):
                continue
            m = _NUMERIC_ID_RE.match(req.url)
            if not m:
                continue

            base, prefix, numeric_id_str, suffix = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            pattern_key = f"{base}{prefix}*{suffix}"
            if pattern_key in tested_patterns:
                continue
            tested_patterns.add(pattern_key)

            numeric_id = int(numeric_id_str)
            # Probe: try id+1 and id+2 (or id-1 if id > 1)
            probe_ids = [numeric_id + 1, numeric_id + 2]
            if numeric_id > 1:
                probe_ids.append(numeric_id - 1)

            # Extract auth token from original request headers
            auth_header = {}
            orig_headers = req.headers or {}
            if isinstance(orig_headers, dict):
                for k, v in orig_headers.items():
                    if k.lower() in ("authorization", "cookie", "x-api-key"):
                        auth_header[k] = v

            original_body = req.response_body or ""

            for probe_id in probe_ids:
                probe_url = f"{base}{prefix}{probe_id}{suffix}"
                resp_body, status = _fetch(probe_url, auth_header)

                if status != 200 or not resp_body:
                    continue

                # Verify it's not the same response as the original
                if resp_body.strip() == original_body.strip():
                    continue

                try:
                    data = json.loads(resp_body)
                    if not isinstance(data, dict) or not data:
                        continue
                except (json.JSONDecodeError, ValueError):
                    # Non-JSON 200 is still suspicious
                    pass

                desc = (
                    f"Accessing `{probe_url}` (ID={probe_id}) with the same auth credentials "
                    f"as `{req.url}` (ID={numeric_id}) returned HTTP 200 with data. "
                    "The server does not validate that the requested resource belongs to the authenticated user. "
                    "Any user can enumerate other users' records by changing the ID in the URL."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title=f"IDOR: resource {prefix}{{id}} accessible across users (tested ID={probe_id})",
                    description=desc,
                    evidence={
                        "original_url": req.url,
                        "original_id": numeric_id,
                        "probed_url": probe_url,
                        "probed_id": probe_id,
                        "request": {"method": "GET", "url": probe_url, "headers": auth_header},
                        "response": {"status": status, "body_excerpt": truncate(resp_body, 300)},
                        "payload_used": str(probe_id),
                        "payload_type": "idor_id_enumeration",
                        "injection_point": "url_path:numeric_id",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"IDOR: {prefix}{{id}} accessible across users",
                        severity=Severity.HIGH, scanner=self.name,
                        page=probe_url, category=self.category, description=desc,
                        evidence_summary=(
                            f"Original: GET {req.url} (ID={numeric_id})\n"
                            f"Probed:   GET {probe_url} (ID={probe_id}) → HTTP {status} with data\n"
                            f"Conclusion: any authenticated user can access any resource by ID."
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The endpoint `{prefix}{{id}}` does not verify resource ownership.\n\n"
                        "**How to fix:** Before returning a resource, check that it belongs to the authenticated user:\n"
                        "```js\n"
                        "const item = await db.items.findUnique({ where: { id, userId: session.user.id } });\n"
                        "if (!item) return res.status(403).json({ error: 'Forbidden' });\n"
                        "```\n"
                        "For Supabase: use RLS policy `USING (auth.uid() = user_id)`.\n\n"
                        "**Verify the fix:** Re-run idor_check — probed ID must return 403 or 404."
                    ),
                    category=self.category, page=probe_url,
                ))
                break  # one finding per path pattern is enough

        return findings


def _fetch(url: str, headers: dict, timeout: int = 5) -> tuple[str, int | None]:
    ctx = ssl._create_unverified_context()
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(20_000).decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        return "", e.code
    except Exception:
        return "", None
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_scanners/test_idor_check.py -v
```
Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add vibe_iterator/scanners/idor_check.py tests/test_scanners/test_idor_check.py
git commit -m "feat: add idor_check scanner — numeric ID enumeration on REST endpoints"
```

---

## Task 5: http_method_tampering scanner

**Files:**
- Create: `vibe_iterator/scanners/http_method_tampering.py`
- Create: `tests/test_scanners/test_http_method_tampering.py`

**What it does:**
- Group 1: For each captured GET endpoint, sends DELETE and PUT/PATCH — flags if response is 200 (should be 405)
- Group 2: Sends POST with `X-HTTP-Method-Override: DELETE` — flags if server processes the override

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scanners/test_http_method_tampering.py`:

```python
"""HTTP method tampering scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.http_method_tampering import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.supabase_anon_key = ""
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_get_req(url: str) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.status_code = 200
    req.response_body = '{"resource":"data"}'
    req.post_data = None
    req.headers = {}
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# Positive — DELETE accepted on GET-only endpoint
# ---------------------------------------------------------------------------

def test_delete_accepted_on_get_endpoint(vuln_app) -> None:
    req = _make_get_req(url=vuln_app.base_url + "/api/resource")
    findings = _run(vuln_app, [req])
    method = [f for f in findings if "delete" in f.title.lower() or "method" in f.title.lower()]
    assert len(method) >= 1
    assert method[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_method_override_accepted(vuln_app) -> None:
    req = _make_get_req(url=vuln_app.base_url + "/api/resource")
    findings = _run(vuln_app, [req])
    override = [f for f in findings if "override" in f.title.lower() or "x-http-method" in f.title.lower()]
    assert len(override) >= 1


# ---------------------------------------------------------------------------
# Negative — no API GET requests → no finding
# ---------------------------------------------------------------------------

def test_no_finding_when_no_requests() -> None:
    scanner = Scanner()
    config = _make_config()
    net = _make_network([])
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    assert findings == []


def test_no_finding_for_static_assets(vuln_app) -> None:
    req = _make_get_req(url=vuln_app.base_url + "/app.js")
    findings = _run(vuln_app, [req])
    method = [f for f in findings if "method" in f.title.lower()]
    assert method == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "http_method_tampering"
    assert s.category == "Misconfiguration"
    assert "pre-deploy" in s.stages
    assert s.requires_second_account is False
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scanners/test_http_method_tampering.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement the scanner**

Create `vibe_iterator/scanners/http_method_tampering.py`:

```python
"""HTTP method tampering scanner — tests DELETE/PUT on read-only endpoints and method override headers."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".jpg", ".gif", ".map", ".woff2"}
_SKIP_FRAGMENTS = ["/static/", "/assets/", "/_next/", "/__next/", "/favicon"]
_DANGEROUS_METHODS = ["DELETE", "PUT", "PATCH"]
_OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "_method"]
_MAX_ENDPOINTS = 10


def _is_api_endpoint(url: str, target: str) -> bool:
    if any(url.endswith(ext) for ext in _STATIC_EXTS):
        return False
    if any(frag in url for frag in _SKIP_FRAGMENTS):
        return False
    parsed = urlparse(url)
    return parsed.netloc == urlparse(target).netloc


class Scanner(BaseScanner):
    """Tests API endpoints for dangerous method acceptance and method override bypass."""

    name = "http_method_tampering"
    category = "Misconfiguration"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target

        get_endpoints = _discover_get_endpoints(network, target)

        seen_fps: set[str] = set()
        for url in get_endpoints[:_MAX_ENDPOINTS]:
            self._test_dangerous_methods(url, stack, target, findings, seen_fps)
            self._test_method_override(url, stack, target, findings, seen_fps)

        return findings

    # ------------------------------------------------------------------ #
    # Group 1 — Direct dangerous method test                               #
    # ------------------------------------------------------------------ #

    def _test_dangerous_methods(
        self, url: str, stack: str, target: str,
        findings: list[Finding], seen: set[str],
    ) -> None:
        for method in _DANGEROUS_METHODS:
            status, body = _fetch(url, method)
            if status is None:
                continue
            if status in (405, 501, 404, 403, 401):
                continue  # Properly rejected

            fp = self.make_fingerprint(self.name, f"{method} accepted on GET endpoint", url)
            if fp in seen:
                continue
            seen.add(fp)

            sev = Severity.CRITICAL if method == "DELETE" else Severity.HIGH
            desc = (
                f"The endpoint `{url}` accepted an HTTP `{method}` request and returned HTTP {status}. "
                "This endpoint was discovered as a GET-only resource. "
                f"Accepting {method} without authorization checks allows attackers to "
                f"{'delete' if method == 'DELETE' else 'modify'} resources they should not be able to touch."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=sev,
                title=f"HTTP method tampering: {method} accepted on {urlparse(url).path}",
                description=desc,
                evidence={
                    "request": {"method": method, "url": url, "headers": {}},
                    "response": {"status": status, "body_excerpt": truncate(body, 200)},
                    "payload_type": "method_tampering",
                    "payload_used": method,
                    "injection_point": "http_method",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"HTTP method tampering: {method} accepted",
                    severity=sev, scanner=self.name, page=url,
                    category=self.category, description=desc,
                    evidence_summary=f"{method} {url} → HTTP {status}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** The endpoint accepts {method} requests it should not handle.\n\n"
                    "**How to fix:** Explicitly define which HTTP methods each route accepts. "
                    "In Express: `router.get('/resource', handler)` — this automatically returns 404 for other methods. "
                    "Add a catch-all: `router.all('/resource', (req, res) => res.status(405).send())`. "
                    "In FastAPI: only define the method you want to expose.\n\n"
                    "**Verify the fix:** Re-run http_method_tampering scanner — endpoint should return 405."
                ),
                category=self.category, page=url,
            ))

    # ------------------------------------------------------------------ #
    # Group 2 — Method override via headers                               #
    # ------------------------------------------------------------------ #

    def _test_method_override(
        self, url: str, stack: str, target: str,
        findings: list[Finding], seen: set[str],
    ) -> None:
        for override_header in _OVERRIDE_HEADERS:
            status, body = _fetch_with_override(url, override_header, "DELETE")
            if status is None:
                continue
            if status in (405, 501, 404, 403, 401):
                continue  # Properly rejected

            fp = self.make_fingerprint(self.name, f"Method override: {override_header}", url)
            if fp in seen:
                continue
            seen.add(fp)

            desc = (
                f"The server processed a DELETE operation via the `{override_header}: DELETE` header "
                f"in a POST request to `{url}` (HTTP {status}). "
                "Method override headers allow attackers to bypass WAF rules or middleware that "
                "only restricts HTTP methods at the routing layer — the underlying handler may "
                "execute the dangerous operation without proper authorization."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title=f"HTTP method override accepted: `{override_header}: DELETE` on {urlparse(url).path}",
                description=desc,
                evidence={
                    "request": {
                        "method": "POST",
                        "url": url,
                        "headers": {override_header: "DELETE"},
                    },
                    "response": {"status": status, "body_excerpt": truncate(body, 200)},
                    "payload_type": "method_override",
                    "payload_used": f"{override_header}: DELETE",
                    "injection_point": f"request_header:{override_header}",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"HTTP method override accepted: {override_header}",
                    severity=Severity.HIGH, scanner=self.name, page=url,
                    category=self.category, description=desc,
                    evidence_summary=f"POST {url} + {override_header}: DELETE → HTTP {status}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** The `{override_header}` header is processed by the server.\n\n"
                    "**How to fix:** Disable method override middleware in production if not explicitly needed. "
                    "In Express: remove `methodOverride()` middleware. "
                    "Ensure WAF and auth middleware check the actual HTTP method, not override headers.\n\n"
                    "**Verify the fix:** Re-run http_method_tampering scanner."
                ),
                category=self.category, page=url,
            ))
            break  # one override finding per endpoint


def _discover_get_endpoints(network: Any, target: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for req in network.get_requests():
        if req.method != "GET":
            continue
        if not _is_api_endpoint(req.url, target):
            continue
        parsed = urlparse(req.url)
        key = f"{parsed.netloc}{parsed.path}"
        if key not in seen:
            seen.add(key)
            result.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
    return result


def _fetch(url: str, method: str, timeout: int = 5) -> tuple[int | None, str]:
    ctx = ssl._create_unverified_context()
    try:
        req = urllib.request.Request(
            url, method=method,
            headers={"User-Agent": "vibe-iterator/method-check"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(2000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def _fetch_with_override(url: str, override_header: str, method: str, timeout: int = 5) -> tuple[int | None, str]:
    ctx = ssl._create_unverified_context()
    try:
        req = urllib.request.Request(
            url, data=b"",
            method="POST",
            headers={
                override_header: method,
                "Content-Type": "application/json",
                "User-Agent": "vibe-iterator/method-override-check",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(2000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_scanners/test_http_method_tampering.py -v
```
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add vibe_iterator/scanners/http_method_tampering.py tests/test_scanners/test_http_method_tampering.py
git commit -m "feat: add http_method_tampering scanner — DELETE acceptance and X-HTTP-Method-Override bypass"
```

---

## Task 6: Register new scanners + update docs

**Files:**
- Modify: `vibe_iterator/engine/runner.py:94-111`
- Modify: `docs/SCANNERS.md`

- [ ] **Step 1: Add entries to `_SCANNER_MODULE_MAP` in runner.py**

In `vibe_iterator/engine/runner.py`, find the `_SCANNER_MODULE_MAP` dict (lines 94-111) and add 4 entries after the `api_exposure` line:

```python
_SCANNER_MODULE_MAP: dict[str, str] = {
    "data_leakage":           "vibe_iterator.scanners.data_leakage",
    "rls_bypass":             "vibe_iterator.scanners.rls_bypass",
    "tier_escalation":        "vibe_iterator.scanners.tier_escalation",
    "bucket_limits":          "vibe_iterator.scanners.bucket_limits",
    "auth_check":             "vibe_iterator.scanners.auth_check",
    "client_tampering":       "vibe_iterator.scanners.client_tampering",
    "sql_injection":          "vibe_iterator.scanners.sql_injection",
    "cors_check":             "vibe_iterator.scanners.cors_check",
    "xss_check":              "vibe_iterator.scanners.xss_check",
    "api_exposure":           "vibe_iterator.scanners.api_exposure",
    # --- Phase 7A: new security scanners ---
    "mass_assignment":        "vibe_iterator.scanners.mass_assignment",
    "info_disclosure":        "vibe_iterator.scanners.info_disclosure",
    "idor_check":             "vibe_iterator.scanners.idor_check",
    "http_method_tampering":  "vibe_iterator.scanners.http_method_tampering",
    # --- Firebase ---
    "firebase_firestore":     "vibe_iterator.scanners.firebase_firestore",
    "firebase_rtdb":          "vibe_iterator.scanners.firebase_rtdb",
    "firebase_storage":       "vibe_iterator.scanners.firebase_storage",
    "firebase_auth":          "vibe_iterator.scanners.firebase_auth",
    "firebase_functions":     "vibe_iterator.scanners.firebase_functions",
}
```

- [ ] **Step 2: Add registry rows to docs/SCANNERS.md**

In `docs/SCANNERS.md`, append 4 rows to the Scanner Registry table:

```markdown
| `mass_assignment` | Access Control | pre-deploy, post-deploy | `['any']` | `False` | 7a |
| `info_disclosure` | Misconfiguration | pre-deploy, post-deploy | `['any']` | `False` | 7a |
| `idor_check` | Access Control | pre-deploy, post-deploy | `['any']` | `False` | 7a |
| `http_method_tampering` | Misconfiguration | pre-deploy, post-deploy | `['any']` | `False` | 7a |
```

- [ ] **Step 3: Verify runner can load all new scanners**

```bash
python -c "
from vibe_iterator.engine.runner import _load_scanner
for name in ['mass_assignment', 'info_disclosure', 'idor_check', 'http_method_tampering']:
    s = _load_scanner(name)
    print(f'OK: {name} -> {s.name}')
"
```
Expected output:
```
OK: mass_assignment -> mass_assignment
OK: info_disclosure -> info_disclosure
OK: idor_check -> idor_check
OK: http_method_tampering -> http_method_tampering
```

- [ ] **Step 4: Commit**

```bash
git add vibe_iterator/engine/runner.py docs/SCANNERS.md
git commit -m "feat: register mass_assignment, info_disclosure, idor_check, http_method_tampering in engine"
```

---

## Task 7: Full suite verification

- [ ] **Step 1: Run the full test suite**

```bash
python -m pytest tests/ -q --no-header
```
Expected: All tests pass (no new failures). Previous count was 372 + 1 skipped — new count should be ~395+ passed.

- [ ] **Step 2: Run ruff lint**

```bash
python -m ruff check vibe_iterator/scanners/mass_assignment.py vibe_iterator/scanners/info_disclosure.py vibe_iterator/scanners/idor_check.py vibe_iterator/scanners/http_method_tampering.py
```
Expected: No output (no errors).

- [ ] **Step 3: Verify coverage hasn't dropped below 70%**

```bash
python -m pytest tests/ --cov=vibe_iterator --cov-report=term-missing -q --no-header 2>&1 | tail -3
```
Expected: TOTAL coverage ≥ 70%.

- [ ] **Step 4: Final commit with summary**

```bash
git add -u
git commit -m "test: Phase 7A full suite verification — 4 new scanners, all tests passing"
```

---

## Self-Review

**Spec coverage check:**
- Mass assignment (OWASP API3) → Task 2 ✓
- Info disclosure (debug endpoints, swagger, secrets, stack traces) → Task 3 ✓
- IDOR for generic REST APIs (OWASP API1) → Task 4 ✓
- HTTP method tampering + override → Task 5 ✓
- Engine registration → Task 6 ✓
- Fixture extended with all needed endpoints → Task 1 ✓

**Placeholder scan:** No TBD, no placeholder code. All implementation steps contain complete code.

**Type consistency:**
- All scanners use `self.new_finding(scanner=self.name, severity=Severity.X, ...)` ✓
- Evidence dict always includes `payload_type`, `payload_used`, `injection_point`, `network_events` ✓
- All helpers `_make_request`, `_fetch` follow the `(str, int|None, float)` or `(int|None, str)` tuple return pattern consistent with existing scanners ✓
