# ADDING_SCANNERS.md — Contributor Guide: Writing a New Scanner

This guide walks you through adding a new scanner to Vibe Iterator from scratch. By the end you'll have a working scanner that shows up in the dashboard, emits findings, and has passing tests.

---

## Overview

Every scanner is a Python module in `vibe_iterator/scanners/`. It exports a single class named `Scanner` that extends `BaseScanner`. The engine discovers scanners by name and calls `scanner.run(session, listeners, config)`.

Scanners are **synchronous** — the engine runs them in a thread via `asyncio.to_thread()` so the WebSocket stays alive during scanning. Never `await` inside a scanner.

---

## Step 1 — Create the scanner module

```bash
touch vibe_iterator/scanners/my_scanner.py
```

Start with this template:

```python
"""my_scanner — short description of what it checks."""

from __future__ import annotations

from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity


class Scanner(BaseScanner):
    name = "my_scanner"
    category = "My Category"           # Shown in dashboard and report
    stages = ["pre-deploy"]            # Which stages include this scanner
    requires_stack = ["any"]           # ["supabase"] to restrict to Supabase apps
    requires_second_account = False    # True if cross-user testing needed

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"

        # Your scanning logic here
        # session       — Selenium BrowserSession (may be None in passive tests)
        # listeners     — dict with "network", "console", "storage" listeners
        # config        — Config dataclass (target, pages, stack, credentials)

        return findings
```

---

## Step 2 — Implement `run()`

### Access captured network traffic

```python
network = listeners["network"]
for req in network.get_requests():
    # req.url, req.method, req.headers, req.response_headers, req.status_code
    # req.request_body, req.response_body
    pass
```

### Access console output

```python
console = listeners["console"]
for entry in console.get_entries():
    # entry.level ("log"|"warn"|"error"), entry.text, entry.url
    pass
```

### Access storage (localStorage / sessionStorage / cookies)

```python
storage = listeners["storage"]
snapshot = storage.get_latest()
# snapshot.local_storage  — dict
# snapshot.session_storage — dict
# snapshot.cookies        — list of dicts
```

### Execute JavaScript in the browser

```python
if session is not None:
    result = session.evaluate("document.title")
```

### Make direct HTTP requests (no browser)

For scanners that test endpoints outside the browser (CORS, API headers):

```python
import ssl
import urllib.request

ctx = ssl._create_unverified_context()
req = urllib.request.Request(url, headers={"Origin": "https://evil.com"})
with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
    headers = {k.lower(): v for k, v in resp.headers.items()}
```

---

## Step 3 — Create Findings

Use `self.new_finding(...)` and `self.build_llm_prompt(...)` from `BaseScanner`:

```python
desc = (
    "The endpoint returns sensitive data without authentication. "
    "An attacker can access this endpoint without logging in."
)

findings.append(self.new_finding(
    scanner=self.name,
    severity=Severity.HIGH,
    title="Unauthenticated access to sensitive endpoint",
    description=desc,
    evidence={
        "endpoint": req.url,
        "test_performed": "replay_without_auth",
        "request": {"method": req.method, "url": req.url},
        "response": {"status": 200, "body_excerpt": "(data returned)"},
        "expected_response": "401 Unauthorized",
        "actual_response": "200 OK",
    },
    llm_prompt=self.build_llm_prompt(
        title="Unauthenticated access to sensitive endpoint",
        severity=Severity.HIGH,
        scanner=self.name,
        page=req.url,
        category=self.category,
        description=desc,
        evidence_summary=f"Endpoint: {req.url}\nExpected: 401\nActual: 200",
        stack=stack,
    ),
    remediation=(
        "**What to fix:** This endpoint does not require authentication.\n\n"
        "**How to fix:** Add authentication middleware that checks for a valid session "
        "before returning data. For Supabase/Next.js: check `session` server-side. "
        "For Express: add a `requireAuth` middleware.\n\n"
        "**Verify the fix:** Re-run the scanner — the endpoint should return 401."
    ),
    category=self.category,
    page=req.url,
))
```

### Severity guide

| Severity | When to use |
|----------|-------------|
| `CRITICAL` | Direct account takeover, mass data exposure, RCE |
| `HIGH` | Authentication bypass, unauthenticated data access |
| `MEDIUM` | Missing security controls, weak configuration |
| `LOW` | Defense-in-depth missing, best practice violation |
| `INFO` | Informational — no direct impact |

### Deduplication with fingerprints

If your scanner checks the same issue type across many URLs, deduplicate to avoid report noise:

```python
seen_fps: set[str] = set()

for url in endpoints:
    fp = self.make_fingerprint(self.name, "Issue title", url)
    if fp in seen_fps:
        continue
    seen_fps.add(fp)
    # emit finding
```

`make_fingerprint` produces a stable `sha256(scanner+title+page)[:16]` hash used for cross-scan comparison in the dashboard's Compare feature.

---

## Step 4 — Register the scanner

**4a. Add to `_SCANNER_MODULE_MAP` in `vibe_iterator/engine/runner.py`:**

```python
_SCANNER_MODULE_MAP: dict[str, str] = {
    # ... existing scanners ...
    "my_scanner": "vibe_iterator.scanners.my_scanner",
}
```

**4b. Add to `_DEFAULT_STAGES` in `vibe_iterator/config.py`:**

```python
_DEFAULT_STAGES: dict[str, list[str]] = {
    "dev": [...],
    "pre-deploy": [..., "my_scanner"],
    "post-deploy": [...],
    "all": [..., "my_scanner"],
}
```

Also add `"my_scanner"` to `_VALID_SCANNER_NAMES` (derived from `_DEFAULT_STAGES["all"]` automatically).

**4c. Add metadata in `vibe_iterator/server/routes.py`:**

```python
_SCANNER_META: dict[str, dict] = {
    # ... existing scanners ...
    "my_scanner": {
        "requires_stack": ["any"],
        "requires_second_account": False,
        "category": "My Category",
        "est_seconds": 20,
    },
}
```

---

## Step 5 — Write tests

Create `tests/test_scanners/test_my_scanner.py`. Tests should:

- Mock `listeners["network"].get_requests()` with controlled requests
- Mock any direct HTTP calls with `unittest.mock.patch`
- Assert finding count, severity, title for each scenario
- Assert no findings for clean inputs

```python
from unittest.mock import MagicMock, patch
from vibe_iterator.scanners.my_scanner import Scanner
from vibe_iterator.scanners.base import Severity

def _make_config(target="https://example.com"):
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "supabase"
    return cfg

def _run(requests, fetch_result=None):
    scanner = Scanner()
    net = MagicMock()
    net.get_requests.return_value = requests
    # patch any HTTP calls your scanner makes:
    with patch("vibe_iterator.scanners.my_scanner._my_http_func", return_value=fetch_result):
        return scanner.run(session=None, listeners={"network": net}, config=_make_config())

def test_my_finding_detected():
    findings = _run([...], fetch_result=...)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH

def test_clean_input_no_findings():
    findings = _run([...], fetch_result=...)
    assert findings == []
```

Run with:

```bash
pytest tests/test_scanners/test_my_scanner.py -v
```

---

## Step 6 — Test the full integration

```bash
# Verify it shows up in config endpoint
vibe-iterator &
curl http://localhost:3001/api/config | python -m json.tool | grep my_scanner
```

---

## Checklist

- [ ] `vibe_iterator/scanners/my_scanner.py` — `Scanner` class with correct `name`, `category`, `stages`, `requires_stack`
- [ ] `run()` returns `list[Finding]` — never raises, never modifies persistent state without restoring it
- [ ] Registered in `runner.py` `_SCANNER_MODULE_MAP`
- [ ] Added to relevant stages in `config.py` `_DEFAULT_STAGES`
- [ ] Metadata in `routes.py` `_SCANNER_META`
- [ ] Tests pass: clean input → 0 findings, vulnerable input → correct findings + severity
- [ ] If scanner touches localStorage/cookies: state is restored in `try/finally`

---

## Tips

- **Keep it passive when possible.** Read network traffic rather than re-sending requests. Active tests (replaying requests, injecting payloads) should be clearly scoped and bounded.
- **Limit active requests.** Use `_MAX_ENDPOINTS = 12` or similar constants to cap how many URLs are probed.
- **Log, don't crash.** Wrap all HTTP calls in `try/except`. A scanner that raises propagates to `scanner_exception` error handling in the engine — the scan continues but the scanner result is marked as `error`.
- **Use `ssl._create_unverified_context()`** for direct HTTP requests so local dev apps with self-signed certs work.
- **Test against `session=None`** — passive scanners should work without a browser session. Active scanners should guard with `if session is None: return []`.
