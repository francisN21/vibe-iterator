# Rate Limit Check Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a standalone `rate_limit_check` scanner that detects missing rate limiting (MEDIUM), account lockout as a DoS vector (LOW), and missing `Retry-After` headers (INFO) across all auth-sensitive endpoints, with opt-in deep scan mode.

**Architecture:** Two-pass probe per endpoint — Phase 1 sends a 10-attempt burst and classifies the response pattern; Phase 2 verifies `Retry-After` when a 429 is found. A module-level `_probe_endpoint()` helper is shared between the standard endpoint list and deep scan mode. All three finding types use `BaseScanner.new_finding()` and `BaseScanner.build_llm_prompt()` following the existing scanner pattern.

**Tech Stack:** Python stdlib `urllib.request`, existing `BaseScanner`/`Finding`/`Severity` from `vibe_iterator.scanners.base`, `unittest.mock.patch` for unit tests, `VulnerableApp` fixture for proof tests.

---

## File Map

| File | Action | What changes |
|------|--------|--------------|
| `tests/fixtures/vulnerable_app/app.py` | Modify | Module-level attempt counter + 4 new POST endpoints |
| `vibe_iterator/config.py` | Modify | `rate_limit_deep_scan` field + `rate_limit_check` in stage lists |
| `vibe_iterator/scanners/rate_limit_check.py` | Create | Full scanner — probe logic, all three findings |
| `vibe_iterator/server/routes.py` | Modify | `rate_limit_check` in `_SCANNER_META` |
| `tests/test_scanners/test_rate_limit_check.py` | Create | 10 unit tests, all HTTP mocked at function level |
| `tests/test_scanners/test_rate_limit_check_proof.py` | Create | 4 proof tests against VulnerableApp |

---

### Task 1: Fixture App — Add Rate Limit Endpoints

**Files:**
- Modify: `tests/fixtures/vulnerable_app/app.py`

The fixture needs a module-level attempt counter (reset on each `VulnerableApp.start()`) and four new POST endpoints. The counter is module-level because `VulnerableHandler` is instantiated fresh per request.

- [ ] **Step 1: Add module-level attempt counter and reset**

At the top of `tests/fixtures/vulnerable_app/app.py`, after the imports, add:

```python
# Module-level attempt counter — reset by VulnerableApp.start()
_attempt_counts: dict[str, int] = {}
```

In `VulnerableApp.start()`, add one line after `self.base_url = ...`:

```python
def start(self) -> str:
    _attempt_counts.clear()          # <-- add this line
    self._server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
    port = self._server.server_address[1]
    self.base_url = f"http://127.0.0.1:{port}"
    self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
    self._thread.start()
    return self.base_url
```

- [ ] **Step 2: Add the four new POST endpoints inside `do_POST`**

Replace the existing `do_POST` method body's `elif path == "/api/auth/login":` block and the final `else:` with the full updated method below. The existing `/api/auth/login` handler at line 119 stays unchanged (still returns 401 with no rate limiting — this is what triggers Finding A in proof tests):

```python
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
```

- [ ] **Step 3: Verify fixture manually**

```bash
python -c "
from tests.fixtures.vulnerable_app.app import VulnerableApp
import urllib.request, json
with VulnerableApp() as app:
    # signup → 200
    req = urllib.request.Request(app.base_url + '/api/auth/signup',
          data=b'{\"email\":\"x\",\"password\":\"y\"}', method='POST',
          headers={'Content-Type':'application/json'})
    try:
        r = urllib.request.urlopen(req, timeout=2)
        print('signup:', r.status)
    except Exception as e:
        print('signup:', e.code)
    # forgot-password attempt 5 → 403
    for i in range(5):
        req2 = urllib.request.Request(app.base_url + '/api/auth/forgot-password',
               data=b'{\"email\":\"x\",\"password\":\"y\"}', method='POST',
               headers={'Content-Type':'application/json'})
        try:
            r2 = urllib.request.urlopen(req2, timeout=2)
            print(f'forgot-pw attempt {i+1}:', r2.status)
        except Exception as e2:
            print(f'forgot-pw attempt {i+1}:', e2.code)
"
```

Expected output:
```
signup: 200
forgot-pw attempt 1: 401
forgot-pw attempt 2: 401
forgot-pw attempt 3: 401
forgot-pw attempt 4: 401
forgot-pw attempt 5: 403
```

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/vulnerable_app/app.py
git commit -m "test(fixture): add rate-limit endpoints for rate_limit_check proof tests"
```

---

### Task 2: Config — Add `rate_limit_deep_scan` and Stage Membership

**Files:**
- Modify: `vibe_iterator/config.py`

- [ ] **Step 1: Write the failing test**

In `tests/test_config.py` (existing file), locate the test helpers and add after the last test:

```python
def test_rate_limit_deep_scan_defaults_false(tmp_path):
    """rate_limit_deep_scan defaults to False when not in YAML."""
    env = tmp_path / ".env"
    env.write_text("VIBE_ITERATOR_TEST_EMAIL=t@e.com\nVIBE_ITERATOR_TEST_PASSWORD=pw\nVIBE_ITERATOR_TARGET=http://localhost:3000\n")
    cfg = load_config(env_path=str(env))
    assert cfg.rate_limit_deep_scan is False


def test_rate_limit_deep_scan_loaded_from_yaml(tmp_path):
    """rate_limit_deep_scan is read from YAML."""
    env = tmp_path / ".env"
    env.write_text("VIBE_ITERATOR_TEST_EMAIL=t@e.com\nVIBE_ITERATOR_TEST_PASSWORD=pw\nVIBE_ITERATOR_TARGET=http://localhost:3000\n")
    yaml_file = tmp_path / "vibe-iterator.config.yaml"
    yaml_file.write_text("rate_limit_deep_scan: true\n")
    cfg = load_config(env_path=str(env), yaml_path=str(yaml_file))
    assert cfg.rate_limit_deep_scan is True


def test_rate_limit_check_in_pre_deploy_stage(tmp_path):
    """rate_limit_check scanner appears in pre-deploy stage."""
    env = tmp_path / ".env"
    env.write_text("VIBE_ITERATOR_TEST_EMAIL=t@e.com\nVIBE_ITERATOR_TEST_PASSWORD=pw\nVIBE_ITERATOR_TARGET=http://localhost:3000\n")
    cfg = load_config(env_path=str(env))
    assert "rate_limit_check" in cfg.scanners_for_stage("pre-deploy")


def test_rate_limit_check_not_in_dev_stage(tmp_path):
    """rate_limit_check scanner is NOT in the dev stage (too slow)."""
    env = tmp_path / ".env"
    env.write_text("VIBE_ITERATOR_TEST_EMAIL=t@e.com\nVIBE_ITERATOR_TEST_PASSWORD=pw\nVIBE_ITERATOR_TARGET=http://localhost:3000\n")
    cfg = load_config(env_path=str(env))
    assert "rate_limit_check" not in cfg.scanners_for_stage("dev")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_config.py::test_rate_limit_deep_scan_defaults_false tests/test_config.py::test_rate_limit_check_in_pre_deploy_stage -v
```

Expected: `FAILED` — `Config` has no `rate_limit_deep_scan` attribute.

- [ ] **Step 3: Add `rate_limit_deep_scan` to `Config` dataclass and YAML loading**

In `vibe_iterator/config.py`:

**a) Add the field to `Config` dataclass** (after `spider_max_depth` at line 78):

```python
    # Spider (endpoint discovery)
    spider_max_pages: int = 30
    spider_max_depth: int = 3

    # Rate limit scanner
    rate_limit_deep_scan: bool = False
```

**b) Add `rate_limit_check` to `_DEFAULT_STAGES`** (replace the entire dict at lines 13-29):

```python
_DEFAULT_STAGES: dict[str, list[str]] = {
    "dev": ["data_leakage", "auth_check", "client_tampering"],
    "pre-deploy": [
        "data_leakage", "auth_check", "client_tampering",
        "rls_bypass", "tier_escalation", "bucket_limits",
        "sql_injection", "xss_check", "api_exposure",
        "rate_limit_check",
    ],
    "post-deploy": [
        "cors_check", "data_leakage", "auth_check",
        "api_exposure", "bucket_limits", "sql_injection",
        "rate_limit_check",
    ],
    "all": [
        "data_leakage", "rls_bypass", "tier_escalation", "bucket_limits",
        "auth_check", "client_tampering", "sql_injection",
        "cors_check", "xss_check", "api_exposure",
        "rate_limit_check",
    ],
}
```

**c) Load `rate_limit_deep_scan` from YAML** (add after the spider block, before the pages block — around line 205):

```python
    # ------------------------------------------------------------------ #
    # Rate limit scanner                                                   #
    # ------------------------------------------------------------------ #
    rate_limit_deep_scan: bool = bool(yaml_data.get("rate_limit_deep_scan", False))
```

**d) Pass it to `Config()`** (at the end of `load_config`, add to the constructor call):

```python
    return Config(
        target=target,
        test_email=test_email,
        test_password=test_password,
        test_email_2=test_email_2,
        test_password_2=test_password_2,
        supabase_url=supabase_url,
        supabase_anon_key=supabase_anon_key,
        pages=pages,
        stages=stages,
        stack=stack,
        port=port,
        scanner_timeout_seconds=scanner_timeout_seconds,
        spider_max_pages=spider_max_pages,
        spider_max_depth=spider_max_depth,
        rate_limit_deep_scan=rate_limit_deep_scan,
        results_dir=results_dir,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_config.py::test_rate_limit_deep_scan_defaults_false tests/test_config.py::test_rate_limit_deep_scan_loaded_from_yaml tests/test_config.py::test_rate_limit_check_in_pre_deploy_stage tests/test_config.py::test_rate_limit_check_not_in_dev_stage -v
```

Expected: `4 passed`

- [ ] **Step 5: Run full config test suite to check for regressions**

```bash
python -m pytest tests/test_config.py -v
```

Expected: all existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add vibe_iterator/config.py tests/test_config.py
git commit -m "feat(config): add rate_limit_deep_scan field and rate_limit_check to stage lists"
```

---

### Task 3: Scanner — Scaffold, Phase 1 Probe, Finding A

**Files:**
- Create: `vibe_iterator/scanners/rate_limit_check.py`
- Create: `tests/test_scanners/test_rate_limit_check.py`

- [ ] **Step 1: Write the failing tests for Finding A**

Create `tests/test_scanners/test_rate_limit_check.py`:

```python
"""Unit tests for rate_limit_check scanner — all HTTP mocked at function level."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vibe_iterator.scanners.rate_limit_check import Scanner
from vibe_iterator.scanners.base import Severity


def _make_config(deep_scan: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.stack.backend = "custom"
    cfg.rate_limit_deep_scan = deep_scan
    return cfg


def _make_network(post_urls: list[str] | None = None) -> MagicMock:
    net = MagicMock()
    reqs = []
    for url in (post_urls or []):
        r = MagicMock()
        r.method = "POST"
        r.url = url
        reqs.append(r)
    net.get_requests.return_value = reqs
    return net


def _run(
    *,
    active_path: str | None = "/api/auth/login",
    burst_responses: list[tuple] | None = None,
    deep_scan: bool = False,
    network_post_urls: list[str] | None = None,
) -> list:
    """
    active_path: what _find_active_path returns (None = endpoint absent).
    burst_responses: list of (status, headers_dict, body_str) returned by _post_full,
                     one per burst attempt. Repeated as needed up to 10.
    """
    scanner = Scanner()
    config = _make_config(deep_scan=deep_scan)
    network = _make_network(network_post_urls)

    if burst_responses is None:
        burst_responses = [(401, {}, '{"error": "invalid"}')]

    # Cycle responses if fewer than 10 provided
    def _side_effect(url):
        idx = len(call_log)
        call_log.append(url)
        r = burst_responses[min(idx, len(burst_responses) - 1)]
        return r

    call_log: list[str] = []

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value=active_path), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_side_effect):
        return scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )


# ── Finding A ────────────────────────────────────────────────────────────────

def test_no_rate_limit_finding_a_emitted():
    """10 × 401 with no shift → Finding A, MEDIUM."""
    findings = _run(burst_responses=[(401, {}, '{"error": "x"}')
                                     ] * 10)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert "No rate limiting" in f.title
    assert "Login" in f.title


def test_finding_a_evidence_structure():
    """Finding A evidence dict has required keys."""
    findings = _run(burst_responses=[(401, {}, '{}') ] * 10)
    ev = findings[0].evidence
    assert ev["attempts_sent"] == 10
    assert ev["response_codes_seen"] == [401] * 10
    assert "expected_behavior" in ev


def test_all_endpoints_404_no_findings():
    """If all path variants 404, no findings emitted."""
    findings = _run(active_path=None)
    assert findings == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py::test_no_rate_limit_finding_a_emitted -v
```

Expected: `ERROR` — `ModuleNotFoundError: No module named 'vibe_iterator.scanners.rate_limit_check'`

- [ ] **Step 3: Create the scanner file with scaffold + Phase 1 + Finding A**

Create `vibe_iterator/scanners/rate_limit_check.py`:

```python
"""Rate limit check scanner — detects missing rate limiting, lockout DoS, and missing Retry-After."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity

_PROBE_BODY = json.dumps({
    "email": "probe@vibe-iterator-test.invalid",
    "password": "VI_PROBE_xXx",
}).encode()
_REQUEST_TIMEOUT = 3
_BURST_COUNT = 10
_DEEP_SCAN_CAP = 20
_LOCKOUT_BODY_SIGNALS = ("locked", "suspended", "too many attempts", "too many requests")

_AUTH_ENDPOINTS: list[tuple[list[str], str]] = [
    (["/api/auth/login", "/api/login", "/auth/login"], "Login"),
    (["/api/auth/forgot-password", "/api/auth/reset-password", "/api/reset-password"], "Password Reset"),
    (["/api/auth/signup", "/api/auth/register", "/api/register"], "Signup"),
    (["/api/auth/otp", "/api/auth/magic-link"], "OTP / Magic Link"),
    (["/api/auth/verify", "/api/auth/resend"], "Email Verification"),
    (["/auth/v1/token?grant_type=password"], "Supabase Auth"),
]


class Scanner(BaseScanner):
    """Two-pass probe for rate limiting across all auth-sensitive endpoints."""

    name = "rate_limit_check"
    category = "Rate Limiting"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        base = config.target.rstrip("/")
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"

        probed_paths: set[str] = set()
        for path_variants, label in _AUTH_ENDPOINTS:
            path = _find_active_path(base, path_variants)
            if path is None:
                continue
            probed_paths.add(path)
            _probe_endpoint(base, path, label, stack, findings, self)

        if getattr(config, "rate_limit_deep_scan", False):
            network = listeners.get("network")
            if network:
                extra: list[str] = []
                seen_paths: set[str] = set(probed_paths)
                for req in network.get_requests():
                    if req.method != "POST" or not req.url.startswith(base):
                        continue
                    path = req.url[len(base):]
                    if path and path not in seen_paths:
                        seen_paths.add(path)
                        extra.append(path)
                    if len(extra) >= _DEEP_SCAN_CAP:
                        break
                for path in extra:
                    label = path.rstrip("/").split("/")[-1].replace("-", " ").title()
                    _probe_endpoint(base, path, label, stack, findings, self)

        return findings


def _find_active_path(base: str, variants: list[str]) -> str | None:
    """Return first path variant that does not 404/405/501, or None."""
    for path in variants:
        code = _post_once(base + path)
        if code not in (404, 405, 501, None):
            return path
    return None


def _probe_endpoint(
    base: str,
    path: str,
    label: str,
    stack: str,
    findings: list[Finding],
    scanner: BaseScanner,
) -> None:
    """Phase 1 burst + Phase 2 Retry-After check for one endpoint."""
    url = base + path
    codes: list[int] = []
    found_429 = False
    retry_after: str | None = None
    lockout_at: int | None = None
    lockout_code_before: int | None = None
    lockout_code_after: int | None = None
    lockout_body: str = ""

    for i in range(_BURST_COUNT):
        code, headers, body = _post_full(url)
        if code is None:
            break

        if code == 429:
            found_429 = True
            retry_after = headers.get("retry-after") or headers.get("Retry-After")
            break

        body_lower = body.lower()
        if any(sig in body_lower for sig in _LOCKOUT_BODY_SIGNALS):
            lockout_at = i + 1
            lockout_code_before = codes[-1] if codes else code
            lockout_code_after = code
            lockout_body = body[:200]
            break

        if codes and code != codes[0]:
            lockout_at = i + 1
            lockout_code_before = codes[0]
            lockout_code_after = code
            lockout_body = body[:200]
            break

        codes.append(code)

    if found_429:
        if not retry_after:
            findings.append(_finding_c(scanner, url, path, label, stack))
        return

    if lockout_at is not None:
        findings.append(_finding_b(
            scanner, url, path, label, stack,
            lockout_at, lockout_code_before or 0, lockout_code_after or 0, lockout_body,
        ))
        return

    if len(codes) >= _BURST_COUNT:
        findings.append(_finding_a(scanner, url, path, label, stack, codes))


def _post_once(url: str) -> int | None:
    try:
        req = urllib.request.Request(
            url, data=_PROBE_BODY, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _post_full(url: str) -> tuple[int | None, dict, str]:
    try:
        req = urllib.request.Request(
            url, data=_PROBE_BODY, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, headers, body
    except Exception:
        return None, {}, ""


def _finding_a(
    scanner: BaseScanner, url: str, path: str,
    label: str, stack: str, codes: list[int],
) -> Finding:
    desc = (
        f"{label} endpoint has no rate limiting — "
        f"{len(codes)} consecutive attempts all returned {codes[0]} with no 429 response. "
        "An attacker can make unlimited attempts without being slowed down, "
        "enabling automated credential attacks."
    )
    return scanner.new_finding(
        scanner=scanner.name,
        severity=Severity.MEDIUM,
        title=f"No rate limiting on {label} endpoint ({path})",
        description=desc,
        evidence={
            "check_group": "Rate Limiting",
            "check_name": "Burst probe",
            "evidence_type": "request_replay",
            "endpoint": url,
            "label": label,
            "attempts_sent": len(codes),
            "response_codes_seen": codes,
            "expected_behavior": "Endpoint should return 429 by attempt 6 with a Retry-After header",
        },
        llm_prompt=scanner.build_llm_prompt(
            title=f"No rate limiting on {label} endpoint",
            severity=Severity.MEDIUM,
            scanner=scanner.name,
            page=url,
            category=scanner.category,
            description=desc,
            evidence_summary=f"{len(codes)} attempts to {url} — all returned {codes[0]}, no 429.",
            stack=stack,
        ),
        remediation=_REMEDIATION_A.format(label=label),
        category=scanner.category,
        page=url,
    )


def _finding_b(
    scanner: BaseScanner, url: str, path: str, label: str, stack: str,
    lockout_at: int, code_before: int, code_after: int, body_excerpt: str,
) -> Finding:
    desc = (
        f"{label} endpoint locks accounts after {lockout_at} failed attempts "
        f"(response changed from {code_before} to {code_after}). "
        "An attacker can deliberately trigger this to lock out any user whose email they know "
        "— no password needed. The account owner is the victim, not the attacker."
    )
    return scanner.new_finding(
        scanner=scanner.name,
        severity=Severity.LOW,
        title=f"Account lockout on {label} endpoint — DoS risk ({path})",
        description=desc,
        evidence={
            "check_group": "Rate Limiting",
            "check_name": "Lockout detection",
            "evidence_type": "request_replay",
            "endpoint": url,
            "label": label,
            "lockout_detected_at_attempt": lockout_at,
            "code_before": code_before,
            "code_after": code_after,
            "body_excerpt": body_excerpt,
            "expected_behavior": "Endpoint should return 429 + Retry-After, not lock the account",
        },
        llm_prompt=scanner.build_llm_prompt(
            title=f"Account lockout on {label} endpoint — DoS risk",
            severity=Severity.LOW,
            scanner=scanner.name,
            page=url,
            category=scanner.category,
            description=desc,
            evidence_summary=f"Attempt {lockout_at} on {url}: code changed {code_before} → {code_after}.",
            stack=stack,
        ),
        remediation=_REMEDIATION_B.format(label=label),
        category=scanner.category,
        page=url,
    )


def _finding_c(
    scanner: BaseScanner, url: str, path: str, label: str, stack: str,
) -> Finding:
    desc = (
        f"{label} endpoint returns 429 but does not include a Retry-After header. "
        "HTTP clients, mobile apps, and retry libraries use this header to know when to retry. "
        "Without it they either retry immediately (defeating the rate limit) or back off arbitrarily."
    )
    return scanner.new_finding(
        scanner=scanner.name,
        severity=Severity.INFO,
        title=f"429 response missing Retry-After header on {label} endpoint ({path})",
        description=desc,
        evidence={
            "check_group": "Rate Limiting",
            "check_name": "Retry-After header",
            "evidence_type": "response_analysis",
            "endpoint": url,
            "label": label,
            "response_code": 429,
            "expected_behavior": "429 response must include Retry-After: <seconds>",
        },
        llm_prompt=scanner.build_llm_prompt(
            title=f"429 response missing Retry-After header on {label} endpoint",
            severity=Severity.INFO,
            scanner=scanner.name,
            page=url,
            category=scanner.category,
            description=desc,
            evidence_summary=f"429 received on {url} but no Retry-After header in response.",
            stack=stack,
        ),
        remediation=_REMEDIATION_C,
        category=scanner.category,
        page=url,
    )


_REMEDIATION_A = (
    "**What to fix:** {label} endpoint has no rate limiting — an attacker can "
    "make unlimited attempts without being slowed down.\n\n"
    "**How to fix (Next.js + Upstash):**\n"
    "Install: npm install @upstash/ratelimit @upstash/redis\n\n"
    "```js\n"
    'import { Ratelimit } from "@upstash/ratelimit";\n'
    'import { Redis } from "@upstash/redis";\n\n'
    "const ratelimit = new Ratelimit({\n"
    '  redis: Redis.fromEnv(),\n'
    '  limiter: Ratelimit.slidingWindow(10, "60 s"),\n'
    "  analytics: true,\n"
    "});\n\n"
    "export async function POST(req) {\n"
    '  const ip = req.headers.get("x-forwarded-for") ?? "anonymous";\n'
    "  const email = (await req.json()).email ?? \"\";\n"
    "  const key = `rl:login:${ip}:${email}`;\n"
    "  const { success, reset } = await ratelimit.limit(key);\n"
    "  if (!success) {\n"
    "    return Response.json(\n"
    '      { error: "Too many attempts. Try again later." },\n'
    "      { status: 429, headers: { \"Retry-After\": String(Math.ceil((reset - Date.now()) / 1000)) } }\n"
    "    );\n"
    "  }\n"
    "  // ... rest of handler\n"
    "}\n"
    "```\n\n"
    "**Alternative (rate-limiter-flexible, no external service):**\n"
    "Install: npm install rate-limiter-flexible\n\n"
    "```js\n"
    'import { RateLimiterMemory } from "rate-limiter-flexible";\n'
    "const limiter = new RateLimiterMemory({ points: 10, duration: 60 });\n\n"
    "const key = `${ip}_${email}`;\n"
    "try { await limiter.consume(key); }\n"
    "catch { return Response.json({ error: \"Too many attempts.\" },\n"
    '        { status: 429, headers: { "Retry-After": "60" } }); }\n'
    "```\n\n"
    "**For Supabase:** Enable Auth → Rate Limits in your Supabase project "
    "dashboard. Set \"Email logins per hour\" to a value ≤ 10.\n\n"
    "**Verify the fix:** Re-run rate_limit_check — the 6th attempt must return 429."
)

_REMEDIATION_B = (
    "**What to fix:** {label} endpoint locks accounts after failed attempts. "
    "A locked account requires manual recovery (e.g. opening an IT ticket or "
    "waiting for a timed reset). An attacker can deliberately trigger this to "
    "lock out any user whose email they know — no password needed.\n\n"
    "**How to fix:** Replace lockout with 429 + Retry-After progressive throttling:\n"
    "- Attempts 1–5:  allow (normal 401)\n"
    "- Attempts 6–20: return 429, Retry-After: 60\n"
    "- Attempts 21–50: return 429, Retry-After: 300\n"
    "- Attempts 51+:  return 429, Retry-After: 3600\n\n"
    "Key on (IP + target email) together — not email alone (locks out the real "
    "user) and not IP alone (trivially bypassed with proxies).\n\n"
    "Never lock the account. The account owner is the victim of lockout, not the attacker.\n\n"
    "**Verify the fix:** Re-run rate_limit_check — lockout finding must be gone, "
    "and a 429 must appear by attempt 6."
)

_REMEDIATION_C = (
    "**What to fix:** The 429 response does not include a Retry-After header. "
    "HTTP clients, mobile apps, and retry libraries use this header to know "
    "when to try again. Without it they either hammer immediately (defeating "
    "the rate limit) or back off arbitrarily.\n\n"
    "**How to fix:** Add the header to every 429 response:\n"
    "  Retry-After: 60   (seconds until the window resets)\n\n"
    "In Next.js:\n"
    '  return Response.json({ error: "Too many attempts." },\n'
    '    { status: 429, headers: { "Retry-After": "60" } });\n\n'
    "**Verify the fix:** Re-run rate_limit_check — INFO finding must be gone."
)
```

- [ ] **Step 4: Run Finding A tests to verify they pass**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py::test_no_rate_limit_finding_a_emitted tests/test_scanners/test_rate_limit_check.py::test_finding_a_evidence_structure tests/test_scanners/test_rate_limit_check.py::test_all_endpoints_404_no_findings -v
```

Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add vibe_iterator/scanners/rate_limit_check.py tests/test_scanners/test_rate_limit_check.py
git commit -m "feat(scanner): rate_limit_check scaffold + Phase 1 probe + Finding A"
```

---

### Task 4: Finding B — Lockout Detection

**Files:**
- Modify: `tests/test_scanners/test_rate_limit_check.py`
- No scanner changes needed — `_finding_b` is already in place from Task 3

- [ ] **Step 1: Add Finding B tests to the test file**

Append to `tests/test_scanners/test_rate_limit_check.py`:

```python
# ── Finding B ────────────────────────────────────────────────────────────────

def test_lockout_detected_code_shift():
    """Attempts 1-4 return 401, attempt 5 returns 403 → Finding B, LOW."""
    responses = [(401, {}, '{"error": "invalid"}')
                 ] * 4 + [(403, {}, '{"error": "forbidden"}')]
    findings = _run(burst_responses=responses)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.LOW
    assert "lockout" in f.title.lower() or "Lockout" in f.title
    assert "DoS" in f.title


def test_lockout_detected_body_signal():
    """All 401 but body contains 'locked' at attempt 6 → Finding B."""
    responses = [(401, {}, '{"error": "invalid"}')
                 ] * 5 + [(401, {}, '{"error": "account locked"}')]
    findings = _run(burst_responses=responses)
    b_findings = [f for f in findings if f.severity == Severity.LOW]
    assert len(b_findings) == 1
    assert b_findings[0].evidence["lockout_detected_at_attempt"] == 6


def test_lockout_evidence_structure():
    """Finding B evidence has all required keys."""
    responses = [(401, {}, '{"error": "x"}') ] * 4 + [(403, {}, '{"error": "locked"}')]
    findings = _run(burst_responses=responses)
    ev = findings[0].evidence
    assert "lockout_detected_at_attempt" in ev
    assert "code_before" in ev
    assert "code_after" in ev
    assert ev["code_before"] == 401
    assert ev["code_after"] == 403
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py::test_lockout_detected_code_shift tests/test_scanners/test_rate_limit_check.py::test_lockout_detected_body_signal tests/test_scanners/test_rate_limit_check.py::test_lockout_evidence_structure -v
```

Expected: `3 passed`

- [ ] **Step 3: Commit**

```bash
git add tests/test_scanners/test_rate_limit_check.py
git commit -m "test(rate_limit_check): Finding B lockout detection tests"
```

---

### Task 5: Finding C — Retry-After Header (Phase 2)

**Files:**
- Modify: `tests/test_scanners/test_rate_limit_check.py`
- No scanner changes needed — `_finding_c` and Phase 2 logic are already in place from Task 3

- [ ] **Step 1: Add Finding C tests**

Append to `tests/test_scanners/test_rate_limit_check.py`:

```python
# ── Finding C ────────────────────────────────────────────────────────────────

def test_rate_limited_with_retry_after_no_finding():
    """429 with Retry-After present → no findings at all."""
    responses = [(401, {}, '{"error": "x"}')
                 ] * 5 + [(429, {"retry-after": "60"}, '{"error": "rate limited"}')]
    findings = _run(burst_responses=responses)
    assert findings == []


def test_rate_limited_missing_retry_after_finding_c():
    """429 present but no Retry-After header → Finding C, INFO."""
    responses = [(401, {}, '{"error": "x"}')
                 ] * 5 + [(429, {}, '{"error": "rate limited"}')]
    findings = _run(burst_responses=responses)
    c_findings = [f for f in findings if "Retry-After" in f.title or "retry" in f.title.lower()]
    assert len(c_findings) == 1
    assert c_findings[0].severity == Severity.INFO


def test_finding_c_evidence_structure():
    """Finding C evidence has response_code and endpoint keys."""
    responses = [(401, {}, '{}') ] * 5 + [(429, {}, '{}')]
    findings = _run(burst_responses=responses)
    ev = findings[0].evidence
    assert ev["response_code"] == 429
    assert "endpoint" in ev
    assert "expected_behavior" in ev
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py::test_rate_limited_with_retry_after_no_finding tests/test_scanners/test_rate_limit_check.py::test_rate_limited_missing_retry_after_finding_c tests/test_scanners/test_rate_limit_check.py::test_finding_c_evidence_structure -v
```

Expected: `3 passed`

- [ ] **Step 3: Run all unit tests so far**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py -v
```

Expected: `9 passed`

- [ ] **Step 4: Commit**

```bash
git add tests/test_scanners/test_rate_limit_check.py
git commit -m "test(rate_limit_check): Finding C Retry-After header tests"
```

---

### Task 6: Deep Scan Mode Tests

**Files:**
- Modify: `tests/test_scanners/test_rate_limit_check.py`

- [ ] **Step 1: Add deep scan tests**

Append to `tests/test_scanners/test_rate_limit_check.py`:

```python
# ── Deep scan ─────────────────────────────────────────────────────────────────

def test_deep_scan_probes_network_endpoints():
    """With deep_scan=True, POST endpoints from network listener are probed."""
    post_urls = [
        "http://localhost:3000/api/custom/action",
        "http://localhost:3000/api/other/submit",
    ]
    # active_path=None skips standard endpoints; deep scan picks up network ones
    probed: list[str] = []

    def _full_side(url):
        probed.append(url)
        return (401, {}, '{"error": "x"}')

    scanner = Scanner()
    config = _make_config(deep_scan=True)
    network = _make_network(post_urls)

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value=None), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        findings = scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    # Each deep-scan endpoint probed (up to 10 burst attempts each)
    assert any("/api/custom/action" in p for p in probed)
    assert any("/api/other/submit" in p for p in probed)
    # Both unprotected → 2 findings
    assert len(findings) == 2


def test_deep_scan_skips_already_covered_endpoints():
    """Deep scan does not double-probe an endpoint from the standard list."""
    post_urls = [
        "http://localhost:3000/api/auth/login",  # overlaps standard list
        "http://localhost:3000/api/custom/new",
    ]
    probed: list[str] = []

    def _full_side(url):
        probed.append(url)
        return (401, {}, '{}')

    scanner = Scanner()
    config = _make_config(deep_scan=True)
    network = _make_network(post_urls)

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value="/api/auth/login"), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    login_probes = [p for p in probed if "/api/auth/login" in p]
    new_probes = [p for p in probed if "/api/custom/new" in p]
    # login probed exactly once (from standard list, 10 burst attempts)
    assert len(login_probes) == 10
    # custom/new also probed
    assert len(new_probes) == 10


def test_deep_scan_caps_at_20_endpoints():
    """Deep scan probes at most 20 additional endpoints beyond the standard list."""
    post_urls = [
        f"http://localhost:3000/api/ep/{i}" for i in range(25)
    ]
    probed_paths: set[str] = set()

    def _full_side(url):
        from urllib.parse import urlparse
        probed_paths.add(urlparse(url).path)
        return (401, {}, '{}')

    scanner = Scanner()
    config = _make_config(deep_scan=True)
    network = _make_network(post_urls)

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value=None), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    assert len(probed_paths) == 20
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py::test_deep_scan_probes_network_endpoints tests/test_scanners/test_rate_limit_check.py::test_deep_scan_skips_already_covered_endpoints tests/test_scanners/test_rate_limit_check.py::test_deep_scan_caps_at_20_endpoints -v
```

Expected: `3 passed`

- [ ] **Step 3: Run full unit test suite**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check.py -v
```

Expected: `12 passed`

- [ ] **Step 4: Commit**

```bash
git add tests/test_scanners/test_rate_limit_check.py
git commit -m "test(rate_limit_check): deep scan mode unit tests"
```

---

### Task 7: Routes Wiring

**Files:**
- Modify: `vibe_iterator/server/routes.py`

- [ ] **Step 1: Add `rate_limit_check` to `_SCANNER_META`**

In `vibe_iterator/server/routes.py`, add to the `_SCANNER_META` dict after the `"api_exposure"` entry (currently the last entry around line 38):

```python
_SCANNER_META: dict[str, dict] = {
    "data_leakage":     {"requires_stack": ["any"],      "requires_second_account": False, "category": "Data Leakage",         "est_seconds": 15},
    "rls_bypass":       {"requires_stack": ["supabase"],  "requires_second_account": True,  "category": "Access Control",       "est_seconds": 30},
    "tier_escalation":  {"requires_stack": ["supabase"],  "requires_second_account": False, "category": "Access Control",       "est_seconds": 20},
    "bucket_limits":    {"requires_stack": ["supabase"],  "requires_second_account": False, "category": "Access Control",       "est_seconds": 25},
    "auth_check":       {"requires_stack": ["any"],       "requires_second_account": True,  "category": "Authentication",       "est_seconds": 60},
    "client_tampering": {"requires_stack": ["any"],       "requires_second_account": False, "category": "Client-Side Tampering","est_seconds": 20},
    "sql_injection":    {"requires_stack": ["any"],       "requires_second_account": False, "category": "Injection",            "est_seconds": 60},
    "cors_check":       {"requires_stack": ["any"],       "requires_second_account": False, "category": "Misconfiguration",     "est_seconds": 15},
    "xss_check":        {"requires_stack": ["any"],       "requires_second_account": False, "category": "Injection",            "est_seconds": 30},
    "api_exposure":     {"requires_stack": ["any"],       "requires_second_account": False, "category": "API Security",         "est_seconds": 20},
    "rate_limit_check": {"requires_stack": ["any"],       "requires_second_account": False, "category": "Rate Limiting",        "est_seconds": 45},
}
```

- [ ] **Step 2: Verify the API config endpoint includes the scanner**

```bash
python -c "
from vibe_iterator.server.routes import _SCANNER_META
assert 'rate_limit_check' in _SCANNER_META
meta = _SCANNER_META['rate_limit_check']
assert meta['category'] == 'Rate Limiting'
assert meta['est_seconds'] == 45
print('OK:', meta)
"
```

Expected: `OK: {'requires_stack': ['any'], 'requires_second_account': False, 'category': 'Rate Limiting', 'est_seconds': 45}`

- [ ] **Step 3: Verify scanner is importable by the engine**

```bash
python -c "
from vibe_iterator.scanners.rate_limit_check import Scanner
s = Scanner()
print('name:', s.name)
print('category:', s.category)
print('stages:', s.stages)
"
```

Expected:
```
name: rate_limit_check
category: Rate Limiting
stages: ['pre-deploy', 'post-deploy']
```

- [ ] **Step 4: Commit**

```bash
git add vibe_iterator/server/routes.py
git commit -m "feat(routes): register rate_limit_check in _SCANNER_META"
```

---

### Task 8: Proof Tests Against VulnerableApp

**Files:**
- Create: `tests/test_scanners/test_rate_limit_check_proof.py`

- [ ] **Step 1: Write proof tests**

Create `tests/test_scanners/test_rate_limit_check_proof.py`:

```python
"""rate_limit_check proof tests — real HTTP against VulnerableApp fixture, no Selenium."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.rate_limit_check import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str, deep_scan: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    cfg.rate_limit_deep_scan = deep_scan
    return cfg


def _run(vuln_app, deep_scan: bool = False, post_urls: list[str] | None = None) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url, deep_scan=deep_scan)
    network = MagicMock()
    reqs = []
    for url in (post_urls or []):
        r = MagicMock()
        r.method = "POST"
        r.url = url
        reqs.append(r)
    network.get_requests.return_value = reqs
    return scanner.run(session=None, listeners={"network": network}, config=config)


def test_proof_no_rate_limit_on_login(vuln_app) -> None:
    """/api/auth/login returns 401 10x with no 429 → Finding A for Login."""
    findings = _run(vuln_app)
    login_findings = [
        f for f in findings
        if "No rate limiting" in f.title and "Login" in f.title
    ]
    assert len(login_findings) >= 1
    assert login_findings[0].severity == Severity.MEDIUM


def test_proof_no_rate_limit_on_signup(vuln_app) -> None:
    """/api/auth/signup returns 200 10x with no 429 → Finding A for Signup."""
    findings = _run(vuln_app)
    signup_findings = [
        f for f in findings
        if "No rate limiting" in f.title and "Signup" in f.title
    ]
    assert len(signup_findings) >= 1
    assert signup_findings[0].severity == Severity.MEDIUM


def test_proof_lockout_on_forgot_password(vuln_app) -> None:
    """/api/auth/forgot-password switches 401→403 at attempt 5 → Finding B."""
    findings = _run(vuln_app)
    lockout_findings = [
        f for f in findings
        if "lockout" in f.title.lower() or "Lockout" in f.title
    ]
    assert len(lockout_findings) >= 1
    f = lockout_findings[0]
    assert f.severity == Severity.LOW
    assert f.evidence["code_before"] == 401
    assert f.evidence["code_after"] == 403


def test_proof_negative_rate_limited_endpoint(vuln_app) -> None:
    """/api/auth/rate-limited-login returns 429+Retry-After → no finding for that endpoint."""
    findings = _run(
        vuln_app,
        deep_scan=True,
        post_urls=[vuln_app.base_url + "/api/auth/rate-limited-login"],
    )
    # This endpoint is properly rate-limited — must not produce Finding A or C
    rl_login_findings = [
        f for f in findings
        if "rate-limited-login" in f.page
    ]
    assert rl_login_findings == []
```

- [ ] **Step 2: Run proof tests**

```bash
python -m pytest tests/test_scanners/test_rate_limit_check_proof.py -v
```

Expected: `4 passed`

- [ ] **Step 3: Commit**

```bash
git add tests/test_scanners/test_rate_limit_check_proof.py
git commit -m "test(rate_limit_check): proof tests against VulnerableApp fixture"
```

---

### Task 9: Full Suite Verification

**Files:** none

- [ ] **Step 1: Run the full test suite**

```bash
python -m pytest --tb=short -q
```

Expected: all tests pass, no regressions.

- [ ] **Step 2: Verify scanner appears in dashboard stage config**

```bash
python -c "
import os; os.environ.setdefault('VIBE_ITERATOR_TEST_EMAIL','t@e.com')
os.environ.setdefault('VIBE_ITERATOR_TEST_PASSWORD','pw')
os.environ.setdefault('VIBE_ITERATOR_TARGET','http://localhost:3000')
from vibe_iterator.config import load_config
cfg = load_config()
print('pre-deploy:', cfg.scanners_for_stage('pre-deploy'))
print('post-deploy:', cfg.scanners_for_stage('post-deploy'))
print('dev:', cfg.scanners_for_stage('dev'))
assert 'rate_limit_check' in cfg.scanners_for_stage('pre-deploy')
assert 'rate_limit_check' in cfg.scanners_for_stage('post-deploy')
assert 'rate_limit_check' not in cfg.scanners_for_stage('dev')
print('OK')
"
```

Expected: `OK` printed, `rate_limit_check` present in pre-deploy and post-deploy, absent from dev.

- [ ] **Step 3: Final commit if any loose files**

```bash
git status
```

If clean: done. If any files modified, stage and commit them.

---

## Self-Review

**Spec coverage:**
- ✅ Standalone scanner (`rate_limit_check.py`) with checkbox toggle via `_SCANNER_META`
- ✅ All auth endpoints: Login, Password Reset, Signup, OTP/Magic Link, Email Verification, Supabase Auth
- ✅ Deep scan mode (`rate_limit_deep_scan` config field, capped at 20)
- ✅ Finding A: Missing rate limiting (MEDIUM)
- ✅ Finding B: Account lockout DoS vector (LOW)
- ✅ Finding C: Missing Retry-After (INFO)
- ✅ Phase 1 burst probe (10 attempts, code-shift detection, body-signal detection)
- ✅ Phase 2 Retry-After verification (only when 429 seen)
- ✅ Fixture additions: `/api/auth/signup`, `/api/auth/forgot-password`, `/api/auth/rate-limited-login`
- ✅ `routes.py` `_SCANNER_META` entry with correct category and est_seconds
- ✅ Config field `rate_limit_deep_scan` with YAML loading
- ✅ Stage membership: pre-deploy ✓, post-deploy ✓, dev ✗
- ✅ 10 unit tests, 4 proof tests
- ✅ Results page: no frontend changes needed — `finding_dict()` is generic, all fields serialize automatically

**Placeholder scan:** No TBD, TODO, or "similar to Task N" patterns.

**Type consistency:** `_finding_a`, `_finding_b`, `_finding_c` all take `(scanner: BaseScanner, url, path, label, stack, ...)` and return `Finding`. `_probe_endpoint` calls all three consistently. `_post_full` returns `tuple[int | None, dict, str]` used uniformly.
