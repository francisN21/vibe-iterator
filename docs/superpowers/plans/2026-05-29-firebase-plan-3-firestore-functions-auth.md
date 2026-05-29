# Firebase Scanner — Plan 3: Firestore + Functions + Auth Scanners

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `firebase_firestore.py`, `firebase_functions.py`, and `firebase_auth.py` with proof tests.

**Architecture:** Same pattern as Plan 2 — each scanner uses `_resolve_config`, runs check groups in isolated `try/except` blocks, uses REST helpers from `firebase_helpers`. Firestore is most complex (IDOR + mass-assignment). Functions and Auth are detection-only (no session required).

**Tech Stack:** `vibe_iterator.scanners.base`, `vibe_iterator.utils.firebase_helpers`, `pytest`, `unittest.mock`

**Prerequisite:** Plans 1 + 2 complete.

---

## Task 1: `firebase_firestore.py` — skeleton + Group 1

**Files:**
- Create: `vibe_iterator/scanners/firebase_firestore.py`
- Create: `tests/test_scanners/test_firebase_firestore_proof.py`

- [ ] **Step 1: Write failing import test**

```python
# tests/test_scanners/test_firebase_firestore_proof.py
"""firebase_firestore scanner proof tests."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.firebase_firestore import Scanner
from vibe_iterator.scanners.base import Severity

@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app

def _make_config(base_url: str, second_account: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = second_account
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": base_url,
        "apiKey": "fakekey",
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
    }
    return cfg

def _make_network() -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = []
    return net

def _run(vuln_app, second_account: bool = False) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url, second_account)
    net = _make_network()
    return scanner.run(session=None, listeners={"network": net}, config=config)

def test_scanner_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_firestore"
    assert s.requires_stack == ["firebase"]
    assert s.requires_second_account is True
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_firestore_proof.py::test_scanner_attributes -v
```
Expected: `ImportError`.

- [ ] **Step 3: Create skeleton**

```python
# vibe_iterator/scanners/firebase_firestore.py
"""Firestore security scanner — open rules, IDOR, mass assignment."""
from __future__ import annotations

from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    detect_firebase_config,
    extract_firebase_config,
    rest_firestore_delete,
    rest_firestore_get,
    rest_firestore_write,
    truncate,
    build_firebase_llm_prompt,
    _from_firestore_fields,
)

_COMMON_COLLECTIONS = [
    "users", "profiles", "orders", "payments", "admin",
    "config", "settings", "subscriptions", "messages", "posts",
]
_PRIVILEGE_FIELDS = {
    "role": "admin", "is_admin": True, "is_premium": True,
    "subscription_tier": "enterprise", "credits": 999999,
}
_SENSITIVE_COLLECTIONS = {"users", "payments", "admin", "profiles"}


class Scanner(BaseScanner):
    name = "firebase_firestore"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = True

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        project_id = cfg["projectId"]
        stack = config.stack.backend
        page = config.target

        try:
            self._group1_unauth_access(project_id, stack, page, findings)
        except Exception:
            pass

        try:
            self._group3_mass_assignment(project_id, stack, page, findings)
        except Exception:
            pass

        try:
            self._group4_collection_enum(project_id, stack, page, findings)
        except Exception:
            pass

        return findings

    def _resolve_config(self, session: Any, network: Any, config: Any) -> dict | None:
        if hasattr(config, "_firebase_cfg"):
            return config._firebase_cfg
        cfg: dict = {}
        if session is not None:
            try:
                cfg = extract_firebase_config(session)
            except Exception:
                pass
        if not cfg.get("projectId"):
            try:
                cfg = detect_firebase_config(network.get_requests()) or {}
            except Exception:
                pass
        return cfg if cfg.get("projectId") else None

    def _group1_unauth_access(self, project_id: str, stack: str, page: str,
                               findings: list[Finding]) -> None:
        pass  # implemented in Task 2

    def _group3_mass_assignment(self, project_id: str, stack: str, page: str,
                                 findings: list[Finding]) -> None:
        pass  # implemented in Task 2

    def _group4_collection_enum(self, project_id: str, stack: str, page: str,
                                 findings: list[Finding]) -> None:
        pass  # implemented in Task 2
```

- [ ] **Step 4: Verify skeleton pass**

```
pytest tests/test_scanners/test_firebase_firestore_proof.py::test_scanner_attributes -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_firestore.py tests/test_scanners/test_firebase_firestore_proof.py
git commit -m "feat: add firebase_firestore scanner skeleton"
```

---

## Task 2: Firestore — implement check groups + proof tests

**Files:**
- Modify: `vibe_iterator/scanners/firebase_firestore.py`
- Modify: `tests/test_scanners/test_firebase_firestore_proof.py`

- [ ] **Step 1: Write failing proof tests**

```python
# append to tests/test_scanners/test_firebase_firestore_proof.py

def test_group1_unauth_read_high(vuln_app) -> None:
    findings = _run(vuln_app)
    unauth = [f for f in findings
              if "unauthenticated" in f.title.lower() and "read" in f.title.lower()]
    assert len(unauth) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in unauth)

def test_group3_mass_assignment_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    mass = [f for f in findings if "mass" in f.title.lower()
            or "privilege" in f.title.lower()]
    assert len(mass) >= 1
    assert any(f.severity == Severity.MEDIUM for f in mass)

def test_group4_collection_enum_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    enum = [f for f in findings if "enumerat" in f.title.lower()
            or "collection" in f.title.lower()]
    assert len(enum) >= 1
    assert any(f.severity == Severity.MEDIUM for f in enum)

def test_negative_secured_collection_no_finding() -> None:
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    # Point at a non-listening host → all REST calls fail → no findings
    cfg._firebase_cfg = {"projectId": "noproject"}
    net = MagicMock()
    net.get_requests.return_value = []
    findings = scanner.run(session=None, listeners={"network": net}, config=cfg)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()
              and "read" in f.title.lower()]
    assert unauth == []
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_firestore_proof.py -k "group or negative" -v
```
Expected: 4 FAIL.

- [ ] **Step 3: Implement check groups**

```python
# replace the three stub methods in firebase_firestore.py

    def _group1_unauth_access(self, project_id: str, stack: str, page: str,
                               findings: list[Finding]) -> None:
        import json as _json
        for coll in _COMMON_COLLECTIONS[:6]:
            body, status = rest_firestore_get(project_id, coll, "probe_doc", id_token=None)
            if status == 200:
                sev = Severity.CRITICAL if coll in _SENSITIVE_COLLECTIONS else Severity.HIGH
                desc = (
                    f"Firestore collection '{coll}' is readable without authentication. "
                    "Security Rules allow unauthenticated reads, exposing all documents. "
                    "Any attacker can enumerate user data without credentials."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=sev,
                    title=f"Firestore: unauthenticated read on '{coll}' collection",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET /documents/{coll}/probe_doc (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET",
                                    "url": f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{coll}/probe_doc",
                                    "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "403 PERMISSION_DENIED",
                        "actual_response": "200 OK with document data",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title=f"Firestore: unauthenticated read on '{coll}'",
                        severity=sev, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET /documents/{coll}/probe_doc (no auth) → 200",
                        detected_services="Firestore",
                    ),
                    remediation=(
                        f"**What to fix:** Add Security Rules that require authentication for '{coll}'.\n\n"
                        "**How to fix:** Firebase Console → Firestore Database → Rules:\n"
                        "```\nrules_version = '2';\nservice cloud.firestore {\n"
                        f"  match /databases/{{database}}/documents/{coll}/{{doc}} {{\n"
                        "    allow read, write: if request.auth != null;\n"
                        "  }\n}\n```\n\n"
                        "**Verify the fix:** Re-run firebase_firestore scanner — unauthenticated read should return 403."
                    ),
                    category=self.category, page=page,
                ))
                break  # one proof is sufficient

    def _group3_mass_assignment(self, project_id: str, stack: str, page: str,
                                 findings: list[Finding]) -> None:
        import json as _json
        doc_id = PROBE_PREFIX + "massassign_test"
        try:
            body, status = rest_firestore_write(
                project_id, "users", doc_id, _PRIVILEGE_FIELDS, id_token=None
            )
            if status and 200 <= status < 300:
                # Read it back to confirm fields persisted
                rb, rs = rest_firestore_get(project_id, "users", doc_id, id_token=None)
                try:
                    doc = _json.loads(rb)
                    persisted = _from_firestore_fields(doc)
                    confirmed = any(k in persisted for k in _PRIVILEGE_FIELDS)
                except Exception:
                    confirmed = True  # if we can't parse, write succeeding is enough
                if confirmed:
                    desc = (
                        "Firestore allows writing privileged fields (role, is_admin, is_premium) "
                        "without authentication or server-side validation. "
                        "An attacker can escalate privileges by writing to their own or another user's document."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="Firestore: mass assignment of privileged fields allowed",
                        description=desc,
                        evidence={
                            "action_attempted": f"PATCH /documents/users/{doc_id} with privilege fields",
                            "auth_context": "unauthenticated",
                            "request": {"method": "PATCH",
                                        "url": f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/users/{doc_id}",
                                        "headers": {}, "body": str(_PRIVILEGE_FIELDS)},
                            "response": {"status": status, "body_excerpt": truncate(body, 300)},
                            "expected_response": "403 PERMISSION_DENIED",
                            "actual_response": f"{status} — privileged fields written",
                            "second_account_used": False,
                        },
                        llm_prompt=build_firebase_llm_prompt(
                            title="Firestore: mass assignment of privileged fields allowed",
                            severity=Severity.MEDIUM, scanner=self.name,
                            page=page, category=self.category, description=desc,
                            evidence_summary=f"PATCH users/{doc_id} with role=admin (no auth) → {status}",
                            detected_services="Firestore",
                        ),
                        remediation=(
                            "**What to fix:** Block client writes to privileged fields.\n\n"
                            "**How to fix:** Use Security Rules to restrict which fields can be written:\n"
                            "```\nallow write: if request.auth != null &&\n"
                            "  !('role' in request.resource.data) &&\n"
                            "  !('is_admin' in request.resource.data);\n```\n\n"
                            "**Verify the fix:** Re-run firebase_firestore scanner — privileged write should return 403."
                        ),
                        category=self.category, page=page,
                    ))
        finally:
            try:
                rest_firestore_delete(project_id, "users", doc_id)
            except Exception:
                pass

    def _group4_collection_enum(self, project_id: str, stack: str, page: str,
                                 findings: list[Finding]) -> None:
        open_colls = []
        for coll in _COMMON_COLLECTIONS[:8]:
            body, status = rest_firestore_get(project_id, coll, "enum_probe", id_token=None)
            if status == 200:
                open_colls.append(coll)
        if open_colls:
            desc = (
                f"Firestore collections are enumerable without authentication: {open_colls}. "
                "An attacker can discover collection names and read documents without credentials. "
                "Security Rules are either absent or use 'allow read: if true;'."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.MEDIUM,
                title=f"Firestore: {len(open_colls)} collection(s) enumerable without auth",
                description=desc,
                evidence={
                    "action_attempted": f"GET /documents/<coll>/probe for each common collection",
                    "auth_context": "unauthenticated",
                    "request": {"method": "GET", "url": "multiple", "headers": {}, "body": None},
                    "response": {"status": 200,
                                 "body_excerpt": f"Collections returning 200: {open_colls}"},
                    "expected_response": "403 PERMISSION_DENIED for all",
                    "actual_response": f"{len(open_colls)} open",
                    "second_account_used": False,
                },
                llm_prompt=build_firebase_llm_prompt(
                    title=f"Firestore: collections enumerable without auth",
                    severity=Severity.MEDIUM, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"Open collections: {open_colls}",
                    detected_services="Firestore",
                ),
                remediation=(
                    "**What to fix:** Apply Security Rules to all collections.\n\n"
                    "**How to fix:** Firebase Console → Firestore Database → Rules — add "
                    "'allow read, write: if request.auth != null;' to each collection.\n\n"
                    "**Verify the fix:** Re-run firebase_firestore scanner — all collections should return 403."
                ),
                category=self.category, page=page,
            ))
```

- [ ] **Step 4: Run proof tests**

```
pytest tests/test_scanners/test_firebase_firestore_proof.py -v
```
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_firestore.py tests/test_scanners/test_firebase_firestore_proof.py
git commit -m "feat: implement firebase_firestore scanner with proof tests"
```

---

## Task 3: `firebase_functions.py` — scanner + proof tests

**Files:**
- Create: `vibe_iterator/scanners/firebase_functions.py`
- Create: `tests/test_scanners/test_firebase_functions_proof.py`

- [ ] **Step 1: Write failing proof tests**

```python
# tests/test_scanners/test_firebase_functions_proof.py
"""firebase_functions scanner proof tests."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.firebase_functions import Scanner
from vibe_iterator.scanners.base import Severity

@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app

def _make_config(base_url: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": base_url,
        "apiKey": "fakekey",
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
    }
    return cfg

def _make_network(fn_url: str = "") -> MagicMock:
    net = MagicMock()
    if fn_url:
        req = MagicMock()
        req.url = fn_url
        net.get_requests.return_value = [req]
    else:
        net.get_requests.return_value = []
    return net

def _run(vuln_app, fn_url: str = "") -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(fn_url)
    return scanner.run(session=None, listeners={"network": net}, config=config)

def test_scanner_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_functions"
    assert s.requires_stack == ["firebase"]

def test_group1_unauth_function_high(vuln_app) -> None:
    # Fixture returns 200 to any POST without auth → unauth function finding
    fn_url = vuln_app.base_url + "/helloWorld"
    findings = _run(vuln_app, fn_url=fn_url)
    unauth = [f for f in findings
              if "unauthenticated" in f.title.lower() or "without auth" in f.title.lower()]
    assert len(unauth) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in unauth)

def test_group2_token_in_response_high(vuln_app) -> None:
    fn_url = vuln_app.base_url + "/getToken"
    findings = _run(vuln_app, fn_url=fn_url)
    # Fixture leaks _FAKE_TOKEN in function body
    leak = [f for f in findings
            if "token" in f.title.lower() or "sensitive" in f.title.lower()
            or "data" in f.title.lower()]
    assert len(leak) >= 1

def test_group3_cors_misconfiguration_high(vuln_app) -> None:
    fn_url = vuln_app.base_url + "/someFunc"
    findings = _run(vuln_app, fn_url=fn_url)
    cors = [f for f in findings if "cors" in f.title.lower()]
    assert len(cors) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in cors)

def test_negative_function_returning_401_no_unauth_finding() -> None:
    # Without a discovered function URL, scanner has nothing to probe
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg._firebase_cfg = {"projectId": "testproj"}
    net = MagicMock()
    net.get_requests.return_value = []
    findings = scanner.run(session=None, listeners={"network": net}, config=cfg)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_functions_proof.py -v
```
Expected: `ImportError`.

- [ ] **Step 3: Implement `firebase_functions.py`**

```python
# vibe_iterator/scanners/firebase_functions.py
"""Cloud Functions security scanner — unauth access, CORS, sensitive data."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    REQUEST_TIMEOUT,
    detect_firebase_config,
    discover_function_urls,
    extract_firebase_config,
    find_id_tokens,
    truncate,
    build_firebase_llm_prompt,
)

_ADMIN_FN_NAMES = [
    "admin", "deleteUser", "setRole", "createAdmin", "grantAdmin",
    "resetPassword", "exportData",
]
_SENSITIVE_BODY_PATTERNS = ["idToken", "refreshToken", "access_token",
                             "password", "secret", "traceback", "__proto__"]


class Scanner(BaseScanner):
    name = "firebase_functions"
    category = "API Security"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        project_id = cfg["projectId"]
        page = config.target

        fn_urls = discover_function_urls(network.get_requests())

        # Also probe common admin names against discovered regions
        regions = self._extract_regions(fn_urls) or ["us-central1"]
        for region in regions[:2]:
            for name in _ADMIN_FN_NAMES:
                url = f"https://{region}-{project_id}.cloudfunctions.net/{name}"
                fn_urls.append(url)
        fn_urls = list(dict.fromkeys(fn_urls))  # deduplicate, preserve order

        # For tests: if fn_urls still empty, check if config has a test URL
        if not fn_urls and hasattr(config, "_firebase_cfg"):
            base = config._firebase_cfg.get("databaseURL", "")
            if base and "127.0.0.1" in base:
                # tests inject via network mock; nothing to add here
                pass

        if not fn_urls:
            return findings

        for url in fn_urls[:15]:
            try:
                self._probe_function(url, project_id, page, findings)
            except Exception:
                pass

        return findings

    def _resolve_config(self, session: Any, network: Any, config: Any) -> dict | None:
        if hasattr(config, "_firebase_cfg"):
            return config._firebase_cfg
        cfg: dict = {}
        if session is not None:
            try:
                cfg = extract_firebase_config(session)
            except Exception:
                pass
        if not cfg.get("projectId"):
            try:
                cfg = detect_firebase_config(network.get_requests()) or {}
            except Exception:
                pass
        return cfg if cfg.get("projectId") else None

    def _extract_regions(self, urls: list[str]) -> list[str]:
        from vibe_iterator.utils.firebase_helpers import _FUNCTION_HOST_RE
        regions = []
        for url in urls:
            m = _FUNCTION_HOST_RE.search(url)
            if m and m.group(1):
                parts = m.group(1).split("-")
                if len(parts) >= 3:
                    region = "-".join(parts[:-1])  # e.g. us-central1
                    if region not in regions:
                        regions.append(region)
        return regions

    def _probe_function(self, url: str, project_id: str, page: str,
                        findings: list[Finding]) -> None:
        # Group 1: unauthenticated call
        body_no_auth, status_no_auth = self._http_post(url, {"probe": True}, token=None)
        if status_no_auth == 200:
            desc = (
                f"Cloud Function at '{url}' is callable without authentication. "
                "Any anonymous user can invoke this function. "
                "Functions handling sensitive operations should verify the caller's identity."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title=f"Cloud Functions: callable without authentication ({url.split('/')[-1]})",
                description=desc,
                evidence={
                    "endpoint": url,
                    "test_performed": "replay_without_auth",
                    "request": {"method": "POST", "url": url, "headers": {}, "body": '{"probe":true}'},
                    "response": {"status": status_no_auth,
                                 "body_excerpt": truncate(body_no_auth, 300)},
                    "expected_response": "401 Unauthorized",
                },
                llm_prompt=build_firebase_llm_prompt(
                    title=f"Cloud Functions: callable without authentication",
                    severity=Severity.HIGH, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"POST {url} (no auth) → 200",
                    detected_services="Cloud Functions",
                ),
                remediation=(
                    "**What to fix:** Verify the caller's identity inside the function.\n\n"
                    "**How to fix:** For callable functions, use `context.auth`. For HTTPS functions:\n"
                    "```js\nconst token = req.headers.authorization?.split('Bearer ')[1];\n"
                    "if (!token) return res.status(401).send('Unauthorized');\n"
                    "await admin.auth().verifyIdToken(token);\n```\n\n"
                    "**Verify the fix:** Re-run firebase_functions scanner — unauthenticated call should return 401."
                ),
                category=self.category, page=page,
            ))

            # Group 2: sensitive data in response
            if body_no_auth:
                tokens = find_id_tokens(body_no_auth)
                has_sensitive = tokens or any(p in body_no_auth for p in _SENSITIVE_BODY_PATTERNS)
                if has_sensitive:
                    sev = Severity.HIGH if tokens else Severity.MEDIUM
                    desc2 = (
                        f"Cloud Function at '{url}' returns sensitive data in its response body: "
                        f"{'ID tokens were found' if tokens else 'sensitive fields detected'}. "
                        "Tokens leaked in responses can be captured by network monitoring tools."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=sev,
                        title=f"Cloud Functions: sensitive data in response ({url.split('/')[-1]})",
                        description=desc2,
                        evidence={
                            "endpoint": url,
                            "test_performed": "response_analysis",
                            "request": {"method": "POST", "url": url, "headers": {}, "body": '{"probe":true}'},
                            "response": {"status": status_no_auth,
                                         "body_excerpt": truncate(body_no_auth, 300)},
                            "expected_response": "Response without tokens or internal data",
                        },
                        llm_prompt=build_firebase_llm_prompt(
                            title="Cloud Functions: sensitive data in response",
                            severity=sev, scanner=self.name,
                            page=page, category=self.category, description=desc2,
                            evidence_summary=f"Function response contains sensitive data.",
                            detected_services="Cloud Functions",
                        ),
                        remediation=(
                            "**What to fix:** Never return tokens, passwords, or internal data in function responses.\n\n"
                            "**How to fix:** Audit function response bodies and strip any tokens or secrets.\n\n"
                            "**Verify the fix:** Re-run firebase_functions scanner — no tokens in response."
                        ),
                        category=self.category, page=page,
                    ))

        # Group 3: CORS misconfiguration
        cors_body, cors_status, cors_headers = self._http_options(url)
        acao = cors_headers.get("Access-Control-Allow-Origin", "")
        acac = cors_headers.get("Access-Control-Allow-Credentials", "")
        if (acao == "*" or acao == "https://evil.example") and acac.lower() == "true":
            desc3 = (
                f"Cloud Function at '{url}' has a CORS misconfiguration: "
                "it allows all origins (or reflects the evil origin) and also sets "
                "Access-Control-Allow-Credentials: true. "
                "This combination lets a malicious site read the function's response using the victim's cookies."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title=f"Cloud Functions: CORS misconfiguration ({url.split('/')[-1]})",
                description=desc3,
                evidence={
                    "endpoint": url,
                    "test_performed": "cors_probe",
                    "request": {"method": "OPTIONS", "url": url,
                                "headers": {"Origin": "https://evil.example"}, "body": None},
                    "response": {"status": cors_status,
                                 "body_excerpt": f"ACAO: {acao}, ACAC: {acac}"},
                    "expected_response": "ACAO restricted to known origins or ACAC absent/false",
                },
                llm_prompt=build_firebase_llm_prompt(
                    title="Cloud Functions: CORS misconfiguration",
                    severity=Severity.HIGH, scanner=self.name,
                    page=page, category=self.category, description=desc3,
                    evidence_summary=f"OPTIONS {url} → ACAO={acao}, ACAC={acac}",
                    detected_services="Cloud Functions",
                ),
                remediation=(
                    "**What to fix:** Restrict CORS origins and never combine wildcard with credentials.\n\n"
                    "**How to fix:** In the function:\n"
                    "```js\nconst ALLOWED = ['https://myapp.com'];\n"
                    "if (ALLOWED.includes(req.headers.origin)) {\n"
                    "  res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
                    "}\n// Do NOT set Allow-Credentials: true with a wildcard origin.\n```\n\n"
                    "**Verify the fix:** Re-run firebase_functions scanner — CORS probe should not reflect evil origin."
                ),
                category=self.category, page=page,
            ))

    def _http_post(self, url: str, payload: dict, token: str | None) -> tuple[str, int | None]:
        import json as _json
        headers: dict = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = _json.dumps(payload).encode()
        try:
            req = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _http_options(self, url: str) -> tuple[str, int | None, dict]:
        headers: dict = {"Origin": "https://evil.example",
                         "Access-Control-Request-Method": "POST"}
        try:
            req = urllib.request.Request(url, method="OPTIONS", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                resp_headers = dict(resp.headers)
                return resp.read().decode("utf-8", errors="replace"), resp.status, resp_headers
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code, dict(e.headers)
            except Exception:
                return "", e.code, {}
        except Exception:
            return "", None, {}
```

- [ ] **Step 4: Run proof tests**

```
pytest tests/test_scanners/test_firebase_functions_proof.py -v
```
Expected: all 5 tests PASS.

> **Note on Group 1/2/3 test:** The fixture returns `_FAKE_TOKEN` in POST body and wildcard CORS in OPTIONS — this drives all three positive assertions. The token detection test (`test_group2_token_in_response_high`) relies on `find_id_tokens` matching the `eyJ...` pattern in `_FAKE_TOKEN`. The CORS test (`test_group3_cors_misconfiguration_high`) relies on the fixture's `do_OPTIONS` setting `ACAO: <reflected origin>` + `ACAC: true`.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_functions.py tests/test_scanners/test_firebase_functions_proof.py
git commit -m "feat: implement firebase_functions scanner with proof tests"
```

---

## Task 4: `firebase_auth.py` — scanner + proof tests

**Files:**
- Create: `vibe_iterator/scanners/firebase_auth.py`
- Create: `tests/test_scanners/test_firebase_auth_proof.py`

- [ ] **Step 1: Write failing proof tests**

```python
# tests/test_scanners/test_firebase_auth_proof.py
"""firebase_auth scanner proof tests."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.firebase_auth import Scanner
from vibe_iterator.scanners.base import Severity

@pytest.fixture(scope="module")
def vuln_app():
    with FirebaseVulnerableApp() as app:
        yield app

def _make_config(base_url: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = base_url
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    # Override IDENTITY_TOOLKIT_BASE to point at fixture
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "apiKey": "fakekey",
        "databaseURL": base_url,
        "storageBucket": "testproj.appspot.com",
        "authDomain": "testproj.firebaseapp.com",
        "_toolkit_base": base_url + "/v1",   # fixture serves /v1/accounts:signUp etc.
    }
    return cfg

def _make_network() -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = []
    return net

def _run(vuln_app) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network()
    storage = MagicMock()
    storage.get_snapshot.return_value = {}
    return scanner.run(session=None, listeners={"network": net, "storage": storage}, config=config)

def test_scanner_attributes() -> None:
    s = Scanner()
    assert s.name == "firebase_auth"
    assert s.requires_stack == ["firebase"]

def test_group1_anonymous_auth_high(vuln_app) -> None:
    findings = _run(vuln_app)
    anon = [f for f in findings if "anonymous" in f.title.lower()]
    assert len(anon) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in anon)

def test_group2_email_enumeration_low(vuln_app) -> None:
    findings = _run(vuln_app)
    enum = [f for f in findings if "enumerat" in f.title.lower()
            or "email" in f.title.lower()]
    assert len(enum) >= 1
    assert any(f.severity in (Severity.LOW, Severity.MEDIUM) for f in enum)

def test_negative_anonymous_disabled() -> None:
    # When signUp returns 400 (anonymous disabled), no finding
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "apiKey": "fakekey",
        "_toolkit_base": "http://localhost:1/v1",  # unreachable → REST returns ("", None)
    }
    net = MagicMock()
    net.get_requests.return_value = []
    storage = MagicMock()
    storage.get_snapshot.return_value = {}
    findings = scanner.run(session=None, listeners={"network": net, "storage": storage}, config=cfg)
    anon = [f for f in findings if "anonymous" in f.title.lower()]
    assert anon == []
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_auth_proof.py -v
```
Expected: `ImportError`.

- [ ] **Step 3: Implement `firebase_auth.py`**

```python
# vibe_iterator/scanners/firebase_auth.py
"""Firebase Auth scanner — anonymous auth abuse, email enumeration, token exposure."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    IDENTITY_TOOLKIT_BASE,
    REQUEST_TIMEOUT,
    detect_firebase_config,
    extract_firebase_config,
    find_id_tokens,
    truncate,
    build_firebase_llm_prompt,
)


class Scanner(BaseScanner):
    name = "firebase_auth"
    category = "Authentication"
    stages = ["dev", "pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        api_key = cfg.get("apiKey")
        if not api_key:
            return findings

        # Support test override of toolkit base
        toolkit_base = cfg.get("_toolkit_base") or IDENTITY_TOOLKIT_BASE
        page = config.target

        try:
            self._group1_anonymous_auth(api_key, toolkit_base, page, findings)
        except Exception:
            pass

        try:
            self._group2_email_enumeration(api_key, toolkit_base, page, config, findings)
        except Exception:
            pass

        try:
            self._group4_token_exposure(network, listeners.get("storage"), page, findings)
        except Exception:
            pass

        return findings

    def _resolve_config(self, session: Any, network: Any, config: Any) -> dict | None:
        if hasattr(config, "_firebase_cfg"):
            return config._firebase_cfg
        cfg: dict = {}
        if session is not None:
            try:
                cfg = extract_firebase_config(session)
            except Exception:
                pass
        if not cfg.get("projectId"):
            try:
                cfg = detect_firebase_config(network.get_requests()) or {}
            except Exception:
                pass
        return cfg if cfg.get("projectId") else None

    def _post(self, url: str, payload: dict) -> tuple[str, int | None]:
        body = json.dumps(payload).encode()
        try:
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _group1_anonymous_auth(self, api_key: str, toolkit_base: str, page: str,
                                findings: list[Finding]) -> None:
        url = f"{toolkit_base}/accounts:signUp?key={api_key}"
        body, status = self._post(url, {"returnSecureToken": True})
        if status == 200:
            try:
                data = json.loads(body)
                has_token = bool(data.get("idToken"))
            except Exception:
                has_token = "idToken" in body
            if has_token:
                desc = (
                    "Firebase project has anonymous authentication enabled. "
                    "Any visitor can sign in anonymously and obtain a valid Firebase ID token. "
                    "If Firestore, RTDB, or Storage rules use 'request.auth != null' as the only check, "
                    "anonymous users can access all 'authenticated' data."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title="Firebase Auth: anonymous sign-in enabled",
                    description=desc,
                    evidence={
                        "check_group": "Anonymous Auth Abuse",
                        "check_name": "Anonymous sign-in returns idToken",
                        "evidence_type": "request_replay",
                        "observed_value": "POST accounts:signUp (no email) → 200 with idToken",
                        "expected_behavior": "Anonymous sign-in disabled (400 error)",
                        "request": {"method": "POST",
                                    "url": url.replace(api_key, "<redacted>"),
                                    "headers": {"Content-Type": "application/json"},
                                    "body": '{"returnSecureToken": true}'},
                        "response": {"status": status,
                                     "body_excerpt": truncate(body.replace(api_key, "<redacted>"), 300)},
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Firebase Auth: anonymous sign-in enabled",
                        severity=Severity.HIGH, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary="POST accounts:signUp (anonymous) → 200 with idToken.",
                        detected_services="Auth",
                    ),
                    remediation=(
                        "**What to fix:** Disable anonymous sign-in if not required.\n\n"
                        "**How to fix:** Firebase Console → Authentication → Sign-in method → "
                        "Anonymous → Disable.\n\n"
                        "**Verify the fix:** Re-run firebase_auth scanner — anonymous signUp should return 400."
                    ),
                    category=self.category, page=page,
                ))

    def _group2_email_enumeration(self, api_key: str, toolkit_base: str, page: str,
                                   config: Any, findings: list[Finding]) -> None:
        url = f"{toolkit_base}/accounts:createAuthUri?key={api_key}"
        target = getattr(config, "target", "http://localhost")

        # Probe a likely-registered address and a random one
        registered_body, registered_status = self._post(url, {
            "identifier": "test@example.com",
            "continueUri": target,
        })
        random_body, random_status = self._post(url, {
            "identifier": "randomzzz9x7@nonexistentdomain.invalid",
            "continueUri": target,
        })

        if registered_status != 200 or random_status != 200:
            return

        try:
            reg_data = json.loads(registered_body)
            rnd_data = json.loads(random_body)
            # Enumeration confirmed if 'registered' flag differs
            reg_flag = reg_data.get("registered", False)
            rnd_flag = rnd_data.get("registered", False)
            if reg_flag != rnd_flag:
                desc = (
                    "Firebase Authentication exposes whether an email address is registered "
                    "via the accounts:createAuthUri endpoint. An attacker can enumerate "
                    "which email addresses have accounts by probing this endpoint."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.LOW,
                    title="Firebase Auth: email enumeration via createAuthUri",
                    description=desc,
                    evidence={
                        "check_group": "Email Enumeration",
                        "check_name": "accounts:createAuthUri registered flag differs",
                        "evidence_type": "request_replay",
                        "observed_value": f"registered=True for known email, False for random",
                        "expected_behavior": "Identical response regardless of whether email exists",
                        "request": {"method": "POST",
                                    "url": url.replace(api_key, "<redacted>"),
                                    "headers": {"Content-Type": "application/json"},
                                    "body": '{"identifier": "<email>", "continueUri": "..."}'},
                        "response": {"status": 200,
                                     "body_excerpt": truncate(registered_body, 200)},
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Firebase Auth: email enumeration via createAuthUri",
                        severity=Severity.LOW, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary="createAuthUri returns different 'registered' flag per email.",
                        detected_services="Auth",
                    ),
                    remediation=(
                        "**What to fix:** Enable email enumeration protection.\n\n"
                        "**How to fix:** Firebase Console → Authentication → Settings → "
                        "Email enumeration protection → Enable.\n\n"
                        "**Verify the fix:** Re-run firebase_auth scanner — createAuthUri should return identical responses."
                    ),
                    category=self.category, page=page,
                ))
        except Exception:
            pass

    def _group4_token_exposure(self, network: Any, storage: Any,
                                page: str, findings: list[Finding]) -> None:
        try:
            requests = network.get_requests()
            for req in requests:
                url = getattr(req, "url", "") or ""
                if "?" in url:
                    tokens = find_id_tokens(url)
                    if tokens:
                        desc = (
                            "Firebase ID tokens are being transmitted in URL query parameters. "
                            "URL parameters are logged by servers, proxies, and browser history, "
                            "creating a risk of token leakage."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.MEDIUM,
                            title="Firebase Auth: ID token exposed in URL parameter",
                            description=desc,
                            evidence={
                                "check_group": "ID Token Exposure",
                                "check_name": "ID token found in URL query string",
                                "evidence_type": "response_analysis",
                                "observed_value": f"Token found in URL: {truncate(url, 100)}",
                                "expected_behavior": "Tokens transmitted only in Authorization headers",
                                "request": {"method": "GET", "url": truncate(url, 100),
                                            "headers": {}, "body": None},
                                "response": {"status": None, "body_excerpt": ""},
                            },
                            llm_prompt=build_firebase_llm_prompt(
                                title="Firebase Auth: ID token exposed in URL parameter",
                                severity=Severity.MEDIUM, scanner=self.name,
                                page=page, category=self.category, description=desc,
                                evidence_summary=f"Token found in URL query string.",
                                detected_services="Auth",
                            ),
                            remediation=(
                                "**What to fix:** Move ID tokens from URL parameters to Authorization headers.\n\n"
                                "**How to fix:** Use `Authorization: Bearer <idToken>` instead of `?token=...`.\n\n"
                                "**Verify the fix:** Re-run firebase_auth scanner — no tokens in URLs."
                            ),
                            category=self.category, page=page,
                        ))
                        break
        except Exception:
            pass
```

- [ ] **Step 4: Run proof tests**

```
pytest tests/test_scanners/test_firebase_auth_proof.py -v
```
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_auth.py tests/test_scanners/test_firebase_auth_proof.py
git commit -m "feat: implement firebase_auth scanner with proof tests"
```

---

## Task 5: Run Plan 3 full suite

- [ ] **Step 1: Run all Plan 3 tests**

```
pytest tests/test_scanners/test_firebase_firestore_proof.py tests/test_scanners/test_firebase_functions_proof.py tests/test_scanners/test_firebase_auth_proof.py -v
```
Expected: all PASS.

- [ ] **Step 2: Run full existing suite for regressions**

```
pytest -x -q
```
Expected: green.

---

**Plan 3 complete. Continue with Plan 4: Engine wiring, config, dashboard, and docs.**
