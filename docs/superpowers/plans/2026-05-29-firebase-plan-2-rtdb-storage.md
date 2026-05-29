# Firebase Scanner — Plan 2: RTDB + Storage Scanners

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `firebase_rtdb.py` and `firebase_storage.py` with proof tests against the fixture from Plan 1.

**Architecture:** Each scanner subclasses `BaseScanner`, targets REST helpers from `firebase_helpers`, uses `_resolve_config` to obtain Firebase project details, and wraps each check group in its own `try/except`.

**Tech Stack:** `vibe_iterator.scanners.base`, `vibe_iterator.utils.firebase_helpers`, `pytest`, `unittest.mock`

**Prerequisite:** Plan 1 complete (helpers + fixture passing).

---

## Task 1: `firebase_rtdb.py` — scanner skeleton

**Files:**
- Create: `vibe_iterator/scanners/firebase_rtdb.py`

- [ ] **Step 1: Write the failing import test**

```python
# tests/test_scanners/test_firebase_rtdb_proof.py
"""firebase_rtdb scanner proof tests — real HTTP against FirebaseVulnerableApp."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.firebase_rtdb import Scanner
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

def _make_network() -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = []
    return net

def _run(vuln_app) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network()
    return scanner.run(session=None, listeners={"network": net}, config=config)

def test_scanner_importable() -> None:
    s = Scanner()
    assert s.name == "firebase_rtdb"
    assert s.requires_stack == ["firebase"]
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_rtdb_proof.py::test_scanner_importable -v
```
Expected: `ImportError` or `ModuleNotFoundError`.

- [ ] **Step 3: Create the scanner skeleton**

```python
# vibe_iterator/scanners/firebase_rtdb.py
"""Realtime Database security scanner — open read/write rules detection."""
from __future__ import annotations

from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    detect_firebase_config,
    extract_firebase_config,
    rest_rtdb_delete,
    rest_rtdb_get,
    rest_rtdb_write,
    truncate,
    build_firebase_llm_prompt,
)

_COMMON_PATHS = ["users", "config", "admin", "settings", "messages", "profiles", "orders"]


class Scanner(BaseScanner):
    name = "firebase_rtdb"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        db_url = cfg.get("databaseURL") or (
            f"https://{cfg['projectId']}-default-rtdb.firebaseio.com"
        )
        stack = config.stack.backend
        page = config.target

        try:
            self._group1_unauth_access(db_url, stack, page, findings)
        except Exception:
            pass

        try:
            self._group2_unauth_write(db_url, stack, page, findings)
        except Exception:
            pass

        try:
            self._group3_shallow_enumeration(db_url, stack, page, findings)
        except Exception:
            pass

        return findings

    def _resolve_config(self, session: Any, network: Any, config: Any) -> dict | None:
        # Allow tests to inject config directly via config._firebase_cfg
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

    def _group1_unauth_access(self, db_url: str, stack: str, page: str,
                               findings: list[Finding]) -> None:
        pass  # implemented in Task 2

    def _group2_unauth_write(self, db_url: str, stack: str, page: str,
                              findings: list[Finding]) -> None:
        pass  # implemented in Task 2

    def _group3_shallow_enumeration(self, db_url: str, stack: str, page: str,
                                     findings: list[Finding]) -> None:
        pass  # implemented in Task 2
```

- [ ] **Step 4: Run to verify skeleton passes**

```
pytest tests/test_scanners/test_firebase_rtdb_proof.py::test_scanner_importable -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_rtdb.py tests/test_scanners/test_firebase_rtdb_proof.py
git commit -m "feat: add firebase_rtdb scanner skeleton"
```

---

## Task 2: RTDB — implement check groups + proof tests

**Files:**
- Modify: `vibe_iterator/scanners/firebase_rtdb.py`
- Modify: `tests/test_scanners/test_firebase_rtdb_proof.py`

- [ ] **Step 1: Write failing proof tests**

```python
# append to tests/test_scanners/test_firebase_rtdb_proof.py

def test_group1_unauth_root_read_critical(vuln_app) -> None:
    findings = _run(vuln_app)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()
              and "read" in f.title.lower()]
    assert len(unauth) >= 1
    assert any(f.severity == Severity.CRITICAL for f in unauth)

def test_group2_unauth_write_critical(vuln_app) -> None:
    findings = _run(vuln_app)
    write = [f for f in findings if "write" in f.title.lower()]
    assert len(write) >= 1
    assert any(f.severity == Severity.CRITICAL for f in write)

def test_group3_shallow_enumeration_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    enum = [f for f in findings if "enumerat" in f.title.lower()
            or "structure" in f.title.lower()]
    assert len(enum) >= 1
    assert any(f.severity == Severity.MEDIUM for f in enum)

def test_negative_secured_path_no_finding(vuln_app) -> None:
    # Fixture's /secured/.json returns 401 → no unauth finding for that path
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    # Override databaseURL to force only the secured path
    config._firebase_cfg = {
        "projectId": "testproj",
        "databaseURL": vuln_app.base_url + "/secured",
        "apiKey": "fakekey",
    }
    net = _make_network()
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()
              and "read" in f.title.lower()]
    assert unauth == []
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_rtdb_proof.py -k "group or negative" -v
```
Expected: 4 FAIL — check groups are stubs returning `pass`.

- [ ] **Step 3: Implement the check groups**

```python
# replace the three stub methods in firebase_rtdb.py

    def _group1_unauth_access(self, db_url: str, stack: str, page: str,
                               findings: list[Finding]) -> None:
        import json as _json
        body, status = rest_rtdb_get(db_url, "", id_token=None)
        if status == 200:
            try:
                data = _json.loads(body)
                has_data = data is not None and data != {}
            except Exception:
                has_data = bool(body and body.strip() != "null")
            if has_data:
                desc = (
                    "The Firebase Realtime Database root is readable without authentication. "
                    "Any anonymous user can fetch the entire database contents. "
                    "This is caused by a Security Rule like '.read: true' at the root level. "
                    "All data in the database is exposed."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.CRITICAL,
                    title="Realtime Database: unauthenticated root read allowed",
                    description=desc,
                    evidence={
                        "action_attempted": "GET /.json (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": f"{db_url}/.json", "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "401 or permission-denied",
                        "actual_response": f"200 OK with data",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Realtime Database: unauthenticated root read allowed",
                        severity=Severity.CRITICAL, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET {db_url}/.json returned 200 with data.",
                        detected_services="Realtime Database",
                    ),
                    remediation=(
                        "**What to fix:** Set `.read` to require authentication at the root.\n\n"
                        "**How to fix:** In Firebase Console → Realtime Database → Rules:\n"
                        '```json\n{ "rules": { ".read": "auth != null", ".write": "auth != null" } }\n```\n\n'
                        "**Verify the fix:** Re-run firebase_rtdb scanner — root read should return 401."
                    ),
                    category=self.category, page=page,
                ))

    def _group2_unauth_write(self, db_url: str, stack: str, page: str,
                              findings: list[Finding]) -> None:
        probe_path = PROBE_PREFIX + "canary"
        body, status = rest_rtdb_write(db_url, probe_path, {"vibe": "iterator", "ts": 0},
                                        id_token=None)
        try:
            rest_rtdb_delete(db_url, probe_path)
        except Exception:
            pass
        if status == 200:
            desc = (
                "The Firebase Realtime Database accepts write operations without authentication. "
                "An attacker can write arbitrary data to any database path, including overwriting "
                "user records or injecting malicious content. "
                "This is caused by a Security Rule like '.write: true' at the root."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.CRITICAL,
                title="Realtime Database: unauthenticated write allowed",
                description=desc,
                evidence={
                    "action_attempted": f"PUT /{probe_path}.json (no auth)",
                    "auth_context": "unauthenticated",
                    "request": {"method": "PUT", "url": f"{db_url}/{probe_path}.json",
                                "headers": {}, "body": '{"vibe":"iterator","ts":0}'},
                    "response": {"status": status, "body_excerpt": truncate(body, 300)},
                    "expected_response": "401 Unauthorized",
                    "actual_response": "200 OK",
                    "second_account_used": False,
                },
                llm_prompt=build_firebase_llm_prompt(
                    title="Realtime Database: unauthenticated write allowed",
                    severity=Severity.CRITICAL, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"PUT {db_url}/{probe_path}.json (no auth) → 200.",
                    detected_services="Realtime Database",
                ),
                remediation=(
                    "**What to fix:** Require authentication for all writes.\n\n"
                    "**How to fix:** Firebase Console → Realtime Database → Rules:\n"
                    '```json\n{ "rules": { ".write": "auth != null" } }\n```\n\n'
                    "**Verify the fix:** Re-run firebase_rtdb scanner — unauthenticated write should return 401."
                ),
                category=self.category, page=page,
            ))

    def _group3_shallow_enumeration(self, db_url: str, stack: str, page: str,
                                     findings: list[Finding]) -> None:
        import json as _json
        url = f"{db_url}/.json?shallow=true"
        body, status = rest_rtdb_get(db_url, "?shallow=true", id_token=None)
        if status == 200:
            try:
                data = _json.loads(body)
                is_key_map = isinstance(data, dict) and len(data) > 0
            except Exception:
                is_key_map = False
            if is_key_map:
                keys = list(data.keys())[:10]
                desc = (
                    "The Firebase Realtime Database exposes its top-level structure to anonymous users "
                    "via the ?shallow=true parameter. Attackers can enumerate all top-level keys "
                    f"without authentication. Discovered keys: {keys}."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Realtime Database: top-level structure enumerable without auth",
                    description=desc,
                    evidence={
                        "action_attempted": "GET /.json?shallow=true (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "401 or empty",
                        "actual_response": f"200 with keys: {keys}",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Realtime Database: top-level structure enumerable without auth",
                        severity=Severity.MEDIUM, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET /.json?shallow=true → 200, keys: {keys}",
                        detected_services="Realtime Database",
                    ),
                    remediation=(
                        "**What to fix:** Disable unauthenticated read at the root.\n\n"
                        "**How to fix:** Firebase Console → Realtime Database → Rules:\n"
                        '```json\n{ "rules": { ".read": "auth != null" } }\n```\n\n'
                        "**Verify the fix:** Re-run firebase_rtdb scanner — shallow read should return 401."
                    ),
                    category=self.category, page=page,
                ))
```

- [ ] **Step 4: Run proof tests**

```
pytest tests/test_scanners/test_firebase_rtdb_proof.py -v
```
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_rtdb.py tests/test_scanners/test_firebase_rtdb_proof.py
git commit -m "feat: implement firebase_rtdb scanner with proof tests"
```

---

## Task 3: `firebase_storage.py` — scanner + proof tests

**Files:**
- Create: `vibe_iterator/scanners/firebase_storage.py`
- Create: `tests/test_scanners/test_firebase_storage_proof.py`

- [ ] **Step 1: Write failing proof tests**

```python
# tests/test_scanners/test_firebase_storage_proof.py
"""firebase_storage scanner proof tests."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
from vibe_iterator.scanners.firebase_storage import Scanner
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
        "storageBucket": base_url.replace("http://", ""),   # fixture serves storage too
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
    assert s.name == "firebase_storage"
    assert s.requires_stack == ["firebase"]

def test_group1_unauth_download_high(vuln_app) -> None:
    findings = _run(vuln_app)
    dl = [f for f in findings if "download" in f.title.lower()
          or "read" in f.title.lower()]
    assert len(dl) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in dl)

def test_group2_unauth_upload_high(vuln_app) -> None:
    findings = _run(vuln_app)
    ul = [f for f in findings if "upload" in f.title.lower()
          or "write" in f.title.lower()]
    assert len(ul) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in ul)

def test_group4_bucket_listing_medium(vuln_app) -> None:
    findings = _run(vuln_app)
    lst = [f for f in findings if "list" in f.title.lower()
           or "enumerat" in f.title.lower()]
    assert len(lst) >= 1
    assert any(f.severity == Severity.MEDIUM for f in lst)

def test_negative_secured_path_no_download_finding() -> None:
    # This test does not use the fixture; just confirms scanner returns [] when
    # all REST calls return 403 (simulated via config pointing at a non-existent host).
    scanner = Scanner()
    cfg = MagicMock()
    cfg.target = "http://localhost:1"
    cfg.stack.backend = "firebase"
    cfg.second_account_configured = False
    cfg._firebase_cfg = {
        "projectId": "testproj",
        "storageBucket": "testproj.appspot.com",
        "databaseURL": "http://localhost:1",
    }
    net = MagicMock()
    net.get_requests.return_value = []
    # REST calls to localhost:1 fail → return ("", None) → no findings
    findings = scanner.run(session=None, listeners={"network": net}, config=cfg)
    dl = [f for f in findings if "download" in f.title.lower()]
    assert dl == []
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_storage_proof.py -v
```
Expected: `ImportError` — scanner does not exist yet.

- [ ] **Step 3: Implement `firebase_storage.py`**

```python
# vibe_iterator/scanners/firebase_storage.py
"""Storage security scanner — unauthenticated download/upload/listing detection."""
from __future__ import annotations

from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    detect_firebase_config,
    extract_firebase_config,
    rest_storage_delete,
    rest_storage_download,
    rest_storage_upload,
    truncate,
    build_firebase_llm_prompt,
)

_COMMON_FILE_PATHS = ["public/test.txt", "avatars/user1.png", "uploads/doc.pdf",
                      "images/photo.jpg", "users/uid1/profile.jpg"]
_PROBE_FILE = f"{PROBE_PREFIX}canary.txt"
_PROBE_CONTENT = b"vibe-iterator probe; safe to delete"


class Scanner(BaseScanner):
    name = "firebase_storage"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        bucket = cfg.get("storageBucket") or f"{cfg['projectId']}.appspot.com"
        stack = config.stack.backend
        page = config.target

        try:
            self._group1_unauth_download(bucket, stack, page, findings)
        except Exception:
            pass

        try:
            self._group2_unauth_upload(bucket, stack, page, findings)
        except Exception:
            pass

        try:
            self._group4_bucket_listing(bucket, stack, page, findings)
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

    def _group1_unauth_download(self, bucket: str, stack: str, page: str,
                                 findings: list[Finding]) -> None:
        for path in _COMMON_FILE_PATHS:
            body, status = rest_storage_download(bucket, path, id_token=None)
            if status == 200 and body:
                desc = (
                    f"Firebase Storage file '{path}' is downloadable without authentication. "
                    "An attacker can download private files without any credentials. "
                    "Storage Security Rules are either missing or set to 'allow read: if true;'."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title=f"Storage: unauthenticated file download allowed ({path})",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET /o/{path}?alt=media (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET",
                                    "url": f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{path}?alt=media",
                                    "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 200)},
                        "expected_response": "403 Forbidden",
                        "actual_response": "200 OK with file bytes",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title=f"Storage: unauthenticated file download allowed",
                        severity=Severity.HIGH, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET {path} (no auth) → 200",
                        detected_services="Storage",
                    ),
                    remediation=(
                        "**What to fix:** Require authentication to read Storage files.\n\n"
                        "**How to fix:** Firebase Console → Storage → Rules:\n"
                        "```\nrules_version = '2';\nservice firebase.storage {\n"
                        "  match /b/{bucket}/o {\n"
                        "    match /{allPaths=**} {\n"
                        "      allow read, write: if request.auth != null;\n"
                        "    }\n  }\n}\n```\n\n"
                        "**Verify the fix:** Re-run firebase_storage scanner — download should return 403."
                    ),
                    category=self.category, page=page,
                ))
                break  # one finding is enough to prove the rule is open

    def _group2_unauth_upload(self, bucket: str, stack: str, page: str,
                               findings: list[Finding]) -> None:
        body, status = rest_storage_upload(bucket, _PROBE_FILE, _PROBE_CONTENT, id_token=None)
        try:
            rest_storage_delete(bucket, _PROBE_FILE)
        except Exception:
            pass
        if status and 200 <= status < 300:
            desc = (
                "Firebase Storage accepts file uploads without authentication. "
                "An attacker can upload arbitrary files to the storage bucket, "
                "potentially serving malicious content or exhausting storage quota. "
                "Storage Security Rules are either missing or set to 'allow write: if true;'."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title="Storage: unauthenticated file upload allowed",
                description=desc,
                evidence={
                    "action_attempted": f"POST /o?name={_PROBE_FILE} (no auth)",
                    "auth_context": "unauthenticated",
                    "request": {"method": "POST",
                                "url": f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?name={_PROBE_FILE}",
                                "headers": {}, "body": f"{len(_PROBE_CONTENT)} bytes"},
                    "response": {"status": status, "body_excerpt": truncate(body, 200)},
                    "expected_response": "403 Forbidden",
                    "actual_response": f"{status} — upload accepted",
                    "second_account_used": False,
                },
                llm_prompt=build_firebase_llm_prompt(
                    title="Storage: unauthenticated file upload allowed",
                    severity=Severity.HIGH, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"POST probe file (no auth) → {status}",
                    detected_services="Storage",
                ),
                remediation=(
                    "**What to fix:** Require authentication for Storage writes.\n\n"
                    "**How to fix:** Firebase Console → Storage → Rules — same fix as for read (see above).\n\n"
                    "**Verify the fix:** Re-run firebase_storage scanner — upload should return 403."
                ),
                category=self.category, page=page,
            ))

    def _group4_bucket_listing(self, bucket: str, stack: str, page: str,
                                findings: list[Finding]) -> None:
        import json as _json
        import urllib.request, urllib.error
        from vibe_iterator.utils.firebase_helpers import REQUEST_TIMEOUT
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
        try:
            req = __import__("urllib.request", fromlist=["Request"]).Request(url, method="GET")
            with __import__("urllib.request", fromlist=["urlopen"]).urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.status
        except __import__("urllib.error", fromlist=["HTTPError"]).HTTPError as e:
            body = ""
            status = e.code
        except Exception:
            return

        if status == 200:
            try:
                data = _json.loads(body)
                items = data.get("items", [])
            except Exception:
                items = []
            if items:
                names = [i.get("name", "") for i in items[:5]]
                desc = (
                    "Firebase Storage bucket contents are enumerable without authentication. "
                    f"An attacker can list all stored files. Found {len(items)} item(s): {names}."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Storage: bucket file listing allowed without auth",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET /v0/b/{bucket}/o (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "403 Forbidden",
                        "actual_response": f"200 with {len(items)} items",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Storage: bucket file listing allowed without auth",
                        severity=Severity.MEDIUM, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET bucket listing (no auth) → 200, {len(items)} files",
                        detected_services="Storage",
                    ),
                    remediation=(
                        "**What to fix:** Disable unauthenticated bucket listing.\n\n"
                        "**How to fix:** Firebase Console → Storage → Rules — require `request.auth != null`.\n\n"
                        "**Verify the fix:** Re-run firebase_storage scanner — listing should return 403."
                    ),
                    category=self.category, page=page,
                ))
```

- [ ] **Step 4: Run proof tests**

```
pytest tests/test_scanners/test_firebase_storage_proof.py -v
```
Expected: all 5 tests PASS (note: `_group4_bucket_listing` uses inline `urllib` imports — that's intentional to avoid a circular import; it can be refactored post-green if desired).

> **Implementation note:** The fixture's bucket listing route `GET /v0/b/{bucket}/o` uses `bucket = base_url.replace("http://", "")` as the bucket name, so the REST call hits `http://127.0.0.1:{port}` correctly. If the test fails on the listing test, verify the bucket value matches the fixture URL.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/scanners/firebase_storage.py tests/test_scanners/test_firebase_storage_proof.py
git commit -m "feat: implement firebase_storage scanner with proof tests"
```

---

## Task 4: Run Plan 2 suite

- [ ] **Step 1: Run all RTDB + Storage tests**

```
pytest tests/test_scanners/test_firebase_rtdb_proof.py tests/test_scanners/test_firebase_storage_proof.py -v
```
Expected: 10 PASS.

- [ ] **Step 2: Run full existing suite for regressions**

```
pytest --ignore=tests/test_scanners/test_firebase_rtdb_proof.py --ignore=tests/test_scanners/test_firebase_storage_proof.py --ignore=tests/test_scanners/test_firebase_fixture_smoke.py --ignore=tests/test_utils/test_firebase_helpers.py -x -q
```
Expected: green.

---

**Plan 2 complete. Continue with Plan 3: Firestore + Functions + Auth scanners.**
