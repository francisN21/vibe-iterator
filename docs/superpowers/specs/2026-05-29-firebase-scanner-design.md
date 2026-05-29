# Firebase Scanner Design Spec

- **Date:** 2026-05-29
- **Status:** Approved — ready for implementation
- **Author:** Senior Software Architect (design), Francisco (approval)
- **Scope:** Add first-class Firebase runtime security scanning to vibe-iterator, mirroring the depth of the existing Supabase support.
- **Related docs:** `CLAUDE.md`, `docs/SCANNERS.md`, `docs/ENGINE.md`, `docs/CONFIG.md`, `docs/DASHBOARD.md`, `docs/STANDARDS.md`, `docs/ADDING_SCANNERS.md`

---

## 1. Summary

vibe-iterator currently runs deep, exploit-proving security scans against Supabase-backed web apps. It launches Selenium + Chrome DevTools Protocol (CDP), authenticates as a real test user, tampers with client-side state and network traffic, and produces findings that demonstrate a vulnerability is *actually exploitable* — not merely theoretically present.

This spec extends that capability to **Firebase**. It adds five new scanners (Firestore, Realtime Database, Storage, Authentication, Cloud Functions), one shared helper module (`firebase_helpers.py`), a new `firebase` stage, a Firebase-specific dashboard panel, a dedicated vulnerable fixture app, and a full proof-test suite.

The design intentionally re-uses every existing extension point so that no engine, routing, scoring, reporting, or WebSocket change is required:

- Scanners subclass `BaseScanner` and implement `run(session, listeners, config) -> list[Finding]`.
- They are gated by `requires_stack = ["firebase"]`, so the engine's existing stack-check in `ScanRunner.run()` skips them when the detected backend is not Firebase.
- Scanner selection from the dashboard re-uses the existing `scanner_overrides` mechanism on `POST /api/scan/start`.
- Findings flow through the existing event system, scoring, results dashboard, and report generator unchanged.

---

## 2. Goals & Non-Goals

### 2.1 Goals

1. Detect and prove the most common Firebase misconfigurations that "vibe-coded" apps ship with: open Security Rules, IDOR via predictable document paths, unauthenticated reads/writes, mass-assignment of privileged fields, unauthenticated Cloud Functions, and account-enumeration vectors.
2. Mirror the Supabase scanner architecture exactly so the codebase stays consistent and contributors can pattern-match.
3. Require zero changes to the engine (`runner.py`), the WebSocket layer, the REST routes, the scoring system, the report generator, `scan.html`, and `results.html`.
4. Be safe by construction: every write probe is namespaced with a `vibe_iterator_probe_` prefix and cleaned up in `try/finally`; failures degrade gracefully and never crash a scan.
5. Provide a complete, hermetic proof-test suite (no real Firebase project, no network egress) using a `ThreadingHTTPServer`-based fixture, identical in spirit to the existing `VulnerableApp`.

### 2.2 Non-Goals

1. **No duplication of generic scanners.** `firebase_auth.py` covers Firebase-specific vectors only (Identity Toolkit endpoints, custom claims, anonymous auth, ID-token exposure). Generic session/login/token logic stays in `auth_check.py`, which already runs regardless of stack.
2. **No new API routes.** The existing `scanner_overrides` flow is sufficient.
3. **No write of destructive data.** Probes write tiny, clearly-labeled, self-cleaning artifacts only. We never delete, overwrite, or mutate pre-existing user data.
4. **No Firebase Admin SDK usage.** All probes operate through the public client surface (REST endpoints + the in-page Firebase JS SDK via CDP), exactly as a real attacker would. We never require service-account credentials.
5. **No support for App Check bypass** in this iteration. If App Check blocks probes, we report it as a positive defensive signal (INFO), not a finding.

---

## 3. Architecture Overview

### 3.1 New & modified files

```
vibe_iterator/
├── scanners/
│   ├── firebase_firestore.py        # NEW — Firestore Security Rules / IDOR / mass assignment
│   ├── firebase_rtdb.py             # NEW — Realtime Database rules / open read+write
│   ├── firebase_storage.py          # NEW — Storage rules / cross-user access / listing
│   ├── firebase_auth.py             # NEW — Identity Toolkit vectors / custom claims / token exposure
│   └── firebase_functions.py        # NEW — Cloud Functions auth / CORS / sensitive data
└── utils/
    └── firebase_helpers.py          # NEW — config extraction, CDP snippets, REST builders

vibe_iterator/engine/
└── runner.py                        # MODIFIED — register 5 scanners in _SCANNER_MODULE_MAP

vibe_iterator/server/static/
├── index.html                       # MODIFIED — add Firebase panel markup
└── js/app.js                        # MODIFIED — add Firebase panel logic

vibe-iterator.config.yaml            # MODIFIED — add `firebase` stage (+ .config.yaml.example)

tests/
├── fixtures/vulnerable_app/
│   └── firebase_app.py              # NEW — Firebase vulnerable fixture (ThreadingHTTPServer)
└── test_scanners/
    ├── test_firebase_firestore_proof.py   # NEW
    ├── test_firebase_rtdb_proof.py        # NEW
    ├── test_firebase_storage_proof.py     # NEW
    ├── test_firebase_auth_proof.py        # NEW
    ├── test_firebase_functions_proof.py   # NEW
    └── ../test_utils/test_firebase_helpers.py   # NEW (under tests/test_utils/)
```

> Implementation note: place `test_firebase_helpers.py` under `tests/test_utils/` to match the existing `tests/test_utils/test_supabase_helpers.py` location. The bracketed path above is shorthand for the same.

### 3.2 Data flow

```
Dashboard (index.html Firebase panel)
        │  POST /api/scan/start { stage: "firebase", scanner_overrides: [...checked] }
        ▼
server/routes.py  ──(validates stage + overrides against config.scanners_for_stage)──►
        ▼
engine/runner.py  ScanRunner.run("firebase")
        │  1. resolve scanner list (stage scanners ∩ overrides)
        │  2. launch browser, attach network/console/storage listeners
        │  3. login as account 1 (auth_mod.login)
        │  4. crawl pages → populate NetworkListener with Firebase traffic
        │  5. for each scanner: stack-check (requires_stack == ["firebase"]) then run()
        ▼
firebase_*.py Scanner.run(session, listeners, config) -> list[Finding]
        │  uses firebase_helpers.* (CDP snippets + REST builders)
        ▼
Findings → ScanResult → events → WebSocket → scan.html / results.html → report generator
```

### 3.3 Why this fits the existing engine with no engine logic change

`ScanRunner.run()` already performs the stack gate (`runner.py` lines ~293–301):

```python
if scanner.requires_stack != ["any"] and \
        self.config.stack.backend not in scanner.requires_stack:
    reason = f"Requires {scanner.requires_stack[0]} stack — detected: {self.config.stack.backend}"
    self._emit("scanner_skipped", {"scanner_name": scanner.name, "reason": reason})
    ...
    continue
```

Setting `requires_stack = ["firebase"]` on each new scanner means they are automatically skipped on Supabase/custom targets and run on Firebase targets. Detection of `backend: firebase` already exists per `docs/CONFIG.md`:

| Signal | Sets |
|---|---|
| Requests to `*.firebaseapp.com` or `googleapis.com/identitytoolkit` | `backend: firebase` |
| Firebase Storage requests (`firebasestorage.googleapis.com`) | `storage: firebase` |

The only required engine change is registering the five new scanner names in `_SCANNER_MODULE_MAP` (see §6).

---

## 4. Configuration Changes

### 4.1 New `firebase` stage

Add to `vibe-iterator.config.yaml` (and the `.example`) under `stages:`:

```yaml
stages:
  # ... existing dev / pre-deploy / post-deploy / all stages ...
  firebase:
    scanners: [firebase_firestore, firebase_rtdb, firebase_storage, firebase_auth, firebase_functions]
    description: "Firebase-specific security audit"
```

This stage is intentionally Firebase-only. The five scanners also list themselves in the generic `pre-deploy`, `post-deploy`, and (for `firebase_auth`) `dev` stages via their `stages` attribute (see registry in §5), so they participate in normal staged scans on Firebase targets too. The dedicated `firebase` stage exists so the dashboard's Firebase panel can target exactly these scanners regardless of which generic stage a user might otherwise pick.

> Stage scoring: `STAGE_MAX_DEDUCTIONS` in `runner.py` has no entry for `"firebase"`. `compute_score()` falls back to the default of `200` (`stage_max = STAGE_MAX_DEDUCTIONS.get(stage, 200)`). This is the desired behavior — no scoring change required. (If a tuned ceiling is later wanted, add `"firebase": 200` explicitly; it is not required for this spec.)

### 4.2 Stack config

No schema change. `StackConfig.backend` already accepts `"firebase"`, `StackConfig.auth` accepts `"firebase-auth"`, and `StackConfig.storage` accepts `"firebase"` (per `config.py` and `docs/CONFIG.md`). Detection remains auto (network-signal based) or manual via `vibe-iterator.config.yaml`:

```yaml
stack:
  backend: firebase        # supabase | firebase | custom
  auth: firebase-auth      # supabase-auth | firebase-auth | custom
  storage: firebase        # supabase | firebase | s3 | custom
```

### 4.3 Config fields consumed by Firebase scanners

Firebase scanners derive their connection details at runtime, not from `.env`. They obtain `apiKey`, `projectId`, `databaseURL`, `storageBucket`, and `authDomain` via `firebase_helpers.extract_firebase_config(session)` (CDP) with a passive fallback to `detect_firebase_config(network_events)`. This avoids forcing the user to hand-enter Firebase keys. The scanners read these existing `Config` attributes only:

| `Config` attribute | Use |
|---|---|
| `config.target` | The `page` field on every Finding; default URL for evidence. |
| `config.stack.backend` | Passed as `stack` into `build_llm_prompt`; used in remediation phrasing. |
| `config.second_account_configured` | Gate for cross-user IDOR checks (firebase_firestore, firebase_storage). |
| `config.scanner_timeout_seconds` | Enforced by the engine, not the scanner; probes must stay well under it. |

---

## 5. Scanner Registry Additions

| Scanner (`name`) | `category` | `stages` | `requires_stack` | `requires_second_account` |
|---|---|---|---|---|
| `firebase_firestore` | `Access Control` | `["pre-deploy", "post-deploy"]` | `["firebase"]` | `True` |
| `firebase_rtdb` | `Access Control` | `["pre-deploy", "post-deploy"]` | `["firebase"]` | `False` |
| `firebase_storage` | `Access Control` | `["pre-deploy", "post-deploy"]` | `["firebase"]` | `False` |
| `firebase_auth` | `Authentication` | `["dev", "pre-deploy", "post-deploy"]` | `["firebase"]` | `False` |
| `firebase_functions` | `API Security` | `["pre-deploy", "post-deploy"]` | `["firebase"]` | `False` |

Notes:

- `firebase_firestore.requires_second_account = True` is used **only** for the cross-user IDOR check group. When no second account is configured, that group silently skips (INFO emit); all other groups still run. This mirrors `rls_bypass`, which sets `requires_second_account = True` yet runs its unauthenticated and over-permissive checks regardless.
- `firebase_storage` cross-user check (Group 3) also benefits from a second account but does not set `requires_second_account = True`, because its primary value (Groups 1, 2, 4) does not need one. When no second account exists, Group 3 silently skips. Setting the flag is reserved for scanners whose headline check needs it.
- The engine's `requires_second_account` flag controls only the `ScanResult.second_account_used` accounting; it does not block a scanner from running.

---

## 6. Engine Registration

In `vibe_iterator/engine/runner.py`, extend `_SCANNER_MODULE_MAP`:

```python
_SCANNER_MODULE_MAP: dict[str, str] = {
    "data_leakage":       "vibe_iterator.scanners.data_leakage",
    "rls_bypass":         "vibe_iterator.scanners.rls_bypass",
    "tier_escalation":    "vibe_iterator.scanners.tier_escalation",
    "bucket_limits":      "vibe_iterator.scanners.bucket_limits",
    "auth_check":         "vibe_iterator.scanners.auth_check",
    "client_tampering":   "vibe_iterator.scanners.client_tampering",
    "sql_injection":      "vibe_iterator.scanners.sql_injection",
    "cors_check":         "vibe_iterator.scanners.cors_check",
    "xss_check":          "vibe_iterator.scanners.xss_check",
    "api_exposure":       "vibe_iterator.scanners.api_exposure",
    # --- Firebase ---
    "firebase_firestore": "vibe_iterator.scanners.firebase_firestore",
    "firebase_rtdb":      "vibe_iterator.scanners.firebase_rtdb",
    "firebase_storage":   "vibe_iterator.scanners.firebase_storage",
    "firebase_auth":      "vibe_iterator.scanners.firebase_auth",
    "firebase_functions": "vibe_iterator.scanners.firebase_functions",
}
```

Each module must expose a class named exactly `Scanner` (the `_load_scanner` convention). No other engine change is required.

---

## 7. `firebase_helpers.py` — Shared Utilities

Lives at `vibe_iterator/utils/firebase_helpers.py`. Mirrors `supabase_helpers.py` conventions: module-level pure functions, no I/O at import time, defensive try/except inside each function, and a shared `truncate()` for evidence safety.

### 7.1 Module header & shared constants

```python
"""Shared utilities for Firebase-specific scanners."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

# Probe namespace — every artifact this tool creates uses this prefix so
# cleanup is unambiguous and accidental collisions are impossible.
PROBE_PREFIX = "vibe_iterator_probe_"

# Default per-request network timeout (seconds). Keep small so a single
# unreachable endpoint cannot blow the scanner's overall timeout.
REQUEST_TIMEOUT = 6

# Identity Toolkit base (Firebase Auth REST API).
IDENTITY_TOOLKIT_BASE = "https://identitytoolkit.googleapis.com/v1"

# Cloud Functions / Cloud Run host patterns used for endpoint discovery.
_FUNCTION_HOST_RE = re.compile(
    r"https://([a-z0-9-]+)\.cloudfunctions\.net|https://([a-z0-9-]+)\.([a-z0-9-]+)\.run\.app"
)

# Firebase ID tokens are JWTs (same eyJ... shape Supabase uses).
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
```

### 7.2 Config extraction

```python
def extract_firebase_config(session: Any) -> dict:
    """Read the live Firebase app config from the page via CDP.

    Tries, in order:
      1. window.firebase.apps[0].options          (compat / namespaced SDK)
      2. window.__FIREBASE_DEFAULTS__ / __firebase_defaults__ (modular SDK env)
      3. Any global object exposing {apiKey, projectId, ...}  (manual config)

    Returns a dict with whatever keys were found:
      { apiKey, projectId, databaseURL, storageBucket, authDomain }
    Missing keys are simply absent. Returns {} if the SDK/config is absent
    or CDP evaluation fails. Never raises.
    """
```

CDP snippet executed by `extract_firebase_config` (string the function feeds to `session.evaluate`):

```javascript
(() => {
  try {
    // 1. compat/namespaced SDK
    if (window.firebase && window.firebase.apps && window.firebase.apps.length) {
      const o = window.firebase.apps[0].options || {};
      return {
        apiKey: o.apiKey, projectId: o.projectId, databaseURL: o.databaseURL,
        storageBucket: o.storageBucket, authDomain: o.authDomain
      };
    }
    // 2. modular SDK defaults
    const d = window.__FIREBASE_DEFAULTS__ || window.__firebase_defaults__;
    if (d && d.config) return d.config;
    if (d && d.projectId) return d;
    // 3. last resort: a manually-attached config object
    for (const k of ['firebaseConfig', '__firebaseConfig', 'FIREBASE_CONFIG']) {
      if (window[k] && window[k].projectId) return window[k];
    }
    return {};
  } catch (e) { return {}; }
})()
```

If the returned dict lacks `projectId`, the function attempts one passive fallback: it has the caller pass `listeners["network"].get_requests()` so it can call `detect_firebase_config(...)` on captured traffic, and also looks for the hosted init file `/__/firebase/init.json` among captured request URLs (the scanner fetches that URL via `urllib.request` and parses the JSON). Implementation detail: `extract_firebase_config` takes only `session`; the network fallback is invoked by the scanner explicitly if `extract_firebase_config` returns `{}` or a dict missing `projectId`.

```python
def detect_firebase_config(network_events: list[Any]) -> dict | None:
    """Passive: reconstruct firebaseConfig from captured network traffic.

    Looks at each captured request/response for:
      - URLs of the form https://<projectId>.firebaseio.com
      - URLs of the form https://<projectId>.firebaseapp.com
      - Storage bucket host <projectId>.appspot.com or firebasestorage URLs
      - identitytoolkit calls carrying ?key=<apiKey>
      - response bodies that are /__/firebase/init.json JSON payloads

    Returns a best-effort dict { apiKey, projectId, databaseURL,
    storageBucket, authDomain } or None if nothing Firebase-shaped is found.
    Never raises.
    """
```

### 7.3 ID-token extraction

```python
def get_firebase_id_token(session: Any) -> str | None:
    """Return the current user's Firebase ID token via CDP, or None.

    Handles both SDK shapes:
      - compat:  firebase.auth().currentUser.getIdToken(true)
      - modular: getAuth() currentUser (when exposed on window)
    Forces a refresh (true) so the token is valid for the probe window.
    Never raises; returns None if no user is signed in or SDK absent.
    """
```

CDP snippet:

```javascript
(async () => {
  try {
    if (window.firebase && window.firebase.auth) {
      const u = window.firebase.auth().currentUser;
      return u ? await u.getIdToken(true) : null;
    }
    // modular SDK: app may expose getAuth on a known global
    const auth = (window.__VIBE_AUTH__) ||
                 (window.getAuth && window.getAuth());
    if (auth && auth.currentUser) return await auth.currentUser.getIdToken(true);
    return null;
  } catch (e) { return null; }
})()
```

### 7.4 CDP snippet builders (in-page SDK path)

Each returns a JavaScript string for `session.evaluate`. All wrap in `try/catch` and return `{ data, error }` (read) or `{ ok, error }` (write) so the scanner can branch without exceptions.

```python
def build_firestore_read_snippet(collection: str, doc_id: str | None = None) -> str:
    """JS that reads a Firestore doc (if doc_id) or queries a collection.
    Uses the live page SDK + current user's auth automatically."""

def build_firestore_write_snippet(collection: str, doc_id: str, data: dict) -> str:
    """JS that writes `data` to collection/doc_id. doc_id MUST start with
    PROBE_PREFIX. Returns { ok, error }."""

def build_rtdb_read_snippet(path: str) -> str:
    """JS that reads `path` from the Realtime Database via the live SDK."""

def build_rtdb_write_snippet(path: str, data: dict) -> str:
    """JS that writes `data` to RTDB `path`. Path MUST contain PROBE_PREFIX."""

def build_storage_download_snippet(path: str) -> str:
    """JS that calls getDownloadURL(ref(path)) and fetches the bytes."""

def build_storage_upload_snippet(path: str, content_bytes: bytes) -> str:
    """JS that uploads content_bytes to Storage `path`. Path MUST contain
    PROBE_PREFIX. content_bytes is base64-encoded into the snippet."""
```

Representative implementation (Firestore read, compat SDK) so the shape is unambiguous:

```python
def build_firestore_read_snippet(collection: str, doc_id: str | None = None) -> str:
    safe_coll = collection.replace("'", "\\'")
    if doc_id:
        safe_doc = doc_id.replace("'", "\\'")
        return f"""
(async () => {{
  try {{
    const db = (window.firebase && window.firebase.firestore)
      ? window.firebase.firestore() : (window.__VIBE_DB__ || null);
    if (!db) return {{ error: 'Firestore SDK not found on window' }};
    const snap = await db.collection('{safe_coll}').doc('{safe_doc}').get();
    return {{ data: snap.exists ? snap.data() : null, exists: snap.exists }};
  }} catch (e) {{ return {{ error: e.message }}; }}
}})()
""".strip()
    return f"""
(async () => {{
  try {{
    const db = (window.firebase && window.firebase.firestore)
      ? window.firebase.firestore() : (window.__VIBE_DB__ || null);
    if (!db) return {{ error: 'Firestore SDK not found on window' }};
    const snap = await db.collection('{safe_coll}').limit(5).get();
    return {{ data: snap.docs.map(d => ({{ id: d.id, ...d.data() }})) }};
  }} catch (e) {{ return {{ error: e.message }}; }}
}})()
""".strip()
```

### 7.5 Direct REST request builders (no-SDK path)

These perform real HTTP via `urllib.request` (stdlib, already used by `rls_bypass`). Each returns a `(body: str, status: int | None)` tuple. On any network/parse error they return `("", None)` — never raise. When `id_token` is provided, an `Authorization: Bearer <id_token>` header is attached; otherwise no auth header is sent (the unauthenticated probe).

```python
def rest_firestore_get(project_id, collection, doc_id, id_token=None) -> tuple[str, int | None]:
    """GET https://firestore.googleapis.com/v1/projects/{project_id}
        /databases/(default)/documents/{collection}/{doc_id}"""

def rest_firestore_write(project_id, collection, doc_id, data, id_token=None) -> tuple[str, int | None]:
    """PATCH (create-or-update) the doc at .../documents/{collection}/{doc_id}.
    `data` is serialized to Firestore's typed-value JSON via _to_firestore_fields(data).
    doc_id MUST start with PROBE_PREFIX."""

def rest_rtdb_get(database_url, path, id_token=None) -> tuple[str, int | None]:
    """GET {database_url}/{path}.json  (path '' or '.' → root '/.json').
    Appends ?auth=<id_token> when a token is given (RTDB REST auth)."""

def rest_rtdb_write(database_url, path, data, id_token=None) -> tuple[str, int | None]:
    """PUT {database_url}/{path}.json with JSON body `data`.
    path MUST contain PROBE_PREFIX."""

def rest_storage_download(bucket, path, id_token=None) -> tuple[str, int | None]:
    """GET https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{urlencoded path}?alt=media"""

def rest_storage_upload(bucket, path, content, id_token=None) -> tuple[str, int | None]:
    """POST https://firebasestorage.googleapis.com/v0/b/{bucket}/o?name={urlencoded path}
    with raw body `content`. path MUST contain PROBE_PREFIX."""

def rest_functions_call(region, project_id, fn_name, payload, id_token=None) -> tuple[str, int | None]:
    """POST https://{region}-{project_id}.cloudfunctions.net/{fn_name}
    with JSON body `payload`."""
```

Representative implementation (RTDB GET) showing the exact error contract:

```python
def rest_rtdb_get(database_url: str, path: str, id_token: str | None = None) -> tuple[str, int | None]:
    base = (database_url or "").rstrip("/")
    seg = path.strip("/")
    url = f"{base}/{seg}.json" if seg else f"{base}/.json"
    if id_token:
        url += ("&" if "?" in url else "?") + f"auth={urllib.parse.quote(id_token)}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None
```

### 7.6 Internal helpers (private)

```python
def _to_firestore_fields(data: dict) -> dict:
    """Convert a flat Python dict to Firestore REST typed-value JSON:
       {"fields": {"role": {"stringValue": "admin"}, "is_premium": {"booleanValue": true}}}"""

def _from_firestore_fields(doc: dict) -> dict:
    """Inverse: flatten a Firestore REST document's typed values to plain dict."""

def discover_function_urls(network_events: list[Any]) -> list[str]:
    """Return unique cloudfunctions.net / run.app URLs seen in captured traffic."""

def find_id_tokens(text: str) -> list[str]:
    """Return JWT-shaped strings (Firebase ID tokens) found in text."""

def truncate(text: str, max_len: int = 300) -> str:
    """Truncate for safe inclusion in evidence dicts (mirrors supabase_helpers)."""
```

### 7.7 Write-safety contract

- Every write helper (`rest_firestore_write`, `rest_rtdb_write`, `rest_storage_upload`, and their CDP counterparts) requires the caller to pass a `doc_id`/`path`/`name` that begins with or contains `PROBE_PREFIX`. Helpers **assert** this and return `("", None)` if violated, so a coding mistake can never create a non-namespaced artifact.
- Helpers do **not** clean up; the *scanner* owns cleanup in `try/finally` (so cleanup runs even when an assertion mid-probe fails). The corresponding delete helpers are:

```python
def rest_firestore_delete(project_id, collection, doc_id, id_token=None) -> tuple[str, int | None]:
def rest_rtdb_delete(database_url, path, id_token=None) -> tuple[str, int | None]:
def rest_storage_delete(bucket, path, id_token=None) -> tuple[str, int | None]:
```

---

## 8. Scanner Specifications

All five scanners share this skeleton (matching `rls_bypass.py`):

```python
class Scanner(BaseScanner):
    name = "firebase_..."
    category = "..."
    stages = [...]
    requires_stack = ["firebase"]
    requires_second_account = ...   # only firebase_firestore = True

    def run(self, session, listeners, config) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        stack = config.stack.backend  # "firebase"

        cfg = self._resolve_config(session, network)
        if not cfg or not cfg.get("projectId"):
            self.emit(_runner_of(session), "Firebase config not detected — skipping", level="warn")
            return []

        # run each check group inside its own try/except so one failure
        # does not abort the remaining groups
        self._group_1(...); self._group_2(...); ...
        return findings
```

> `self.emit(...)` requires a `runner` reference. The engine calls `scanner.run(...)` but `BaseScanner.emit(runner, message, level)` takes the runner explicitly. To stay consistent with existing scanners, **emit via the engine's progress mechanism the same way existing scanners do**: existing scanners that emit do so by calling `self.emit(runner, msg)` where `runner` is obtained from the listeners bundle. Concretely, follow the convention already used in the codebase: pass progress messages through `self.emit`. Where a scanner currently has no runner handle (e.g. `rls_bypass` does not emit), Firebase scanners will accept the same `listeners` dict and use `listeners.get("runner")` if present; if absent, emit is a no-op (the `emit` method already swallows exceptions). This keeps behavior identical in tests where `listeners` is a `MagicMock`.

Every Finding is constructed with `self.new_finding(...)` and `self.build_llm_prompt(...)` exactly as `rls_bypass` does, and `page` is set to the relevant URL (`config.target` or the discovered endpoint).

### 8.1 `firebase_firestore.py` — Access Control

Constants:

```python
_COMMON_COLLECTIONS = ["users", "profiles", "orders", "payments", "admin",
                       "config", "settings", "subscriptions", "messages", "posts"]
_PRIVILEGE_FIELDS = {"role": "admin", "is_admin": True, "is_premium": True,
                     "subscription_tier": "enterprise", "credits": 999999}
```

| Group | Checks | Severity |
|---|---|---|
| 1 — Unauthenticated Access | For each discovered/common collection, `rest_firestore_get(project_id, coll, <known/probed doc>, id_token=None)`. A `200` with document data → rules allow public read. Also a CDP read attempt with no auth context (sign out first if a no-auth context is cheaply available; otherwise REST is authoritative). Expected: `403`. | HIGH (CRITICAL if collection name in `{users, payments, admin, profiles}`) |
| 2 — Overly Permissive Rules (IDOR) | Requires a second account. Authenticate as account 2 (`auth_mod.login(session, config, account=2)`), capture account 1's uid first (from its ID token's `user_id`/`sub` claim). Attempt authenticated REST read of `users/<uid1>` and a write to `users/<uid1>` (probe doc field). Success → IDOR. Also pattern-match `403`/`200` bodies for the signature of `allow read, write: if true`. | HIGH (CRITICAL on write success or on sensitive collections) |
| 3 — Mass Assignment | As account 2 (or account 1 if no second account), write `users/<PROBE_PREFIX+uid>` containing `_PRIVILEGE_FIELDS`, then read it back. If the server persisted any privileged field, mass assignment is possible. Cleaned up in `finally`. | MEDIUM |
| 4 — Collection Enumeration | `rest_firestore_get` (list endpoint) for each name in `_COMMON_COLLECTIONS` with `id_token=None`. Any name returning data instead of `403` is flagged. Reports the set of enumerable collections in one finding. | MEDIUM |

Cleanup: Group 2/3 writes use `PROBE_PREFIX` doc ids and are deleted via `rest_firestore_delete` in `finally`. The primary session is always restored with `auth_mod.login(session, config, account=1)` in `finally`, mirroring `rls_bypass`.

Evidence: Access Control structure (see §10.1). `second_account_used` reflects whether account 2 was actually engaged.

### 8.2 `firebase_rtdb.py` — Access Control

Constants:

```python
_COMMON_PATHS = ["users", "config", "admin", "settings", "messages", "profiles", "orders"]
```

`databaseURL` is taken from the resolved config; if absent, the scanner derives `https://{projectId}-default-rtdb.firebaseio.com` and `https://{projectId}.firebaseio.com` as candidates and probes both.

| Group | Checks | Severity |
|---|---|---|
| 1 — Unauthenticated Access | `rest_rtdb_get(database_url, "", id_token=None)` (root `/.json`) and each `_COMMON_PATHS` entry. A `200` with non-null data → public read. Expected: `401`/permission-denied. | CRITICAL |
| 2 — Unauthenticated Write | `rest_rtdb_write(database_url, f"{PROBE_PREFIX}canary", {"vibe": "iterator", "ts": <int>}, id_token=None)`. A `200` → public write. **Always** `rest_rtdb_delete(database_url, f"{PROBE_PREFIX}canary")` in `finally`. | CRITICAL |
| 3 — Data Enumeration | `rest_rtdb_get(database_url, "?shallow=true")` against root with no token. If a full top-level key list is returned (object of keys → `true`), the DB leaks its structure to anonymous users. | MEDIUM |
| 4 — Overly Permissive Auth Rules | If a token is available (account 1), authenticated read of another user's path (`users/<some-other-uid>` if discoverable, else a probed sibling). Permissive responses indicate `.read: true`/`.write: true`. | HIGH |

Evidence: Access Control structure (§10.1).

### 8.3 `firebase_storage.py` — Access Control

`bucket` taken from resolved config `storageBucket` (e.g. `my-app.appspot.com`); fallback `f"{projectId}.appspot.com"`.

Constants:

```python
_COMMON_FILE_PATHS = ["public/test.txt", "uploads/", "avatars/", "images/",
                      "users/", "private/", "documents/"]
_PROBE_FILE = f"{PROBE_PREFIX}canary.txt"
_PROBE_CONTENT = b"vibe-iterator probe; safe to delete"
```

| Group | Checks | Severity |
|---|---|---|
| 1 — Unauthenticated Download | `rest_storage_download(bucket, path, id_token=None)` for each common path. A `200` with bytes on a non-`public/` path → over-permissive read rules. Expected: `403`. | HIGH |
| 2 — Unauthenticated Upload | `rest_storage_upload(bucket, _PROBE_FILE, _PROBE_CONTENT, id_token=None)`. A `200`/`2xx` → public write. **Always** `rest_storage_delete(bucket, _PROBE_FILE)` in `finally`. | HIGH |
| 3 — Cross-User Path Access | If second account configured: authenticate as account 2, attempt `rest_storage_download` of a path scoped to account 1's uid (`users/<uid1>/...`). Success → cross-user read. Silently skips with INFO emit when no second account. | HIGH |
| 4 — Bucket Listing | `GET https://firebasestorage.googleapis.com/v0/b/{bucket}/o` (list objects) with no token. A `200` JSON object containing an `items` array → open bucket enumeration. | MEDIUM |

Evidence: Access Control structure (§10.1).

### 8.4 `firebase_auth.py` — Authentication (Firebase-specific only)

`apiKey` taken from resolved config; required for all Identity Toolkit calls (`?key={apiKey}`). If `apiKey` is missing, the scanner emits a warn and returns `[]`.

| Group | Checks | Severity |
|---|---|---|
| 1 — Anonymous Auth Abuse | POST `IDENTITY_TOOLKIT_BASE/accounts:signUp?key={apiKey}` with `{"returnSecureToken": true}` (anonymous sign-in). A `200` returning an `idToken` → anonymous auth is enabled. If enabled, use that token to retry Group-1 Firestore/RTDB reads of common collections; any data returned demonstrates real anonymous data access. | HIGH |
| 2 — Email Enumeration | POST `IDENTITY_TOOLKIT_BASE/accounts:createAuthUri?key={apiKey}` with `{"identifier": "<test email>", "continueUri": config.target}`. A response whose `registered` flag (or `allProviders` content) differs between a known-registered email (the test account) and a random non-existent email confirms enumeration. | LOW |
| 3 — Custom Claims Exposure | Decode the current ID token payload (base64, no verification) and inspect for client-trusted privilege claims (`admin`, `role`, `is_premium`). Then attempt to forge a tampered claim: re-sign is impossible, so instead replay a request that *should* require the privilege using the unmodified token while asserting the app does not trust a client-set field. If the app reads privilege from a *client-mutable* location (e.g. a Firestore `users/<uid>.role` the user can write — cross-check with firestore Group 3) rather than verified custom claims, flag it. | HIGH |
| 4 — ID Token Exposure | Inspect captured network events (`network.get_requests()`) for ID tokens appearing in URL query params or response bodies (`find_id_tokens`). Inspect `listeners["storage"]` snapshot for tokens persisted in `localStorage`. Tokens in URLs/response bodies are a leakage vector. | MEDIUM |
| 5 — fetchSignInMethodsForEmail Leakage | POST `accounts:createAuthUri` (the endpoint `fetchSignInMethodsForEmail` uses) with a probe email; a non-empty `signinMethods`/`allProviders` for an arbitrary address confirms account-existence disclosure. | LOW |

Notes:
- This scanner sends auth-probe POSTs only to Google's public Identity Toolkit API using the app's own public `apiKey`. It never creates persistent accounts beyond an anonymous session, which it discards (it does not call `accounts:delete`; anonymous sessions are ephemeral and harmless). If a real account is inadvertently created in Group 1, the scanner records the local id token only and never stores credentials.
- Groups 3 and 4 are read/inspection only; no writes.

Evidence: Authentication structure (see §10.2).

### 8.5 `firebase_functions.py` — API Security

| Group | Checks | Severity |
|---|---|---|
| 1 — Unauthenticated HTTPS Functions | `discover_function_urls(network.get_requests())` finds `cloudfunctions.net`/`run.app` URLs actually used by the app. Replay each with `rest_functions_call(..., id_token=None)` (or a direct GET/POST with no auth header). Expected: `401`/`403`. A `200` → function is callable unauthenticated. | HIGH |
| 2 — Sensitive Data in Responses | For each function response captured (or obtained in Group 1), scan the body for tokens (`find_id_tokens`), API-key shapes, emails/PII patterns, and internal schema markers (`stack`, `traceback`, `__proto__`, internal table names). | MEDIUM (HIGH if tokens/keys/PII present) |
| 3 — CORS Misconfiguration | Issue an `OPTIONS`/`GET` to each discovered function with `Origin: https://evil.example`. If the response echoes `Access-Control-Allow-Origin: *` (or reflects the evil origin) **and** sets `Access-Control-Allow-Credentials: true`, that is an exploitable CORS misconfiguration. | HIGH |
| 4 — Admin Function Exposure | Probe common sensitive function names by name against `https://{region}-{projectId}.cloudfunctions.net/{name}` for `name in {admin, deleteUser, setRole, createAdmin, grantAdmin, resetPassword, exportData}` with no auth. Any non-`401/403/404` (especially `200`) is flagged. Region defaults to `us-central1` plus any region seen in discovered URLs. | HIGH |

Evidence: API Security structure (see §10.3).

---

## 9. Severity Mapping (consolidated)

| Scanner | Group | Severity |
|---|---|---|
| firebase_firestore | 1 Unauthenticated Access | HIGH (CRITICAL on sensitive collections) |
| firebase_firestore | 2 Overly Permissive / IDOR | HIGH (CRITICAL on write / sensitive collection) |
| firebase_firestore | 3 Mass Assignment | MEDIUM |
| firebase_firestore | 4 Collection Enumeration | MEDIUM |
| firebase_rtdb | 1 Unauthenticated Access | CRITICAL |
| firebase_rtdb | 2 Unauthenticated Write | CRITICAL |
| firebase_rtdb | 3 Data Enumeration | MEDIUM |
| firebase_rtdb | 4 Overly Permissive Auth Rules | HIGH |
| firebase_storage | 1 Unauthenticated Download | HIGH |
| firebase_storage | 2 Unauthenticated Upload | HIGH |
| firebase_storage | 3 Cross-User Path Access | HIGH |
| firebase_storage | 4 Bucket Listing | MEDIUM |
| firebase_auth | 1 Anonymous Auth Abuse | HIGH |
| firebase_auth | 2 Email Enumeration | LOW |
| firebase_auth | 3 Custom Claims Exposure | HIGH |
| firebase_auth | 4 ID Token Exposure | MEDIUM |
| firebase_auth | 5 fetchSignInMethodsForEmail Leakage | LOW |
| firebase_functions | 1 Unauthenticated HTTPS Functions | HIGH |
| firebase_functions | 2 Sensitive Data in Responses | MEDIUM (HIGH if tokens/keys/PII) |
| firebase_functions | 3 CORS Misconfiguration | HIGH |
| firebase_functions | 4 Admin Function Exposure | HIGH |

All severities use the `Severity` enum from `vibe_iterator/scanners/base.py` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

---

## 10. Evidence Structures

These are passed verbatim as the `evidence` dict to `self.new_finding(...)`. Always run user-controlled or token values through `truncate()` before inclusion.

### 10.1 Access Control (firebase_firestore, firebase_rtdb, firebase_storage)

```python
{
    "action_attempted": "GET firestore users/<uid1> as user2",   # human-readable
    "auth_context": "unauthenticated" | "authenticated as uid: <uid>",
    "request": {
        "method": "GET",                      # or PUT / POST / PATCH
        "url": "https://firestore.googleapis.com/v1/projects/<pid>/databases/(default)/documents/users/<uid1>",
        "headers": {"Authorization": "Bearer <redacted>"},   # token never stored raw
        "body": None,                         # or a truncated JSON string for writes
    },
    "response": {
        "status": 200,
        "body_excerpt": "...truncate(body, 300)...",
    },
    "expected_response": "403 Forbidden",
    "actual_response": "200 OK with data",
    "second_account_used": True,              # bool
}
```

### 10.2 Authentication (firebase_auth)

```python
{
    "check_group": "Anonymous Auth Abuse",    # the Group name
    "check_name": "Anonymous sign-in enabled then read users collection",
    "evidence_type": "request_replay" | "storage_inspection" | "response_analysis",
    "observed_value": "anonymous idToken issued; read 5 rows from /users",
    "expected_behavior": "anonymous sign-in disabled OR no data accessible to anon",
    "request": {
        "method": "POST",
        "url": "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<redacted>",
        "headers": {"Content-Type": "application/json"},
        "body": '{"returnSecureToken": true}',
    },
    "response": {
        "status": 200,
        "body_excerpt": "...truncate(body, 300)...",
    },
}
```

### 10.3 API Security (firebase_functions)

```python
{
    "endpoint": "POST https://us-central1-myapp.cloudfunctions.net/setRole",
    "test_performed": "replay_without_auth",
    "request": {
        "method": "POST",
        "url": "https://us-central1-myapp.cloudfunctions.net/setRole",
        "headers": {},
        "body": '{"uid": "vibe_iterator_probe_uid", "role": "admin"}',
    },
    "response": {
        "status": 200,
        "body_excerpt": "...truncate(body, 300)...",
    },
    "expected_response": "401 Unauthorized",
}
```

---

## 11. LLM Fix Prompt

Each Finding's `llm_prompt` is generated at construction time. Because Firebase remediation differs from the generic Supabase-flavored `BaseScanner.build_llm_prompt`, Firebase scanners build the prompt from a **Firebase-specific template string** (constructed inline, then passed as `llm_prompt=` to `new_finding`). The template:

```
You are a security expert helping me fix a vulnerability in my Firebase web application.

VULNERABILITY: {title}
SEVERITY: {severity}
SCANNER: {scanner_name}
PAGE: {page_url}
CATEGORY: {category}

WHAT WAS FOUND:
{plain_english_description}

EVIDENCE:
{evidence_summary}

YOUR TASK:
Fix the vulnerability described above in my codebase.

1. Explain the root cause
2. Show the specific Firebase Security Rules change or code change needed
3. Show the exact Firebase Console setting or rules config to apply
4. Confirm what to test after applying the fix

My stack: Firebase ({detected_services})
```

Substitution rules:
- `{severity}` = `severity.value.upper()` (e.g. `HIGH`).
- `{scanner_name}` = `self.name`.
- `{page_url}` = the Finding `page`.
- `{category}` = `self.category`.
- `{plain_english_description}` = the same string used for the Finding `description`.
- `{evidence_summary}` = a 2–4 line human summary (the same compact summary passed to evidence-summary builders elsewhere), not the raw evidence dict.
- `{detected_services}` = comma-joined list of the Firebase services this scan touched, derived from the resolved config and which scanners ran, e.g. `Firestore, Storage, Auth`. If only the current scanner's service is known, use that single service (e.g. `Firestore`).

Implementation: add a small module-level helper `build_firebase_llm_prompt(*, title, severity, scanner, page, category, description, evidence_summary, detected_services)` inside `firebase_helpers.py` returning the filled template. Each scanner calls it instead of `BaseScanner.build_llm_prompt`.

---

## 12. Remediation Text

Each Finding's `remediation` field is a structured Markdown block (same format `rls_bypass` uses: `**What to fix:**` / `**How to fix:**` / `**Verify the fix:**`). Per-service guidance:

- **Firestore:** Provide the corrected `firestore.rules`, e.g.
  ```
  match /users/{uid} {
    allow read, write: if request.auth != null && request.auth.uid == uid;
  }
  ```
  Console path: Firebase Console → Firestore Database → Rules.
- **RTDB:** Provide corrected `database.rules.json`, e.g.
  ```json
  { "rules": { "users": { "$uid": {
      ".read": "auth != null && auth.uid === $uid",
      ".write": "auth != null && auth.uid === $uid" } } } }
  ```
  Console path: Realtime Database → Rules.
- **Storage:** Provide corrected `storage.rules`, e.g.
  ```
  match /users/{uid}/{file=**} {
    allow read, write: if request.auth != null && request.auth.uid == uid;
  }
  ```
  Console path: Storage → Rules.
- **Auth:** Console → Authentication → Sign-in method (disable Anonymous if unused); enable email-enumeration protection (Authentication → Settings → "Email enumeration protection"). For custom-claims trust issues: move privilege to verified custom claims set by a trusted backend (`admin.auth().setCustomUserClaims`), never client-writable docs.
- **Functions:** Enforce auth inside the function (`context.auth` for callable, verify `Authorization` Bearer ID token for HTTPS); restrict CORS to known origins; never return tokens/PII. Console/CLI path: function source + `firebase deploy --only functions`.

Every remediation ends with a concrete **Verify the fix** line instructing the user to re-run the relevant Firebase scanner and confirm the probe now returns `403`/`401`/permission-denied.

---

## 13. Dashboard — Firebase Panel

### 13.1 `index.html`

Add a Firebase panel that renders only when the detected stack backend is `firebase`. The panel sits alongside the existing stage selector. Markup target (hidden by default; `initFirebasePanel()` unhides it when config indicates Firebase):

```html
<section id="firebase-panel" class="panel firebase-panel" hidden>
  <header class="firebase-panel__head">
    <span class="firebase-panel__icon">⚡</span>
    <h2>FIREBASE SECURITY SCAN</h2>
    <p class="firebase-panel__detected">
      Detected: <span id="fb-project-id">—</span> · firebaseio.com
    </p>
  </header>

  <p class="firebase-panel__label">Select services to scan:</p>

  <div class="firebase-panel__grid">
    <label><input type="checkbox" class="fb-svc" value="firebase_firestore" checked> Firestore Rules</label>
    <label><input type="checkbox" class="fb-svc" value="firebase_rtdb"      checked> Realtime Database</label>
    <label><input type="checkbox" class="fb-svc" value="firebase_storage"   checked> Storage Rules</label>
    <label><input type="checkbox" class="fb-svc" value="firebase_auth"      checked> Authentication</label>
    <label><input type="checkbox" class="fb-svc" value="firebase_functions" checked> Cloud Functions</label>
  </div>

  <div class="firebase-panel__actions">
    <button id="fb-select-all" type="button" class="btn btn--ghost">SELECT ALL</button>
    <button id="fb-scan" type="button" class="btn btn--primary">▶ SCAN FIREBASE</button>
  </div>
</section>
```

Rendered layout:

```
┌─────────────────────────────────────────────────────────┐
│  ⚡ FIREBASE SECURITY SCAN                                │
│  Detected: {projectId} · firebaseio.com                  │
│                                                          │
│  Select services to scan:                                │
│                                                          │
│  ☑ Firestore Rules      ☑ Realtime Database              │
│  ☑ Storage Rules        ☑ Authentication                 │
│  ☑ Cloud Functions                                       │
│                                                          │
│  [  SELECT ALL  ]              [ ▶ SCAN FIREBASE ]       │
└──────────────────────────────────────────────────────────┘
```

Behavior:
- All five checkboxes default to `checked`.
- `SELECT ALL` toggles every checkbox on; if all are already on it toggles all off (acts as a select-all / clear-all toggle).
- `SCAN FIREBASE` is disabled (dimmed via a `disabled` attribute / `is-disabled` class) when zero checkboxes are checked.
- Clicking `SCAN FIREBASE` POSTs to `/api/scan/start` then navigates to `scan.html` — identical to the existing stage-launch flow.

### 13.2 `app.js`

Add three functions, wired on `DOMContentLoaded`:

```javascript
// Reads detected stack/config (from the existing config endpoint the home page
// already calls), shows the Firebase panel when backend === "firebase",
// fills #fb-project-id, and binds the SELECT ALL + SCAN FIREBASE handlers.
function initFirebasePanel(configMeta) {
  const panel = document.getElementById('firebase-panel');
  if (!panel) return;
  const isFirebase = configMeta && configMeta.stack && configMeta.stack.backend === 'firebase';
  panel.hidden = !isFirebase;
  if (!isFirebase) return;

  document.getElementById('fb-project-id').textContent =
    (configMeta.firebase && configMeta.firebase.projectId) || 'unknown';

  document.getElementById('fb-select-all')
    .addEventListener('click', toggleAllFirebaseServices);
  document.getElementById('fb-scan')
    .addEventListener('click', startFirebaseScan);
  document.querySelectorAll('.fb-svc')
    .forEach(cb => cb.addEventListener('change', updateFirebaseScanButton));

  updateFirebaseScanButton();
}

// Enable/disable the SCAN FIREBASE button based on whether any checkbox is checked.
function updateFirebaseScanButton() {
  const anyChecked = !![...document.querySelectorAll('.fb-svc')].find(cb => cb.checked);
  const btn = document.getElementById('fb-scan');
  btn.disabled = !anyChecked;
  btn.classList.toggle('is-disabled', !anyChecked);
}

// SELECT ALL toggle (all on, or all off if already all on).
function toggleAllFirebaseServices() {
  const boxes = [...document.querySelectorAll('.fb-svc')];
  const allOn = boxes.every(cb => cb.checked);
  boxes.forEach(cb => { cb.checked = !allOn; });
  updateFirebaseScanButton();
}

// Build scanner_overrides from checked boxes and start the scan.
async function startFirebaseScan() {
  const overrides = [...document.querySelectorAll('.fb-svc')]
    .filter(cb => cb.checked).map(cb => cb.value);
  if (overrides.length === 0) return;

  const resp = await fetch('/api/scan/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ stage: 'firebase', scanner_overrides: overrides }),
  });
  if (resp.ok) {
    window.location.href = 'scan.html';
  } else {
    // surface the error the same way existing stage-start failures are shown
    const err = await resp.json().catch(() => ({ detail: 'Scan failed to start' }));
    showStartError(err.detail || 'Scan failed to start');
  }
}
```

- The home page's existing config-loading code must call `initFirebasePanel(configMeta)` after it fetches config metadata (the same metadata that drives the stage list — see `routes.py` `stages_info`/stack reporting). If the config endpoint does not already expose `firebase.projectId`, the panel still works and shows `unknown`; the scanner re-detects config at scan time regardless.
- `scan.html` and `results.html` require **no changes** — the live terminal and findings feed are driven entirely by the WebSocket events the engine already emits.

### 13.3 CSS

Add `.firebase-panel`, `.firebase-panel__grid` (2-column on wide, 1-column on narrow), and `.is-disabled` styling to `dashboard.css`, matching the existing hacker-themed control-center aesthetic (monospace, neon-accent borders). No new color tokens required; reuse existing CSS variables.

---

## 14. Error Handling

All scanners follow these rules (consistent with `STANDARDS.md` and existing scanners):

| Condition | Behavior |
|---|---|
| Firebase config not detected (`extract_firebase_config` + passive fallback both empty, or no `projectId`) | `self.emit(runner, "Firebase config not detected — skipping", level="warn")`, `return []`. |
| Firebase SDK not found on page (CDP snippet returns `{error: 'SDK not found'}`) | `self.emit(runner, "Firebase SDK not found on page — using REST path only", level="info")`. CDP path skipped; REST builders carry the check. |
| A write-cleanup delete fails | `self.emit(runner, "Probe cleanup failed for <path> — manual delete may be needed", level="info")`. No Finding is produced for the cleanup failure itself. |
| A single REST request fails (timeout, DNS, HTTP error) | Caught per-request inside the helper (`return ("", None)`); the current check skips, remaining check groups still run. |
| Second account absent (cross-user groups) | `self.emit(runner, "Second account not configured — skipping cross-user checks", level="info")`; group silently skips. |
| Any unexpected exception inside a check group | Caught by the per-group `try/except`; logged via emit at `info` level; remaining groups continue. The scanner never re-raises. |
| App Check blocks all probes (consistent 403 even with valid token) | Treated as a positive defensive signal; no Finding. Optionally an INFO emit noting App Check appears active. |

Top-level contract: `run()` must never raise. If a catastrophic error escapes the per-group guards, the engine's own `try/except` records a `scanner_exception` and continues; but scanners should not rely on that and must keep their own guards.

Write-safety contract (restated): every created artifact uses `PROBE_PREFIX`; every write path has a paired delete in `finally`; helpers assert the prefix and refuse non-namespaced writes.

---

## 15. Testing

### 15.1 Layout

```
tests/
├── fixtures/vulnerable_app/
│   └── firebase_app.py                      # NEW — Firebase vulnerable fixture
├── test_scanners/
│   ├── test_firebase_firestore_proof.py     # NEW
│   ├── test_firebase_rtdb_proof.py          # NEW
│   ├── test_firebase_storage_proof.py       # NEW
│   ├── test_firebase_auth_proof.py          # NEW
│   └── test_firebase_functions_proof.py     # NEW
└── test_utils/
    └── test_firebase_helpers.py             # NEW
```

### 15.2 `firebase_app.py` fixture

A `ThreadingHTTPServer` on a random free port, exposed via a `FirebaseVulnerableApp` context manager identical in shape to the existing `VulnerableApp` (`start()`/`stop()`/`__enter__`/`__exit__`/`base_url`). Because the production REST helpers target fixed Google hosts, the fixture works in one of two equivalent ways — the spec mandates the **base-URL injection** approach so tests stay hermetic:

- Helpers accept an optional internal `_base_override` (defaulting to the real Google host) so proof tests can point Firestore/RTDB/Storage/Identity-Toolkit/Functions REST calls at `firebase_app`'s `base_url`. Tests pass the fixture URL through the resolved-config dict (`databaseURL`, derived Firestore/Storage/functions bases) and a monkeypatched `IDENTITY_TOOLKIT_BASE`. No real network egress ever occurs.

The fixture simulates, at minimum:

| Route | Simulates | Used by |
|---|---|---|
| `GET /v1/projects/{pid}/databases/(default)/documents/{coll}/{doc}` | Firestore doc readable without auth (open rules); returns typed-value JSON. | firestore G1/G2/G4 |
| `PATCH .../documents/{coll}/{doc}` | Firestore write accepted without auth, persists privileged fields. | firestore G2/G3 |
| `DELETE .../documents/{coll}/{doc}` | Cleanup endpoint (always `200`). | firestore cleanup |
| `GET /{path}.json` and `/.json` | RTDB readable without auth; `?shallow=true` returns key list. | rtdb G1/G3/G4 |
| `PUT /{path}.json` | RTDB write accepted without auth. | rtdb G2 |
| `DELETE /{path}.json` | Cleanup (always `200`). | rtdb cleanup |
| `GET /v0/b/{bucket}/o/{path}?alt=media` | Storage download without auth. | storage G1/G3 |
| `POST /v0/b/{bucket}/o?name={path}` | Storage upload without auth. | storage G2 |
| `GET /v0/b/{bucket}/o` | Bucket object listing (`{"items":[...]}`). | storage G4 |
| `DELETE /v0/b/{bucket}/o/{path}` | Cleanup (always `200`). | storage cleanup |
| `POST /v1/accounts:signUp` | Returns `idToken` (anonymous auth enabled). | auth G1 |
| `POST /v1/accounts:createAuthUri` | Returns `registered: true`/provider list (email enumeration). | auth G2/G5 |
| `POST/GET/OPTIONS /{region}-{pid}.cloudfunctions.net/{fn}` (mapped onto the fixture path) | `200` without auth; wildcard CORS + credentials on `OPTIONS`; one function leaks a token in its body; `setRole`/`admin` reachable. | functions G1–G4 |

The fixture also exposes "secured" sibling routes (e.g. `/secured/.json` returns `401`; a secured Firestore doc returns `403`) so each scanner has a negative-test target.

### 15.3 Proof tests

Each `test_firebase_*_proof.py` follows the exact pattern of `test_api_exposure_proof.py`:

- A module-scoped `vuln_app` fixture wrapping `FirebaseVulnerableApp()`.
- A `_make_config(base_url)` building a `MagicMock` config with `target`, `stack.backend = "firebase"`, `second_account_configured`, and the resolved Firebase config dict pointing at the fixture base URL.
- A `_run(...)` helper that instantiates `Scanner()`, builds a mocked `listeners` dict (`network` as a `MagicMock` whose `get_requests()` returns crafted request objects; `storage`/`console` as `MagicMock`), and calls `scanner.run(session=<MagicMock or None>, listeners=..., config=...)`.
- Positive assertions per check group: at least one Finding with the expected `title` substring and expected `severity` from §9.
- Exactly **one negative test per scanner**: point the scanner at a secured route (or a fixture mode where rules deny) and assert `findings == []` (or no Finding of that group's type).

Concrete per-scanner positive assertions:

| Test file | Asserts |
|---|---|
| `test_firebase_firestore_proof.py` | Unauth read → HIGH/CRITICAL finding; cross-user IDOR (second account on) → CRITICAL; mass-assignment privileged field persisted → MEDIUM; enumeration → MEDIUM. Negative: secured doc returns 403 → no finding. |
| `test_firebase_rtdb_proof.py` | Unauth root read → CRITICAL; unauth write (probe key) → CRITICAL and cleanup DELETE was called; `?shallow` enumeration → MEDIUM. Negative: secured path 401 → no finding. |
| `test_firebase_storage_proof.py` | Unauth download → HIGH; unauth upload → HIGH and cleanup DELETE called; bucket listing → MEDIUM. Negative: secured path 403 → no finding. |
| `test_firebase_auth_proof.py` | signUp returns idToken → HIGH (anonymous abuse); createAuthUri registered diff → LOW (enumeration); token-in-response detection → MEDIUM. Negative: signUp 400/disabled → no anonymous finding. |
| `test_firebase_functions_proof.py` | Unauth function 200 → HIGH; token in body → HIGH; wildcard CORS + credentials → HIGH; admin function reachable → HIGH. Negative: function returning 401 → no unauth finding. |

### 15.4 `test_firebase_helpers.py`

Unit tests for every helper with mocked HTTP (monkeypatch `urllib.request.urlopen` to return canned responses, or point at the fixture). Coverage:

- `extract_firebase_config`: feed a `MagicMock` session whose `evaluate` returns each of the three config shapes (compat, modular defaults, manual) and assert the normalized dict; assert `{}` on exception.
- `detect_firebase_config`: feed crafted network-event lists; assert reconstructed `{projectId, databaseURL, ...}`; assert `None` when nothing Firebase-shaped.
- `get_firebase_id_token`: session returning a token string; session returning `None`; exception path → `None`.
- Each `build_*_snippet`: assert the returned JS contains the collection/path/data and is valid (single-quote escaping verified).
- Each `rest_*` builder: monkeypatched `urlopen` returns `200` body → `(body, 200)`; `HTTPError` → `(body, code)`; arbitrary exception → `("", None)`. Assert `Authorization` header present iff `id_token` given; assert RTDB `?auth=` appended.
- Write helpers: assert they refuse (return `("", None)`) when `doc_id`/`path`/`name` lacks `PROBE_PREFIX`.
- `_to_firestore_fields`/`_from_firestore_fields`: round-trip a mixed dict.
- `discover_function_urls`: extracts unique `cloudfunctions.net`/`run.app` URLs.
- `find_id_tokens`: finds JWT-shaped strings.
- `truncate`: long string truncated with the `...[truncated]` marker.

### 15.5 Running

```
pytest tests/test_scanners/test_firebase_firestore_proof.py \
       tests/test_scanners/test_firebase_rtdb_proof.py \
       tests/test_scanners/test_firebase_storage_proof.py \
       tests/test_scanners/test_firebase_auth_proof.py \
       tests/test_scanners/test_firebase_functions_proof.py \
       tests/test_utils/test_firebase_helpers.py -v
```

All tests must be hermetic (no real network), deterministic, and complete well under the default scanner timeout. They must pass in CI alongside the existing suite.

---

## 16. Security & Safety Considerations

1. **Probe namespacing:** every created Firestore doc, RTDB key, and Storage object is named with `vibe_iterator_probe_`. Helpers assert this; non-namespaced writes are refused.
2. **Guaranteed cleanup:** all write groups delete their artifacts in `try/finally`, so a probe leaves nothing behind even when an exception fires mid-check.
3. **No credential persistence:** ID tokens and `apiKey` values are redacted in evidence (`Bearer <redacted>`, `key=<redacted>`); only excerpts and structural facts are stored.
4. **No destructive operations:** scanners never delete or mutate pre-existing data; only their own probe artifacts.
5. **Local-only fixture:** the test fixture binds to `127.0.0.1:0` and never reaches the internet.
6. **Graceful on defenses:** App Check / disabled-anonymous / locked-down rules produce no false-positive findings — the absence of a finding is the correct outcome.
7. **Rate-limit friendliness:** common-name probes are bounded (collections capped at the `_COMMON_*` list length, functions at the sensitive-name list) and use a short `REQUEST_TIMEOUT`, so a scan cannot become an inadvertent DoS.

---

## 17. Implementation Order (suggested)

1. `utils/firebase_helpers.py` + `tests/test_utils/test_firebase_helpers.py` (TDD; unit-testable in isolation).
2. `tests/fixtures/vulnerable_app/firebase_app.py` (the proof harness everything else depends on).
3. `scanners/firebase_rtdb.py` + proof test (simplest: no second account, clear CRITICAL signals) — validates the fixture-injection pattern end to end.
4. `scanners/firebase_storage.py` + proof test.
5. `scanners/firebase_firestore.py` + proof test (most complex: second-account IDOR + mass assignment).
6. `scanners/firebase_functions.py` + proof test.
7. `scanners/firebase_auth.py` + proof test.
8. Register all five in `engine/runner.py` `_SCANNER_MODULE_MAP`.
9. Add the `firebase` stage to `vibe-iterator.config.yaml` and `.example`.
10. Dashboard: `index.html` panel, `app.js` functions, `dashboard.css` styles.
11. Update `docs/SCANNERS.md` registry table and `docs/CONFIG.md` stage list to include the Firebase scanners and stage.
12. Run the full suite; confirm no regressions and all Firebase proof tests pass.

---

## 18. Acceptance Criteria ("Done When")

- [ ] All five Firebase scanner modules exist, each exposing a `Scanner` subclass of `BaseScanner` with the registry attributes from §5.
- [ ] `firebase_helpers.py` implements every function in §7 with the exact `(body, status)` / `dict` / `str | None` contracts, and refuses non-`PROBE_PREFIX` writes.
- [ ] `_SCANNER_MODULE_MAP` includes all five names; the engine loads and runs them on a Firebase target and skips them on a Supabase/custom target via the existing stack gate.
- [ ] `vibe-iterator.config.yaml` (and `.example`) contains the `firebase` stage with the five scanners.
- [ ] The dashboard renders the Firebase panel only when `backend == "firebase"`; checkboxes default checked; SELECT ALL toggles; SCAN FIREBASE dims when none checked; starting POSTs `{ stage: "firebase", scanner_overrides: [...] }` and navigates to `scan.html`.
- [ ] No changes were required to `runner.py` logic beyond the registry map, to `routes.py`, `websocket.py`, the scoring system, the report generator, `scan.html`, or `results.html`.
- [ ] Every write probe is namespaced and cleaned up in `try/finally`; cross-user/second-account checks skip silently with an INFO emit when no second account is configured.
- [ ] Findings use the correct severities (§9) and the correct evidence structure per category (§10), and carry a Firebase-specific `llm_prompt` (§11) and structured `remediation` (§12).
- [ ] `firebase_app.py` fixture and all six new test files exist; every scanner has positive proof tests per check group and exactly one negative test; `test_firebase_helpers.py` covers every helper.
- [ ] The full test suite (existing + new) passes in CI with no network egress and within the scanner timeout budget.
- [ ] `docs/SCANNERS.md` and `docs/CONFIG.md` are updated to document the new scanners and the `firebase` stage.

---

## 19. Open Questions

None. All design decisions in this document are approved. Detection of `backend: firebase`, the `scanner_overrides` API, the event/scoring/report pipeline, and the fixture/proof-test pattern already exist in the codebase and are reused as-is.
