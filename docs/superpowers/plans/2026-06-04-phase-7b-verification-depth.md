# Phase 7B Verification Depth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Phase 7B verification depth: Firebase helper branch coverage, real-world edge fixtures, opt-in Selenium/CDP proof coverage, e2e stability tracking, and final docs alignment.

**Architecture:** Keep production behavior stable unless a new proof test exposes a real false positive, false negative, unsafe probe, or missing parser branch. Use focused unit/proof tests for default coverage, local `127.0.0.1` fixtures for integration proof, and opt-in Selenium/CDP e2e for release confidence. Preserve Phase 6 proof-quality gates and keep e2e outside the default `pytest` path unless explicitly enabled.

**Tech Stack:** Python 3.11, pytest, pytest-cov, Selenium/CDP through existing `vibe_iterator.crawler.browser`, stdlib `urllib`, `ThreadingHTTPServer` fixtures, existing Superpowers docs workflow.

---

## File Map

**Create:**
- `tests/e2e/e2e-stability-log.json` - e2e graduation tracker.

**Modify:**
- `tests/test_utils/test_firebase_helpers.py` - Firebase helper branch and request-shape coverage.
- `vibe_iterator/utils/firebase_helpers.py` - only for tested missing helper behavior: `firebasedatabase.app` detection, nested Firestore typed values, token filtering if needed.
- `tests/fixtures/vulnerable_app/app.py` - generic tier/storage/auth/rate-limit positive and negative fixture routes.
- `tests/fixtures/vulnerable_app/firebase_app.py` - Firebase-shaped local REST fixture routes and controls.
- `tests/test_scanners/test_core_runtime_scanners.py` - tier/client tampering negative and positive edge tests.
- `tests/test_scanners/test_bucket_limits.py` - Supabase storage URL and accepted-upload proof controls.
- `tests/test_scanners/test_auth_check_proof.py` - protected/public auth proof controls.
- `tests/test_scanners/test_firebase_*_proof.py` - Firebase local fixture proof extensions.
- `tests/e2e/test_real_browser_smoke.py` - opt-in real browser proof matrix.
- `.github/workflows/vibe-iterator-e2e.yml` - manual e2e workflow if no equivalent workflow exists.
- `README.md` - final test count and Phase 7B status.
- `docs/PHASES.md` - Phase 6 and Phase 7B entries.
- `docs/SCANNERS.md` - proof-quality vocabulary section.
- `docs/CONFIG.md` - verify and align `VIBE_ITERATOR_BACKEND_URL`.
- `docs/ADDING_SCANNERS.md` - proof-quality guidance for new scanners.
- `.env.example` - verify schema alignment; edit only if drift is found.

---

## Task 0: Branch And Baseline Sanity

**Files:**
- Read: `docs/superpowers/specs/2026-06-03-phase-7b-readiness-design.md`
- Read: `docs/current-state.md`
- Read: `docs/progress.md`

- [ ] **Step 1: Confirm branch and local artifacts**

Run:

```powershell
git status --short --branch
git log --oneline --decorate -5
```

Expected:

```text
## codex/phase7b-verification-depth
?? docs/results.md
?? vibe-iterator.discovered.yaml
```

If still on `main`, run:

```powershell
git switch -c codex/phase7b-verification-depth
```

- [ ] **Step 2: Confirm the approved spec**

Run:

```powershell
Select-String -Path docs\superpowers\specs\2026-06-03-phase-7b-readiness-design.md -Pattern "Status|Next step|Phase-Done Gate" -Context 0,4
```

Expected: status is `Approved`, next step is this implementation plan, and the phase-done gate lists default suite, coverage, e2e, stability log, wheel smoke, docs, and proof-gate preservation.

- [ ] **Step 3: Run the fast baseline suite before edits**

Run:

```powershell
python -m pytest -q
```

Expected: zero failures. Record the actual pass/skip count in the eventual docs update. Do not edit docs yet.

---

## Task 1: Firebase Helper Tests First

**Files:**
- Modify: `tests/test_utils/test_firebase_helpers.py`
- Possibly modify: `vibe_iterator/utils/firebase_helpers.py`

- [ ] **Step 1: Expand imports in the helper test file**

In `tests/test_utils/test_firebase_helpers.py`, update the import list from `vibe_iterator.utils.firebase_helpers` to include the helpers under test:

```python
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    REQUEST_TIMEOUT,
    _CLOSED_LOCAL_ENDPOINTS,
    _from_firestore_fields,
    _to_firestore_fields,
    build_firebase_llm_prompt,
    build_firestore_read_snippet,
    build_firestore_write_snippet,
    build_rtdb_read_snippet,
    build_rtdb_write_snippet,
    build_storage_download_snippet,
    build_storage_upload_snippet,
    detect_firebase_config,
    discover_function_urls,
    extract_firebase_config,
    find_id_tokens,
    get_firebase_id_token,
    is_closed_local_url,
    rest_firestore_delete,
    rest_firestore_get,
    rest_firestore_write,
    rest_functions_call,
    rest_rtdb_delete,
    rest_rtdb_get,
    rest_rtdb_write,
    rest_storage_delete,
    rest_storage_download,
    rest_storage_upload,
    truncate,
)
```

- [ ] **Step 2: Add reusable request capture helpers**

Append these helpers after `_fake_resp`:

```python
def _http_error(status: int, body: str = '{"error":"denied"}'):
    import urllib.error

    return urllib.error.HTTPError(
        "https://example.test",
        status,
        "error",
        {},
        io.BytesIO(body.encode()),
    )


def _capture_urlopen(calls: list):
    def fake_open(req, timeout):
        body = req.data.decode("utf-8") if getattr(req, "data", None) else ""
        calls.append({
            "url": req.full_url,
            "method": req.get_method(),
            "headers": dict(req.header_items()),
            "body": body,
            "timeout": timeout,
        })
        return _fake_resp('{"ok":true}', 200)

    return fake_open
```

- [ ] **Step 3: Add failing tests for local reachability caching**

Append:

```python
def test_is_closed_local_url_open_port_returns_false() -> None:
    import socket

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        host, port = server.getsockname()
        assert is_closed_local_url(f"http://{host}:{port}") is False


def test_is_closed_local_url_closed_port_is_cached(monkeypatch) -> None:
    _CLOSED_LOCAL_ENDPOINTS.clear()
    attempts = []

    def fake_create_connection(endpoint, timeout):
        attempts.append((endpoint, timeout))
        raise OSError("closed")

    monkeypatch.setattr("socket.create_connection", fake_create_connection)

    assert is_closed_local_url("http://127.0.0.1:65530") is True
    assert is_closed_local_url("http://127.0.0.1:65530") is True
    assert len(attempts) == 1
    _CLOSED_LOCAL_ENDPOINTS.clear()


def test_is_closed_local_url_ignores_non_local_and_invalid_port() -> None:
    assert is_closed_local_url("https://firebase.google.com") is False
    assert is_closed_local_url("http://127.0.0.1:notaport") is False
```

- [ ] **Step 4: Add failing tests for Firebase config detection**

Append:

```python
def test_detect_firebase_config_from_firebasedatabase_app_url() -> None:
    req = MagicMock()
    req.url = "https://myproject-default-rtdb.firebasedatabase.app/users.json"
    result = detect_firebase_config([req])
    assert result is not None
    assert result["projectId"] == "myproject"
    assert result["databaseURL"] == "https://myproject-default-rtdb.firebasedatabase.app"


def test_detect_firebase_config_combines_identity_storage_and_auth_domain() -> None:
    events = [
        MagicMock(url="https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=api-key-123"),
        MagicMock(url="https://firebasestorage.googleapis.com/v0/b/proj.appspot.com/o"),
        MagicMock(url="https://proj.firebaseapp.com/login"),
    ]
    result = detect_firebase_config(events)
    assert result == {
        "apiKey": "api-key-123",
        "storageBucket": "proj.appspot.com",
        "authDomain": "proj.firebaseapp.com",
        "projectId": "proj",
    }
```

- [ ] **Step 5: Add failing tests for REST request shapes**

Append:

```python
def test_rest_rtdb_delete_success_and_auth_param() -> None:
    calls = []
    with patch("urllib.request.urlopen", side_effect=_capture_urlopen(calls)):
        body, status = rest_rtdb_delete("https://proj.firebaseio.com", "users/uid1", id_token="tok 123")
    assert status == 200
    assert body == '{"ok":true}'
    assert calls[0]["method"] == "DELETE"
    assert calls[0]["url"] == "https://proj.firebaseio.com/users/uid1.json?auth=tok%20123"


def test_rest_rtdb_delete_http_error_and_unknown_exception() -> None:
    with patch("urllib.request.urlopen", side_effect=_http_error(403)):
        assert rest_rtdb_delete("https://proj.firebaseio.com", "secured") == ('{"error":"denied"}', 403)
    with patch("urllib.request.urlopen", side_effect=RuntimeError("timeout")):
        assert rest_rtdb_delete("https://proj.firebaseio.com", "secured") == ("", None)


def test_rest_firestore_methods_build_urls_headers_and_bodies() -> None:
    calls = []
    with patch("urllib.request.urlopen", side_effect=_capture_urlopen(calls)):
        assert rest_firestore_get("proj", "users", "uid1", id_token="tok")[1] == 200
        assert rest_firestore_write("proj", "users", PROBE_PREFIX + "doc", {"age": 7}, id_token="tok")[1] == 200
        assert rest_firestore_delete("proj", "users", "uid1", id_token="tok")[1] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["headers"]["Authorization"] == "Bearer tok"
    assert calls[1]["method"] == "PATCH"
    assert '"integerValue": "7"' in calls[1]["body"]
    assert calls[2]["method"] == "DELETE"


def test_rest_firestore_write_refuses_non_probe_doc() -> None:
    assert rest_firestore_write("proj", "users", "real-doc", {"role": "admin"}) == ("", None)


def test_rest_storage_methods_encode_paths_and_auth_headers() -> None:
    calls = []
    with patch("urllib.request.urlopen", side_effect=_capture_urlopen(calls)):
        assert rest_storage_download("proj.appspot.com", "private/a b.txt", id_token="tok")[1] == 200
        assert rest_storage_upload("proj.appspot.com", PROBE_PREFIX + "a b.txt", b"hi", id_token="tok")[1] == 200
        assert rest_storage_delete("proj.appspot.com", "private/a b.txt", id_token="tok")[1] == 200

    assert "private%2Fa%20b.txt" in calls[0]["url"]
    assert calls[0]["headers"]["Authorization"] == "Bearer tok"
    assert calls[1]["method"] == "POST"
    assert "name=vibe_iterator_probe_a%20b.txt" in calls[1]["url"]
    assert calls[2]["method"] == "DELETE"


def test_rest_storage_upload_refuses_non_probe_path() -> None:
    assert rest_storage_upload("proj.appspot.com", "real-file.txt", b"hi") == ("", None)


def test_rest_functions_call_builds_auth_json_request_and_handles_unknown_exception() -> None:
    calls = []
    with patch("urllib.request.urlopen", side_effect=_capture_urlopen(calls)):
        body, status = rest_functions_call("us-central1", "proj", "helloWorld", {"x": 1}, id_token="tok")
    assert status == 200
    assert body == '{"ok":true}'
    assert calls[0]["url"] == "https://us-central1-proj.cloudfunctions.net/helloWorld"
    assert calls[0]["method"] == "POST"
    assert calls[0]["headers"]["Authorization"] == "Bearer tok"
    assert calls[0]["body"] == '{"x": 1}'

    with patch("urllib.request.urlopen", side_effect=RuntimeError("down")):
        assert rest_functions_call("us-central1", "proj", "helloWorld", {}) == ("", None)
```

- [ ] **Step 6: Add failing tests for nested Firestore typed values**

Append:

```python
def test_firestore_fields_roundtrip_nested_maps_arrays_and_unknown_values() -> None:
    data = {
        "name": "alice",
        "profile": {"tier": "free", "active": True},
        "tags": ["alpha", 3, None],
        "score": 9.5,
        "nothing": None,
    }
    doc = _to_firestore_fields(data)
    assert doc["fields"]["profile"]["mapValue"]["fields"]["tier"] == {"stringValue": "free"}
    assert doc["fields"]["tags"]["arrayValue"]["values"][1] == {"integerValue": "3"}

    doc["fields"]["mystery"] = {"timestampValue": "2026-06-04T00:00:00Z"}
    roundtrip = _from_firestore_fields(doc)
    assert roundtrip["profile"] == {"tier": "free", "active": True}
    assert roundtrip["tags"] == ["alpha", 3, None]
    assert roundtrip["score"] == 9.5
    assert roundtrip["nothing"] is None
    assert roundtrip["mystery"] == "2026-06-04T00:00:00Z"
```

- [ ] **Step 7: Run the helper tests and observe failures**

Run:

```powershell
python -m pytest tests/test_utils/test_firebase_helpers.py -q
```

Expected before implementation: failures for `firebasedatabase.app` detection and nested Firestore conversion if those branches are missing. Existing helper behavior may already satisfy some request-shape tests.

- [ ] **Step 8: Implement only the missing helper behavior**

If `firebasedatabase.app` detection fails, update the RTDB regex in `vibe_iterator/utils/firebase_helpers.py`:

```python
_RTDB_HOST_RE = re.compile(
    r"https://([a-z0-9-]+?)(?:-default-rtdb)?\.(firebaseio\.com|firebasedatabase\.app)"
)
```

Then update `detect_firebase_config` so the database URL preserves the matched domain:

```python
m = _RTDB_HOST_RE.search(url)
if m:
    project_id = m.group(1)
    domain = m.group(2)
    cfg.setdefault("projectId", project_id)
    if domain == "firebasedatabase.app":
        cfg.setdefault("databaseURL", f"https://{project_id}-default-rtdb.firebasedatabase.app")
    else:
        cfg.setdefault("databaseURL", f"https://{project_id}-default-rtdb.firebaseio.com")
```

If nested Firestore conversion fails, replace `_to_firestore_fields` and `_from_firestore_fields` with helper-based conversion:

```python
def _to_firestore_value(value: Any) -> dict:
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if value is None:
        return {"nullValue": None}
    if isinstance(value, dict):
        return {"mapValue": {"fields": {k: _to_firestore_value(v) for k, v in value.items()}}}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_to_firestore_value(v) for v in value]}}
    return {"stringValue": str(value)}


def _to_firestore_fields(data: dict) -> dict:
    return {"fields": {k: _to_firestore_value(v) for k, v in data.items()}}


def _from_firestore_value(value: dict) -> Any:
    if "stringValue" in value:
        return value["stringValue"]
    if "integerValue" in value:
        return int(value["integerValue"])
    if "doubleValue" in value:
        return value["doubleValue"]
    if "booleanValue" in value:
        return value["booleanValue"]
    if "nullValue" in value:
        return None
    if "mapValue" in value:
        return _from_firestore_fields(value["mapValue"])
    if "arrayValue" in value:
        return [_from_firestore_value(v) for v in value.get("arrayValue", {}).get("values", [])]
    if "timestampValue" in value:
        return value["timestampValue"]
    return None


def _from_firestore_fields(doc: dict) -> dict:
    return {k: _from_firestore_value(v) for k, v in (doc.get("fields") or {}).items()}
```

- [ ] **Step 9: Re-run helper tests**

Run:

```powershell
python -m pytest tests/test_utils/test_firebase_helpers.py -q
```

Expected: all Firebase helper tests pass.

- [ ] **Step 10: Check focused coverage**

Run:

```powershell
python -m pytest tests/test_utils/test_firebase_helpers.py --cov=vibe_iterator.utils.firebase_helpers --cov-report=term-missing -q
```

Expected: `vibe_iterator/utils/firebase_helpers.py` coverage is at least `75%`.

- [ ] **Step 11: Commit Track 2**

Run:

```powershell
git add tests/test_utils/test_firebase_helpers.py vibe_iterator/utils/firebase_helpers.py
git commit -m "test(firebase): deepen helper coverage and Firestore conversion"
```

---

## Task 2: Generic Fixture Edge Routes And Proof Tests

**Files:**
- Modify: `tests/fixtures/vulnerable_app/app.py`
- Modify: `tests/test_scanners/test_core_runtime_scanners.py`
- Modify: `tests/test_scanners/test_bucket_limits.py`
- Modify: `tests/test_scanners/test_auth_check_proof.py`

- [ ] **Step 1: Add fixture route comments**

At the top of `tests/fixtures/vulnerable_app/app.py`, extend the vulnerability comment block with these lines:

```python
  - /pricing, /application, /api/protected-401 — negative controls for auth bypass
  - /api/tier/structured — structured tier proof response
  - /api/tier/text-copy — unrelated premium text negative control
  - /api/tier/rpc-error — RPC error text negative control
  - /storage/v1/object/... — Supabase-shaped storage edge routes
```

- [ ] **Step 2: Add GET routes**

Inside `VulnerableHandler.do_GET`, add these branches before the final `else`:

```python
        elif path == "/api/protected-401":
            self._respond_json(401, {"error": "unauthorized"})
        elif path in ("/pricing", "/application"):
            self._respond_html(200, "<!doctype html><title>Public</title><h1>public product page</h1>")
        elif path == "/api/tier/structured":
            self._respond_json(200, {"subscription": {"tier": "premium"}, "source": "server"})
        elif path == "/api/tier/text-copy":
            self._respond_json(200, {"message": "Premium support is available on paid plans."})
        elif path == "/api/tier/rpc-error":
            self._respond_json(200, {"data": None, "error": "Premium tier function unavailable"})
        elif path.startswith("/storage/v1/object/list/"):
            bucket = path.rsplit("/", 1)[-1]
            self._respond_json(200, {"bucket": bucket, "objects": []})
        elif path.startswith("/storage/v1/object/public/"):
            self._respond_json(200, {"storage": "public-object"})
        elif path.startswith("/storage/v1/object/sign/"):
            self._respond_json(200, {"signedURL": "/signed/test"})
        elif path.startswith("/storage/v1/object/preview/"):
            self._respond_json(200, {"preview": True, "accepted": False})
```

- [ ] **Step 3: Add storage POST negative and positive controls**

Inside `VulnerableHandler.do_POST`, before the final `else`, add:

```python
        elif path.startswith("/storage/v1/object/dry-run/"):
            self._respond_json(200, {"dry_run": True, "accepted": False})

        elif path.startswith("/storage/v1/object/denied/"):
            self._respond_json(403, {"error": "storage policy denied"})

        elif path.startswith("/storage/v1/object/accepted/"):
            self._respond_json(201, {"name": path.rsplit("/", 1)[-1], "accepted": True})
```

- [ ] **Step 4: Add tier proof tests**

In `tests/test_scanners/test_core_runtime_scanners.py`, add:

```python
def test_network_reflects_tier_accepts_nested_subscription_path() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/tier/structured", body='{"subscription":{"tier":"premium"}}'),
    ]

    proof = _network_reflects_tier(network, "plan", "premium")

    assert proof == {
        "url": "http://localhost:3000/api/tier/structured",
        "status": 200,
        "json_path": "subscription.tier",
        "matched_value": "premium",
    }


def test_network_reflects_tier_ignores_rpc_error_text() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/tier/rpc-error", body='{"data":null,"error":"Premium tier function unavailable"}'),
    ]

    assert _network_reflects_tier(network, "plan", "premium") is None
```

- [ ] **Step 5: Add auth proof route controls**

In `tests/test_scanners/test_auth_check_proof.py`, add:

```python
def test_protected_401_endpoint_is_not_auth_bypass(vuln_app) -> None:
    req = _make_api_req(url=vuln_app.base_url + "/api/protected-401")
    req.status_code = 401
    req.response_body = '{"error":"unauthorized"}'

    findings = _run(vuln_app, [req])

    assert [f for f in findings if "accessible without authentication" in f.title.lower()] == []
```

- [ ] **Step 6: Add storage discovery controls**

In `tests/test_scanners/test_bucket_limits.py`, add:

```python
def test_discover_buckets_ignores_preview_and_dry_run_paths() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        SimpleNamespace(url="https://x/storage/v1/object/preview/avatars/file.png"),
        SimpleNamespace(url="https://x/storage/v1/object/dry-run/avatars/file.png"),
        SimpleNamespace(url="https://x/storage/v1/object/public/avatars/file.png"),
    ]

    assert _discover_buckets(network) == ["avatars"]
```

If this fails because preview or dry-run are treated as bucket names, update `_discover_buckets` in `vibe_iterator/scanners/bucket_limits.py` to skip operation segments:

```python
operation_segments = {"public", "sign", "list", "preview", "dry-run", "denied"}
```

- [ ] **Step 7: Run focused tests**

Run:

```powershell
python -m pytest tests/test_scanners/test_core_runtime_scanners.py tests/test_scanners/test_auth_check_proof.py tests/test_scanners/test_bucket_limits.py -q
```

Expected: all focused tests pass.

- [ ] **Step 8: Commit generic fixture track**

Run:

```powershell
git add tests/fixtures/vulnerable_app/app.py tests/test_scanners/test_core_runtime_scanners.py tests/test_scanners/test_auth_check_proof.py tests/test_scanners/test_bucket_limits.py vibe_iterator/scanners/bucket_limits.py
git commit -m "test(fixtures): add tier storage and auth proof controls"
```

If `bucket_limits.py` was not modified, leave it out of the `git add`.

---

## Task 3: Firebase Fixture Edge Routes And Proof Tests

**Files:**
- Modify: `tests/fixtures/vulnerable_app/firebase_app.py`
- Modify: `tests/test_scanners/test_firebase_fixture_smoke.py`
- Modify: `tests/test_scanners/test_firebase_auth_proof.py`
- Modify: `tests/test_scanners/test_firebase_firestore_proof.py`
- Modify: `tests/test_scanners/test_firebase_rtdb_proof.py`
- Modify: `tests/test_scanners/test_firebase_storage_proof.py`
- Modify: `tests/test_scanners/test_firebase_functions_proof.py`

- [ ] **Step 1: Add Firebase fixture route comments**

In `tests/fixtures/vulnerable_app/firebase_app.py`, extend the top route list with:

```python
  - Negative controls: secured Firestore/RTDB/Storage routes return denied responses
  - Positive probe controls: probe-prefixed writes/uploads return shaped success responses
  - Auth controls: anonymous signup enabled and disabled paths are modeled separately
  - Functions controls: unauthenticated execution and reflected credentialed CORS are separate
```

- [ ] **Step 2: Add auth negative route**

In `FirebaseHandler.do_POST`, update the `accounts:signUp` branch:

```python
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
```

- [ ] **Step 3: Tighten secured write/delete controls**

Ensure `do_PUT`, `do_PATCH`, and `do_DELETE` return denied responses for secured routes:

```python
        if path.endswith(".json"):
            rtdb_path = path[:-5]
            if rtdb_path.startswith("/secured") or rtdb_path == "/secured":
                self._json(401, {"error": "Permission denied"})
                return
```

For Firestore PATCH and DELETE:

```python
        if "/databases/(default)/documents/" in path:
            doc_path = path.split("/documents/", 1)[1]
            if doc_path.startswith("secured/"):
                self._json(403, {"error": {"status": "PERMISSION_DENIED"}})
                return
            self._json(200, {"name": path, "fields": {}})
            return
```

- [ ] **Step 4: Add fixture smoke tests**

In `tests/test_scanners/test_firebase_fixture_smoke.py`, add:

```python
def test_firebase_fixture_denies_secured_firestore_and_rtdb() -> None:
    import urllib.error
    import urllib.request

    with FirebaseVulnerableApp() as app:
        with pytest.raises(urllib.error.HTTPError) as rtdb_err:
            urllib.request.urlopen(f"{app.base_url}/secured.json", timeout=3)
        assert rtdb_err.value.code == 401

        firestore_url = (
            f"{app.base_url}/v1/projects/proj/databases/(default)/documents/secured/doc1"
        )
        with pytest.raises(urllib.error.HTTPError) as fs_err:
            urllib.request.urlopen(firestore_url, timeout=3)
        assert fs_err.value.code == 403


def test_firebase_fixture_accepts_probe_prefixed_storage_upload() -> None:
    import urllib.request

    with FirebaseVulnerableApp() as app:
        req = urllib.request.Request(
            f"{app.base_url}/v0/b/proj.appspot.com/o?name=vibe_iterator_probe_file.txt",
            data=b"probe",
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode()
        assert resp.status == 200
        assert "vibe_iterator_probe_file.txt" in body
```

- [ ] **Step 5: Run Firebase proof tests**

Run:

```powershell
python -m pytest tests/test_scanners/test_firebase_fixture_smoke.py tests/test_scanners/test_firebase_auth_proof.py tests/test_scanners/test_firebase_firestore_proof.py tests/test_scanners/test_firebase_rtdb_proof.py tests/test_scanners/test_firebase_storage_proof.py tests/test_scanners/test_firebase_functions_proof.py -q
```

Expected: all Firebase proof tests pass.

- [ ] **Step 6: Commit Firebase fixture track**

Run:

```powershell
git add tests/fixtures/vulnerable_app/firebase_app.py tests/test_scanners/test_firebase_fixture_smoke.py tests/test_scanners/test_firebase_auth_proof.py tests/test_scanners/test_firebase_firestore_proof.py tests/test_scanners/test_firebase_rtdb_proof.py tests/test_scanners/test_firebase_storage_proof.py tests/test_scanners/test_firebase_functions_proof.py
git commit -m "test(firebase): add local fixture edge controls"
```

---

## Task 4: Opt-In Selenium/CDP E2E Matrix And Stability Log

**Files:**
- Modify: `tests/e2e/test_real_browser_smoke.py`
- Create: `tests/e2e/e2e-stability-log.json`
- Create or modify: `.github/workflows/vibe-iterator-e2e.yml`

- [ ] **Step 1: Add scan helper in e2e test file**

In `tests/e2e/test_real_browser_smoke.py`, add `FirebaseVulnerableApp` import:

```python
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp
```

Add this helper above the skip-marked tests:

```python
def _run_scan(base_url: str, scanners: list[str], stack: StackConfig, pages: list[str], scan_id: str):
    events = []
    config = Config(
        target=base_url,
        test_email="tester@example.com",
        test_password="password123",
        test_email_2=None,
        test_password_2=None,
        supabase_url=None,
        supabase_anon_key=None,
        pages=pages,
        stages={scan_id: scanners},
        stack=stack,
        port=3001,
        scanner_timeout_seconds=30,
    )
    runner = ScanRunner(
        config=config,
        on_event=events.append,
        scanner_overrides=None,
        browser_headless=True,
        scan_id=scan_id,
    )
    return asyncio.run(runner.run(scan_id)), events
```

- [ ] **Step 2: Add generic e2e scanner matrix test**

Append:

```python
@pytest.mark.skipif(
    os.getenv("VIBE_ITERATOR_RUN_E2E_SMOKE") != "1",
    reason="Set VIBE_ITERATOR_RUN_E2E_SMOKE=1 to run the real Selenium/CDP generic matrix.",
)
def test_real_scan_runner_finds_generic_fixture_matrix() -> None:
    scanners = [
        "auth_check",
        "api_exposure",
        "cors_check",
        "info_disclosure",
        "sql_injection",
        "xss_check",
        "mass_assignment",
        "idor_check",
        "http_method_tampering",
        "rate_limit_check",
    ]
    pages = [
        "/",
        "/login",
        "/dashboard",
        "/api/data",
        "/api/user",
        "/api/protected",
        "/api/admin",
        "/api/search?q=test",
        "/api/profile",
        "/api/items/1",
        "/api/resource",
    ]
    with VulnerableApp() as app:
        result, events = _run_scan(
            app.base_url,
            scanners,
            StackConfig(backend="custom", auth="custom", storage="custom"),
            pages,
            "phase7b-generic-e2e",
        )

    titles = [finding.title.lower() for finding in result.findings]
    scanner_names = {finding.scanner for finding in result.findings}

    assert result.status == "completed"
    assert result.requests_captured["total"] > 0
    assert any(event.type == "scan_completed" for event in events)
    assert "auth_check" in scanner_names
    assert "cors_check" in scanner_names
    assert "info_disclosure" in scanner_names
    assert any("sql" in title for title in titles)
    assert any("mass assignment" in title for title in titles)
    assert any("idor" in title or "object reference" in title for title in titles)
```

- [ ] **Step 3: Add Firebase e2e matrix test**

Append:

```python
@pytest.mark.skipif(
    os.getenv("VIBE_ITERATOR_RUN_E2E_SMOKE") != "1",
    reason="Set VIBE_ITERATOR_RUN_E2E_SMOKE=1 to run the real Selenium/CDP Firebase matrix.",
)
def test_real_scan_runner_finds_firebase_fixture_matrix() -> None:
    scanners = [
        "firebase_auth",
        "firebase_firestore",
        "firebase_rtdb",
        "firebase_storage",
        "firebase_functions",
    ]
    pages = ["/", "/users.json", "/v0/b/proj.appspot.com/o", "/helloFunction"]
    with FirebaseVulnerableApp() as app:
        result, events = _run_scan(
            app.base_url,
            scanners,
            StackConfig(backend="firebase", auth="firebase-auth", storage="firebase"),
            pages,
            "phase7b-firebase-e2e",
        )

    assert result.status == "completed"
    assert any(event.type == "scan_completed" for event in events)
    assert result.requests_captured["total"] > 0
    assert {r.scanner_name for r in result.scanner_results} == set(scanners)
```

If this fails because the Firebase fixture has no browser-visible page that triggers Firebase-shaped network calls, add a `GET /` branch to `FirebaseHandler.do_GET`:

```python
        if path == "/":
            self._html(200, """<!doctype html><title>Firebase Fixture</title>
            <script>
            fetch('/users.json');
            fetch('/v0/b/proj.appspot.com/o');
            fetch('/helloFunction', {method:'POST', body:'{}'});
            </script>""")
            return
```

Also add `_html` helper:

```python
    def _html(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
```

- [ ] **Step 4: Create stability log**

Create `tests/e2e/e2e-stability-log.json`:

```json
{
  "graduation_status": "option-c",
  "graduation_target": "option-a",
  "consecutive_clean_runs_required": 6,
  "consecutive_clean_runs_achieved": 0,
  "runs": []
}
```

After the first clean opt-in e2e run, generate the recorded run with PowerShell so the commit hash is concrete:

```powershell
$short = git rev-parse --short HEAD
@{
  graduation_status = "option-c"
  graduation_target = "option-a"
  consecutive_clean_runs_required = 6
  consecutive_clean_runs_achieved = 1
  runs = @(
    @{
      id = 1
      date = "2026-06-04"
      commit = $short
      trigger = "phase-7b-merge"
      result = "pass"
      flaky = $false
      scanners_covered = @(
        "auth_check",
        "api_exposure",
        "cors_check",
        "info_disclosure",
        "sql_injection",
        "xss_check",
        "mass_assignment",
        "idor_check",
        "http_method_tampering",
        "rate_limit_check",
        "firebase_auth",
        "firebase_firestore",
        "firebase_rtdb",
        "firebase_storage",
        "firebase_functions"
      )
      notes = "Initial Phase 7B local opt-in e2e run."
    }
  )
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 tests\e2e\e2e-stability-log.json
```

- [ ] **Step 5: Add manual GitHub Actions workflow**

If `.github/workflows/vibe-iterator-e2e.yml` does not exist, create it:

```yaml
name: vibe-iterator E2E Smoke

on:
  workflow_dispatch:

jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Chrome
        uses: browser-actions/setup-chrome@v1

      - name: Install package and test dependencies
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e ".[dev]"

      - name: Run opt-in Selenium/CDP e2e smoke
        env:
          VIBE_ITERATOR_RUN_E2E_SMOKE: "1"
        run: python -m pytest tests/e2e -q
```

- [ ] **Step 6: Run default e2e skip check**

Run:

```powershell
python -m pytest tests/e2e -q
```

Expected: all e2e tests skipped.

- [ ] **Step 7: Run opt-in e2e**

Run:

```powershell
$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; python -m pytest tests/e2e -q
```

Expected: all e2e tests pass. If Chrome is unavailable locally, record that in the final report and do not mark Phase 7B done.

- [ ] **Step 8: Commit e2e track**

Run:

```powershell
git add tests/e2e/test_real_browser_smoke.py tests/e2e/e2e-stability-log.json .github/workflows/vibe-iterator-e2e.yml tests/fixtures/vulnerable_app/firebase_app.py
git commit -m "test(e2e): add phase 7b browser proof matrix"
```

Only include `firebase_app.py` if it was modified in this task.

---

## Task 5: Full Verification Before Docs

**Files:**
- No source edits unless tests expose a real issue.

- [ ] **Step 1: Run default suite**

Run:

```powershell
python -m pytest -q
```

Expected: zero failures.

- [ ] **Step 2: Run coverage**

Run:

```powershell
python -m pytest --cov=vibe_iterator --cov-report=term-missing
```

Expected:

```text
TOTAL ... >= 81%
vibe_iterator\utils\firebase_helpers.py ... >= 75%
```

- [ ] **Step 3: Run wheel smoke in temp directory**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$smokeRoot = Join-Path $env:TEMP "vibe-iterator-phase7b-wheel-$stamp"
$wheelDir = Join-Path $smokeRoot 'dist'
$venvDir = Join-Path $smokeRoot 'venv'
New-Item -ItemType Directory -Path $wheelDir -Force | Out-Null
uv build --wheel --out-dir $wheelDir
$wheel = Get-ChildItem -Path $wheelDir -Filter '*.whl' | Select-Object -First 1
if (-not $wheel) { throw 'No wheel produced' }
python -m venv $venvDir
& (Join-Path $venvDir 'Scripts\python.exe') -m pip install --upgrade pip
& (Join-Path $venvDir 'Scripts\python.exe') -m pip install $wheel.FullName
& (Join-Path $venvDir 'Scripts\vibe-iterator.exe') --help
```

Expected: installed CLI help renders.

- [ ] **Step 4: Remove generated local build folders if present**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath '.').Path
$targets = @('build', 'vibe_iterator.egg-info')
foreach ($target in $targets) {
  $resolved = Resolve-Path -LiteralPath $target -ErrorAction SilentlyContinue
  if ($resolved) {
    $path = $resolved.Path
    if (-not ($path.StartsWith($repo + [System.IO.Path]::DirectorySeparatorChar))) {
      throw "Refusing to remove path outside repo: $path"
    }
    Remove-Item -LiteralPath $path -Recurse -Force
  }
}
```

---

## Task 6: Final Docs Alignment

**Files:**
- Modify: `README.md`
- Modify: `docs/PHASES.md`
- Modify: `docs/SCANNERS.md`
- Modify: `docs/CONFIG.md`
- Modify: `docs/ADDING_SCANNERS.md`
- Verify: `.env.example`

- [ ] **Step 1: Update README status**

In `README.md`, update the Status line with the exact final verified default-suite count and coverage from Task 5. Use this PowerShell snippet to produce the sentence from recorded values after the final verification commands complete:

```powershell
$passed = Read-Host "Final passed test count from python -m pytest -q"
$skipped = Read-Host "Final skipped test count from python -m pytest -q"
$coverage = Read-Host "Final TOTAL coverage percentage"
"> **v0.1.0 — Phase 7B verification depth complete. $passed tests passing, $skipped skipped, $coverage% coverage.**"
```

Add one checked roadmap item:

```markdown
- [x] Phase 7B verification depth: Firebase helper coverage, edge fixtures, opt-in Selenium/CDP e2e matrix
```

- [ ] **Step 2: Add Phase 6 and Phase 7B to PHASES.md**

Append after Phase 5:

```markdown
---

## Phase 6 — Proof Quality Hardening

**Goal:** Reduce false positives and require stronger runtime proof before reporting scanner findings.

**Delivered:** Split-origin backend probing with `VIBE_ITERATOR_BACKEND_URL`, scanner proof-quality gates, structured tier/client-tampering evidence, storage proof cleanup, CORS severity labels, known fake key suppression, and CI/CD scan workflow support.

**Done when:** Full suite and coverage passed, fresh wheel install smoke passed, and `main` contained the Phase 6 scanner hardening merge.

---

## Phase 7B — Verification Depth

**Goal:** Prove the hardened scanners across deeper local fixtures and opt-in real browser e2e runs.

**Delivered:** Firebase helper coverage above 75%, real-world tier/storage/auth edge fixtures with positive and negative controls, opt-in Selenium/CDP e2e proof matrix, e2e stability log, and final docs alignment.

**Done when:** The Phase-Done Gate in `docs/superpowers/specs/2026-06-03-phase-7b-readiness-design.md` is fully checked by verification output.
```

- [ ] **Step 3: Add proof-quality vocabulary to SCANNERS.md**

After "Scanner Rules", add:

```markdown
## Proof Quality Vocabulary

Many hardened scanners include `evidence["proof_quality"]` to distinguish strong runtime proof from weaker discovery signals. New scanners should include this field whenever they report exploitable behavior, or document why it does not apply.

Common values include:

| Value | Meaning |
| ----- | ------- |
| `protected_api_path_replayed_without_auth` | A protected API request was replayed without auth and still returned protected data. |
| `protected_route_path_loaded_without_auth` | A protected route loaded after auth was removed and showed protected-page signals. |
| `structured_api_response_contains_tampered_tier` | A structured JSON API response accepted a tampered tier/plan value. |
| `structured_api_response_contains_tampered_authorization_value` | A structured JSON API response accepted a tampered role/admin/permission value. |
| `resource_write_response_contains_injected_privileged_field` | A write endpoint accepted and returned an injected privileged field. |
| `oversized_storage_upload_accepted` | Storage accepted a probe upload that should have exceeded size limits. |
| `dangerous_mime_storage_upload_accepted` | Storage accepted a blocked MIME type. |
| `reflected_origin_allows_credentials` | CORS reflected an untrusted origin while credentials were allowed. |
| `wildcard_origin_without_credentials` | CORS allowed wildcard origin without credentials. |
| `api_documentation_response` | A sensitive documentation endpoint returned API schema content. |
| `env_file_key_value_response` | A sensitive path returned environment-style key/value secrets. |
```

- [ ] **Step 4: Verify CONFIG.md backend URL coverage**

Run:

```powershell
Select-String -Path docs\CONFIG.md -Pattern "VIBE_ITERATOR_BACKEND_URL" -Context 2,2
```

If it already documents the variable, add only a short note that scanners send `Origin` from `VIBE_ITERATOR_TARGET` when probing `BACKEND_URL`:

```markdown
When `VIBE_ITERATOR_BACKEND_URL` is set, runtime API probes target that backend directly and send an `Origin` header derived from `VIBE_ITERATOR_TARGET`.
```

- [ ] **Step 5: Add scanner-author proof gate note**

In `docs/ADDING_SCANNERS.md`, add near the evidence guidance:

```markdown
### Proof Quality Evidence

If a scanner reports exploitable runtime behavior, include `proof_quality` in the finding evidence. Use a stable snake_case value that describes the proof, not the vulnerability class. Example:

```python
evidence={
    "proof_quality": "structured_api_response_contains_tampered_authorization_value",
    "request": {"method": "PATCH", "url": url},
    "response": {"status": 200, "json_path": "role", "matched_value": "admin"},
}
```

If `proof_quality` does not apply, explain why in the scanner tests or scanner docs.
```

- [ ] **Step 6: Run docs encoding test**

Run:

```powershell
python -m pytest tests/test_docs/test_encoding.py -q
```

Expected: pass.

- [ ] **Step 7: Commit docs**

Run:

```powershell
git add README.md docs/PHASES.md docs/SCANNERS.md docs/CONFIG.md docs/ADDING_SCANNERS.md .env.example
git commit -m "docs: align phase 7b verification behavior"
```

Only include `.env.example` if it changed.

---

## Task 7: Final Phase-Done Verification

**Files:**
- No edits expected.

- [ ] **Step 1: Run default suite**

Run:

```powershell
python -m pytest -q
```

Expected: zero failures.

- [ ] **Step 2: Run coverage**

Run:

```powershell
python -m pytest --cov=vibe_iterator --cov-report=term-missing
```

Expected: overall coverage at least 81%; `firebase_helpers.py` at least 75%.

- [ ] **Step 3: Run opt-in e2e**

Run:

```powershell
$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; python -m pytest tests/e2e -q
```

Expected: zero failures. If this cannot run because Chrome is unavailable, stop and report the blocker; do not call Phase 7B complete.

- [ ] **Step 4: Run wheel/install smoke**

Use the command from Task 5 Step 3.

Expected: installed `vibe-iterator --help` prints CLI help.

- [ ] **Step 5: Confirm proof gates were not loosened**

Run:

```powershell
git diff main...HEAD -- vibe_iterator/scanners
```

Review any scanner diffs. Confirm changes only tighten proof, add safe parsing, or fix bugs exposed by tests.

- [ ] **Step 6: Final status**

Run:

```powershell
git status --short --branch
git log --oneline --decorate -8
```

Expected: working tree clean except pre-existing local artifacts if still present:

```text
?? docs/results.md
?? vibe-iterator.discovered.yaml
```

---

## Self-Review

- Spec coverage: Tracks 1-4 are mapped to Tasks 1-6, and the Phase-Done Gate is mapped to Task 7.
- Marker scan: no unresolved work markers are intended in this plan.
- Type consistency: helper names match `vibe_iterator/utils/firebase_helpers.py`; scanner test files match existing paths.
- Risk control: e2e remains opt-in, external services are avoided, docs update is last, and Phase 6 proof gates are preserved.
