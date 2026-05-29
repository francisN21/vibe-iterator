# Firebase Scanner — Plan 1: Helpers & Fixture

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `firebase_helpers.py` (all shared utilities) and `firebase_app.py` (the vulnerable HTTP fixture used by all proof tests).

**Architecture:** TDD from the bottom up — helpers are pure functions testable in isolation; fixture is a `ThreadingHTTPServer` context manager matching the shape of the existing `VulnerableApp`.

**Tech Stack:** Python stdlib (`urllib.request`, `json`, `re`, `base64`, `threading`), `pytest`, `unittest.mock`

---

## Task 1: `firebase_helpers.py` — module skeleton + constants

**Files:**
- Create: `vibe_iterator/utils/firebase_helpers.py`
- Create: `tests/test_utils/test_firebase_helpers.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_utils/test_firebase_helpers.py
"""Unit tests for Firebase helper utilities."""
from __future__ import annotations
from vibe_iterator.utils.firebase_helpers import PROBE_PREFIX, REQUEST_TIMEOUT, truncate

def test_constants() -> None:
    assert PROBE_PREFIX == "vibe_iterator_probe_"
    assert REQUEST_TIMEOUT == 6

def test_truncate_long_string() -> None:
    assert truncate("abcdef", 3) == "abc...[truncated]"

def test_truncate_short_string() -> None:
    assert truncate("abc", 10) == "abc"
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_utils/test_firebase_helpers.py -v
```
Expected: `ImportError` — module does not exist yet.

- [ ] **Step 3: Create the module with constants and `truncate`**

```python
# vibe_iterator/utils/firebase_helpers.py
"""Shared utilities for Firebase-specific scanners."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

PROBE_PREFIX = "vibe_iterator_probe_"
REQUEST_TIMEOUT = 6
IDENTITY_TOOLKIT_BASE = "https://identitytoolkit.googleapis.com/v1"

_FUNCTION_HOST_RE = re.compile(
    r"https://([a-z0-9-]+)\.cloudfunctions\.net|https://([a-z0-9-]+)\.([a-z0-9-]+)\.run\.app"
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")


def truncate(text: str, max_len: int = 300) -> str:
    s = str(text)
    return s if len(s) <= max_len else s[:max_len] + "...[truncated]"
```

- [ ] **Step 4: Run to verify pass**

```
pytest tests/test_utils/test_firebase_helpers.py::test_constants tests/test_utils/test_firebase_helpers.py::test_truncate_long_string tests/test_utils/test_firebase_helpers.py::test_truncate_short_string -v
```
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/utils/firebase_helpers.py tests/test_utils/test_firebase_helpers.py
git commit -m "feat: add firebase_helpers skeleton — constants and truncate"
```

---

## Task 2: Config extraction helpers

**Files:**
- Modify: `vibe_iterator/utils/firebase_helpers.py`
- Modify: `tests/test_utils/test_firebase_helpers.py`

- [ ] **Step 1: Write failing tests**

```python
# append to tests/test_utils/test_firebase_helpers.py
from unittest.mock import MagicMock
from vibe_iterator.utils.firebase_helpers import (
    extract_firebase_config, detect_firebase_config,
)

def test_extract_firebase_config_compat_sdk() -> None:
    session = MagicMock()
    session.evaluate.return_value = {
        "apiKey": "key1", "projectId": "proj1",
        "databaseURL": "https://proj1.firebaseio.com",
        "storageBucket": "proj1.appspot.com", "authDomain": "proj1.firebaseapp.com",
    }
    cfg = extract_firebase_config(session)
    assert cfg["projectId"] == "proj1"
    assert cfg["apiKey"] == "key1"

def test_extract_firebase_config_exception_returns_empty() -> None:
    session = MagicMock()
    session.evaluate.side_effect = Exception("CDP error")
    assert extract_firebase_config(session) == {}

def test_detect_firebase_config_from_rtdb_url() -> None:
    req = MagicMock()
    req.url = "https://myproject-default-rtdb.firebaseio.com/users.json"
    result = detect_firebase_config([req])
    assert result is not None
    assert result.get("projectId") == "myproject"

def test_detect_firebase_config_none_when_no_firebase() -> None:
    req = MagicMock()
    req.url = "https://example.com/api/data"
    assert detect_firebase_config([req]) is None
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_utils/test_firebase_helpers.py -k "config" -v
```
Expected: `ImportError` on the new names.

- [ ] **Step 3: Implement `extract_firebase_config` and `detect_firebase_config`**

```python
# append to vibe_iterator/utils/firebase_helpers.py

_EXTRACT_CONFIG_JS = """
(() => {
  try {
    if (window.firebase && window.firebase.apps && window.firebase.apps.length) {
      const o = window.firebase.apps[0].options || {};
      return {apiKey:o.apiKey,projectId:o.projectId,databaseURL:o.databaseURL,
              storageBucket:o.storageBucket,authDomain:o.authDomain};
    }
    const d = window.__FIREBASE_DEFAULTS__ || window.__firebase_defaults__;
    if (d && d.config) return d.config;
    if (d && d.projectId) return d;
    for (const k of ['firebaseConfig','__firebaseConfig','FIREBASE_CONFIG']) {
      if (window[k] && window[k].projectId) return window[k];
    }
    return {};
  } catch(e) { return {}; }
})()
""".strip()


def extract_firebase_config(session: Any) -> dict:
    try:
        result = session.evaluate(_EXTRACT_CONFIG_JS)
        return result if isinstance(result, dict) else {}
    except Exception:
        return {}


_RTDB_HOST_RE = re.compile(r"https://([a-z0-9-]+?)(?:-default-rtdb)?\.firebaseio\.com")
_API_KEY_RE = re.compile(r"[?&]key=([A-Za-z0-9_\-]+)")
_BUCKET_RE = re.compile(r"https://firebasestorage\.googleapis\.com/v0/b/([^/]+)/")


def detect_firebase_config(network_events: list[Any]) -> dict | None:
    cfg: dict = {}
    for event in network_events:
        url = getattr(event, "url", "") or ""
        m = _RTDB_HOST_RE.search(url)
        if m:
            cfg.setdefault("projectId", m.group(1))
            cfg.setdefault("databaseURL", f"https://{m.group(1)}-default-rtdb.firebaseio.com")
        if "identitytoolkit.googleapis.com" in url:
            km = _API_KEY_RE.search(url)
            if km:
                cfg.setdefault("apiKey", km.group(1))
        bm = _BUCKET_RE.search(url)
        if bm:
            cfg.setdefault("storageBucket", bm.group(1))
        if "firebaseapp.com" in url:
            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
                if host.endswith(".firebaseapp.com"):
                    cfg.setdefault("authDomain", host)
                    cfg.setdefault("projectId", host.replace(".firebaseapp.com", ""))
            except Exception:
                pass
    return cfg if cfg else None
```

- [ ] **Step 4: Run to verify pass**

```
pytest tests/test_utils/test_firebase_helpers.py -k "config" -v
```
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/utils/firebase_helpers.py tests/test_utils/test_firebase_helpers.py
git commit -m "feat: add firebase_helpers config extraction"
```

---

## Task 3: ID token + CDP snippet builders

**Files:**
- Modify: `vibe_iterator/utils/firebase_helpers.py`
- Modify: `tests/test_utils/test_firebase_helpers.py`

- [ ] **Step 1: Write failing tests**

```python
# append to tests/test_utils/test_firebase_helpers.py
from vibe_iterator.utils.firebase_helpers import (
    get_firebase_id_token,
    build_firestore_read_snippet, build_firestore_write_snippet,
    build_rtdb_read_snippet, build_rtdb_write_snippet,
    build_storage_download_snippet, build_storage_upload_snippet,
    PROBE_PREFIX,
)

def test_get_firebase_id_token_returns_token() -> None:
    session = MagicMock()
    session.evaluate.return_value = "eyJfake.token.here"
    assert get_firebase_id_token(session) == "eyJfake.token.here"

def test_get_firebase_id_token_exception_returns_none() -> None:
    session = MagicMock()
    session.evaluate.side_effect = Exception("CDP error")
    assert get_firebase_id_token(session) is None

def test_firestore_read_snippet_contains_collection() -> None:
    js = build_firestore_read_snippet("users", "uid123")
    assert "users" in js
    assert "uid123" in js

def test_firestore_write_snippet_requires_probe_prefix() -> None:
    doc_id = PROBE_PREFIX + "test"
    js = build_firestore_write_snippet("users", doc_id, {"role": "admin"})
    assert PROBE_PREFIX in js
    assert "role" in js

def test_rtdb_read_snippet_contains_path() -> None:
    js = build_rtdb_read_snippet("users/uid1")
    assert "users/uid1" in js

def test_rtdb_write_snippet_requires_probe_prefix() -> None:
    path = PROBE_PREFIX + "canary"
    js = build_rtdb_write_snippet(path, {"ts": 1})
    assert PROBE_PREFIX in js

def test_storage_snippets_contain_path() -> None:
    dl = build_storage_download_snippet("avatars/user1.png")
    ul = build_storage_upload_snippet(PROBE_PREFIX + "canary.txt", b"hello")
    assert "avatars/user1.png" in dl
    assert PROBE_PREFIX in ul
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_utils/test_firebase_helpers.py -k "token or snippet" -v
```
Expected: `ImportError` on missing names.

- [ ] **Step 3: Implement**

```python
# append to vibe_iterator/utils/firebase_helpers.py
import base64 as _base64

_GET_TOKEN_JS = """
(async () => {
  try {
    if (window.firebase && window.firebase.auth) {
      const u = window.firebase.auth().currentUser;
      return u ? await u.getIdToken(true) : null;
    }
    const auth = (window.__VIBE_AUTH__) || (window.getAuth && window.getAuth());
    if (auth && auth.currentUser) return await auth.currentUser.getIdToken(true);
    return null;
  } catch(e) { return null; }
})()
""".strip()


def get_firebase_id_token(session: Any) -> str | None:
    try:
        result = session.evaluate(_GET_TOKEN_JS)
        return result if isinstance(result, str) else None
    except Exception:
        return None


def build_firestore_read_snippet(collection: str, doc_id: str | None = None) -> str:
    sc = collection.replace("'", "\\'")
    if doc_id:
        sd = doc_id.replace("'", "\\'")
        return (
            f"(async()=>{{try{{const db=(window.firebase&&window.firebase.firestore)"
            f"?window.firebase.firestore():(window.__VIBE_DB__||null);"
            f"if(!db)return{{error:'Firestore SDK not found on window'}};"
            f"const snap=await db.collection('{sc}').doc('{sd}').get();"
            f"return{{data:snap.exists?snap.data():null,exists:snap.exists}};"
            f"}}catch(e){{return{{error:e.message}}}}}})()"
        )
    return (
        f"(async()=>{{try{{const db=(window.firebase&&window.firebase.firestore)"
        f"?window.firebase.firestore():(window.__VIBE_DB__||null);"
        f"if(!db)return{{error:'Firestore SDK not found on window'}};"
        f"const snap=await db.collection('{sc}').limit(5).get();"
        f"return{{data:snap.docs.map(d=>{{return{{id:d.id,...d.data()}}}})}}}}"
        f"catch(e){{return{{error:e.message}}}}}})()"
    )


def build_firestore_write_snippet(collection: str, doc_id: str, data: dict) -> str:
    assert PROBE_PREFIX in doc_id, f"doc_id must contain {PROBE_PREFIX}"
    sc = collection.replace("'", "\\'")
    sd = doc_id.replace("'", "\\'")
    dj = json.dumps(data)
    return (
        f"(async()=>{{try{{const db=(window.firebase&&window.firebase.firestore)"
        f"?window.firebase.firestore():(window.__VIBE_DB__||null);"
        f"if(!db)return{{error:'Firestore SDK not found on window'}};"
        f"await db.collection('{sc}').doc('{sd}').set({dj});"
        f"return{{ok:true}}}}catch(e){{return{{error:e.message}}}}}})()"
    )


def build_rtdb_read_snippet(path: str) -> str:
    sp = path.replace("'", "\\'")
    return (
        f"(async()=>{{try{{const db=(window.firebase&&window.firebase.database)"
        f"?window.firebase.database():(window.__VIBE_RTDB__||null);"
        f"if(!db)return{{error:'RTDB SDK not found on window'}};"
        f"const snap=await db.ref('{sp}').once('value');"
        f"return{{data:snap.val()}}}}catch(e){{return{{error:e.message}}}}}})()"
    )


def build_rtdb_write_snippet(path: str, data: dict) -> str:
    assert PROBE_PREFIX in path, f"path must contain {PROBE_PREFIX}"
    sp = path.replace("'", "\\'")
    dj = json.dumps(data)
    return (
        f"(async()=>{{try{{const db=(window.firebase&&window.firebase.database)"
        f"?window.firebase.database():(window.__VIBE_RTDB__||null);"
        f"if(!db)return{{error:'RTDB SDK not found on window'}};"
        f"await db.ref('{sp}').set({dj});"
        f"return{{ok:true}}}}catch(e){{return{{error:e.message}}}}}})()"
    )


def build_storage_download_snippet(path: str) -> str:
    sp = path.replace("'", "\\'")
    return (
        f"(async()=>{{try{{const st=(window.firebase&&window.firebase.storage)"
        f"?window.firebase.storage():(window.__VIBE_STORAGE__||null);"
        f"if(!st)return{{error:'Storage SDK not found on window'}};"
        f"const url=await st.ref('{sp}').getDownloadURL();"
        f"const r=await fetch(url);const t=await r.text();"
        f"return{{ok:true,status:r.status,excerpt:t.slice(0,200)}}}}"
        f"catch(e){{return{{error:e.message}}}}}})()"
    )


def build_storage_upload_snippet(path: str, content_bytes: bytes) -> str:
    assert PROBE_PREFIX in path, f"path must contain {PROBE_PREFIX}"
    sp = path.replace("'", "\\'")
    b64 = _base64.b64encode(content_bytes).decode()
    return (
        f"(async()=>{{try{{const st=(window.firebase&&window.firebase.storage)"
        f"?window.firebase.storage():(window.__VIBE_STORAGE__||null);"
        f"if(!st)return{{error:'Storage SDK not found on window'}};"
        f"const bytes=Uint8Array.from(atob('{b64}'),c=>c.charCodeAt(0));"
        f"await st.ref('{sp}').put(bytes);"
        f"return{{ok:true}}}}catch(e){{return{{error:e.message}}}}}})()"
    )
```

- [ ] **Step 4: Run to verify pass**

```
pytest tests/test_utils/test_firebase_helpers.py -k "token or snippet" -v
```
Expected: 8 PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/utils/firebase_helpers.py tests/test_utils/test_firebase_helpers.py
git commit -m "feat: add firebase_helpers token extraction and CDP snippet builders"
```

---

## Task 4: REST request builders + write-safety contract

**Files:**
- Modify: `vibe_iterator/utils/firebase_helpers.py`
- Modify: `tests/test_utils/test_firebase_helpers.py`

- [ ] **Step 1: Write failing tests**

```python
# append to tests/test_utils/test_firebase_helpers.py
import io
from unittest.mock import patch, MagicMock
from vibe_iterator.utils.firebase_helpers import (
    rest_rtdb_get, rest_rtdb_write, rest_rtdb_delete,
    rest_firestore_get, rest_firestore_write, rest_firestore_delete,
    rest_storage_download, rest_storage_upload, rest_storage_delete,
    _to_firestore_fields, _from_firestore_fields,
    discover_function_urls, find_id_tokens,
    PROBE_PREFIX,
)

def _fake_resp(body: str, status: int):
    r = MagicMock()
    r.read.return_value = body.encode()
    r.status = status
    r.__enter__ = lambda s: s
    r.__exit__ = MagicMock(return_value=False)
    return r

def test_rest_rtdb_get_success() -> None:
    with patch("urllib.request.urlopen", return_value=_fake_resp('{"a":1}', 200)):
        body, status = rest_rtdb_get("https://proj.firebaseio.com", "users")
    assert status == 200
    assert '"a"' in body

def test_rest_rtdb_get_appends_auth_param() -> None:
    captured = []
    def fake_open(req, timeout):
        captured.append(req.full_url)
        return _fake_resp("{}", 200)
    with patch("urllib.request.urlopen", side_effect=fake_open):
        rest_rtdb_get("https://proj.firebaseio.com", "users", id_token="tok123")
    assert "auth=tok123" in captured[0]

def test_rest_rtdb_write_refuses_without_probe_prefix() -> None:
    body, status = rest_rtdb_write("https://proj.firebaseio.com", "users/evil", {"x": 1})
    assert status is None
    assert body == ""

def test_rest_rtdb_write_accepts_probe_path() -> None:
    with patch("urllib.request.urlopen", return_value=_fake_resp('{}', 200)):
        body, status = rest_rtdb_write(
            "https://proj.firebaseio.com", PROBE_PREFIX + "canary", {"ts": 1}
        )
    assert status == 200

def test_rest_rtdb_get_http_error() -> None:
    import urllib.error
    err = urllib.error.HTTPError("url", 403, "Forbidden", {}, io.BytesIO(b'{"error":"denied"}'))
    with patch("urllib.request.urlopen", side_effect=err):
        body, status = rest_rtdb_get("https://proj.firebaseio.com", "secret")
    assert status == 403

def test_rest_rtdb_get_unknown_exception() -> None:
    with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
        body, status = rest_rtdb_get("https://proj.firebaseio.com", "x")
    assert body == ""
    assert status is None

def test_to_from_firestore_fields_roundtrip() -> None:
    data = {"name": "alice", "age": 30, "active": True}
    doc = _to_firestore_fields(data)
    assert doc["fields"]["name"] == {"stringValue": "alice"}
    assert doc["fields"]["age"] == {"integerValue": "30"}
    assert doc["fields"]["active"] == {"booleanValue": True}
    roundtrip = _from_firestore_fields(doc)
    assert roundtrip["name"] == "alice"
    assert roundtrip["age"] == 30

def test_discover_function_urls() -> None:
    reqs = [MagicMock(url="https://us-central1-proj.cloudfunctions.net/hello"),
            MagicMock(url="https://example.com/api"),
            MagicMock(url="https://us-central1-proj.cloudfunctions.net/hello")]
    urls = discover_function_urls(reqs)
    assert len(urls) == 1
    assert "cloudfunctions.net" in urls[0]

def test_find_id_tokens() -> None:
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signature"
    text = f"Authorization: Bearer {token} other stuff"
    found = find_id_tokens(text)
    assert token in found
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_utils/test_firebase_helpers.py -k "rest or firestore_fields or discover or find_id" -v
```
Expected: `ImportError` on missing names.

- [ ] **Step 3: Implement REST builders + private helpers**

```python
# append to vibe_iterator/utils/firebase_helpers.py

# ---- Firestore REST typed-value conversion --------------------------------

def _to_firestore_fields(data: dict) -> dict:
    fields = {}
    for k, v in data.items():
        if isinstance(v, bool):
            fields[k] = {"booleanValue": v}
        elif isinstance(v, int):
            fields[k] = {"integerValue": str(v)}
        elif isinstance(v, float):
            fields[k] = {"doubleValue": v}
        elif v is None:
            fields[k] = {"nullValue": None}
        else:
            fields[k] = {"stringValue": str(v)}
    return {"fields": fields}


def _from_firestore_fields(doc: dict) -> dict:
    out = {}
    for k, v in (doc.get("fields") or {}).items():
        if "stringValue" in v:
            out[k] = v["stringValue"]
        elif "integerValue" in v:
            out[k] = int(v["integerValue"])
        elif "doubleValue" in v:
            out[k] = v["doubleValue"]
        elif "booleanValue" in v:
            out[k] = v["booleanValue"]
        else:
            out[k] = None
    return out


# ---- RTDB REST -----------------------------------------------------------

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


def rest_rtdb_write(database_url: str, path: str, data: dict, id_token: str | None = None) -> tuple[str, int | None]:
    if PROBE_PREFIX not in path:
        return "", None
    base = (database_url or "").rstrip("/")
    seg = path.strip("/")
    url = f"{base}/{seg}.json"
    if id_token:
        url += f"?auth={urllib.parse.quote(id_token)}"
    body = json.dumps(data).encode()
    try:
        req = urllib.request.Request(url, data=body, method="PUT",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


def rest_rtdb_delete(database_url: str, path: str, id_token: str | None = None) -> tuple[str, int | None]:
    base = (database_url or "").rstrip("/")
    seg = path.strip("/")
    url = f"{base}/{seg}.json"
    if id_token:
        url += f"?auth={urllib.parse.quote(id_token)}"
    try:
        req = urllib.request.Request(url, method="DELETE")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


# ---- Firestore REST -------------------------------------------------------

def rest_firestore_get(project_id: str, collection: str, doc_id: str,
                       id_token: str | None = None) -> tuple[str, int | None]:
    url = (f"https://firestore.googleapis.com/v1/projects/{project_id}"
           f"/databases/(default)/documents/{collection}/{doc_id}")
    headers: dict = {}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


def rest_firestore_write(project_id: str, collection: str, doc_id: str,
                         data: dict, id_token: str | None = None) -> tuple[str, int | None]:
    if PROBE_PREFIX not in doc_id:
        return "", None
    url = (f"https://firestore.googleapis.com/v1/projects/{project_id}"
           f"/databases/(default)/documents/{collection}/{doc_id}")
    headers: dict = {"Content-Type": "application/json"}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    body = json.dumps(_to_firestore_fields(data)).encode()
    try:
        req = urllib.request.Request(url, data=body, method="PATCH", headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


def rest_firestore_delete(project_id: str, collection: str, doc_id: str,
                          id_token: str | None = None) -> tuple[str, int | None]:
    url = (f"https://firestore.googleapis.com/v1/projects/{project_id}"
           f"/databases/(default)/documents/{collection}/{doc_id}")
    headers: dict = {}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    try:
        req = urllib.request.Request(url, headers=headers, method="DELETE")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


# ---- Storage REST --------------------------------------------------------

def rest_storage_download(bucket: str, path: str,
                          id_token: str | None = None) -> tuple[str, int | None]:
    enc = urllib.parse.quote(path, safe="")
    url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{enc}?alt=media"
    headers: dict = {}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


def rest_storage_upload(bucket: str, path: str, content: bytes,
                        id_token: str | None = None) -> tuple[str, int | None]:
    if PROBE_PREFIX not in path:
        return "", None
    enc = urllib.parse.quote(path, safe="")
    url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?name={enc}"
    headers: dict = {"Content-Type": "application/octet-stream"}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    try:
        req = urllib.request.Request(url, data=content, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


def rest_storage_delete(bucket: str, path: str,
                        id_token: str | None = None) -> tuple[str, int | None]:
    enc = urllib.parse.quote(path, safe="")
    url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{enc}"
    headers: dict = {}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    try:
        req = urllib.request.Request(url, headers=headers, method="DELETE")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code
        except Exception:
            return "", e.code
    except Exception:
        return "", None


# ---- Functions REST ------------------------------------------------------

def rest_functions_call(region: str, project_id: str, fn_name: str,
                        payload: dict, id_token: str | None = None) -> tuple[str, int | None]:
    url = f"https://{region}-{project_id}.cloudfunctions.net/{fn_name}"
    headers: dict = {"Content-Type": "application/json"}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    body = json.dumps(payload).encode()
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


# ---- Discovery helpers ---------------------------------------------------

def discover_function_urls(network_events: list[Any]) -> list[str]:
    seen: set[str] = set()
    for event in network_events:
        url = getattr(event, "url", "") or ""
        m = _FUNCTION_HOST_RE.search(url)
        if m:
            base = url.split("?")[0]
            seen.add(base)
    return list(seen)


def find_id_tokens(text: str) -> list[str]:
    return _JWT_RE.findall(text or "")


# ---- LLM prompt builder --------------------------------------------------

def build_firebase_llm_prompt(
    *,
    title: str,
    severity: Any,
    scanner: str,
    page: str,
    category: str,
    description: str,
    evidence_summary: str,
    detected_services: str,
) -> str:
    sev_str = severity.value.upper() if hasattr(severity, "value") else str(severity).upper()
    return (
        f"You are a security expert helping me fix a vulnerability in my Firebase web application.\n\n"
        f"VULNERABILITY: {title}\n"
        f"SEVERITY: {sev_str}\n"
        f"SCANNER: {scanner}\n"
        f"PAGE: {page}\n"
        f"CATEGORY: {category}\n\n"
        f"WHAT WAS FOUND:\n{description}\n\n"
        f"EVIDENCE:\n{evidence_summary}\n\n"
        f"YOUR TASK:\n"
        f"Fix the vulnerability described above in my codebase.\n\n"
        f"1. Explain the root cause\n"
        f"2. Show the specific Firebase Security Rules change or code change needed\n"
        f"3. Show the exact Firebase Console setting or rules config to apply\n"
        f"4. Confirm what to test after applying the fix\n\n"
        f"My stack: Firebase ({detected_services})"
    )
```

- [ ] **Step 4: Run to verify pass**

```
pytest tests/test_utils/test_firebase_helpers.py -v
```
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/utils/firebase_helpers.py tests/test_utils/test_firebase_helpers.py
git commit -m "feat: add firebase_helpers REST builders, discovery utils, LLM prompt builder"
```

---

## Task 5: Firebase vulnerable fixture app

**Files:**
- Create: `tests/fixtures/vulnerable_app/firebase_app.py`

- [ ] **Step 1: Write a minimal smoke test first**

```python
# create tests/test_scanners/test_firebase_fixture_smoke.py
"""Smoke test: fixture starts, routes respond, fixture stops cleanly."""
from __future__ import annotations
import urllib.request
from tests.fixtures.vulnerable_app.firebase_app import FirebaseVulnerableApp

def test_fixture_starts_and_serves_rtdb_root() -> None:
    with FirebaseVulnerableApp() as app:
        url = app.base_url + "/.json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200

def test_fixture_secured_path_returns_401() -> None:
    with FirebaseVulnerableApp() as app:
        url = app.base_url + "/secured/.json"
        try:
            urllib.request.urlopen(url, timeout=5)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 401
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_scanners/test_firebase_fixture_smoke.py -v
```
Expected: `ImportError` — `firebase_app` does not exist yet.

- [ ] **Step 3: Implement the fixture**

```python
# tests/fixtures/vulnerable_app/firebase_app.py
"""Firebase-shaped vulnerable HTTP fixture for proof tests.

All vulnerabilities are deliberate and local-only (127.0.0.1).
Routes simulate an open Firebase project (no Security Rules enforced):
  - RTDB:       GET/PUT/DELETE /{path}.json
  - Firestore:  GET/PATCH/DELETE /v1/projects/{pid}/databases/(default)/documents/{coll}/{doc}
  - Storage:    GET/POST/DELETE /v0/b/{bucket}/o[/{enc_path}]
  - Auth:       POST /v1/accounts:signUp, POST /v1/accounts:createAuthUri
  - Functions:  POST/GET/OPTIONS /{fn_name}  (any path not matched above)
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
_STORED: dict = {}   # simulates DB/Storage state within one test run


class FirebaseHandler(BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        qs = urllib.parse.parse_qs(p.query)

        # RTDB: secured path → 401
        if path.startswith("/secured/") or path == "/secured.json":
            self._json(401, {"error": "Permission denied"})
            return

        # RTDB: root or path.json
        if path.endswith(".json"):
            rtdb_path = path[:-5] or "/"
            if rtdb_path == "/" or rtdb_path == "":
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
                self._json(403, {"error": "PERMISSION_DENIED"})
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
            if name:
                _STORED[name] = raw
            self._json(200, {"name": name, "bucket": "proj.appspot.com"})
            return

        # Firestore: PATCH = write (handled in do_PUT but POST also comes here sometimes)
        if "/databases/(default)/documents/" in path:
            _STORED[path] = raw.decode()
            self._json(200, {"name": path, "fields": {}})
            return

        # Functions: any POST to unknown path → 200 (unauthenticated function)
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
            rtdb_path = path[:-5]
            _STORED[rtdb_path] = raw.decode()
            self._json(200, json.loads(raw) if raw else {})
            return

        self._json(404, {"error": "not found"})

    def do_PATCH(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""

        if "/databases/(default)/documents/" in path:
            _STORED[path] = raw.decode()
            self._json(200, {"name": path, "fields": {}})
            return

        self._json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        p = urllib.parse.urlparse(self.path)
        path = p.path
        _STORED.pop(path, None)

        # RTDB delete
        if path.endswith(".json"):
            self._json(200, {})
            return

        # Firestore delete
        if "/databases/(default)/documents/" in path:
            self._json(200, {})
            return

        # Storage delete
        if "/v0/b/" in path:
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


class FirebaseVulnerableApp:
    """Start the Firebase fixture on a random free port; use as context manager."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""

    def start(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), FirebaseHandler)
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
```

- [ ] **Step 4: Run smoke tests**

```
pytest tests/test_scanners/test_firebase_fixture_smoke.py -v
```
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```
git add tests/fixtures/vulnerable_app/firebase_app.py tests/test_scanners/test_firebase_fixture_smoke.py
git commit -m "feat: add FirebaseVulnerableApp fixture for proof tests"
```

---

## Task 6: Run full helpers test suite

- [ ] **Step 1: Run all helpers + fixture tests together**

```
pytest tests/test_utils/test_firebase_helpers.py tests/test_scanners/test_firebase_fixture_smoke.py -v
```
Expected: all PASS, no errors.

- [ ] **Step 2: Run existing suite to confirm no regressions**

```
pytest --ignore=tests/test_scanners/test_firebase_fixture_smoke.py --ignore=tests/test_utils/test_firebase_helpers.py -x -q
```
Expected: existing tests still green.

- [ ] **Step 3: Commit (only if step 2 found something to fix)**

If any regressions: fix, then:
```
git add -p
git commit -m "fix: resolve regression from firebase_helpers import"
```

---

**Plan 1 complete. Continue with Plan 2: RTDB + Storage scanners.**
