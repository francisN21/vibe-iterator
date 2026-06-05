"""Shared utilities for Firebase-specific scanners."""
from __future__ import annotations

import base64 as _base64
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

PROBE_PREFIX = "vibe_iterator_probe_"
REQUEST_TIMEOUT = 6
IDENTITY_TOOLKIT_BASE = "https://identitytoolkit.googleapis.com/v1"
LOCAL_REACHABILITY_TIMEOUT_SECONDS = 0.25
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOCAL_REACHABILITY_CACHE_SECONDS = 2.0
_CLOSED_LOCAL_ENDPOINTS: dict[tuple[str, int], float] = {}

_FUNCTION_HOST_RE = re.compile(
    r"https://([a-z0-9-]+)\.cloudfunctions\.net|https://([a-z0-9-]+)\.([a-z0-9-]+)\.run\.app"
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")


def truncate(text: str, max_len: int = 300) -> str:
    s = str(text)
    return s if len(s) <= max_len else s[:max_len] + "...[truncated]"


def is_closed_local_url(url: str) -> bool:
    """Return True when a localhost URL has no listener on its target port."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if host not in LOCAL_HOSTS:
        return False

    try:
        port = parsed.port
    except ValueError:
        return False
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    endpoint = (host, port)
    now = time.monotonic()
    cached_at = _CLOSED_LOCAL_ENDPOINTS.get(endpoint)
    if cached_at is not None and now - cached_at < LOCAL_REACHABILITY_CACHE_SECONDS:
        return True
    if cached_at is not None:
        _CLOSED_LOCAL_ENDPOINTS.pop(endpoint, None)

    try:
        with socket.create_connection(endpoint, timeout=LOCAL_REACHABILITY_TIMEOUT_SECONDS):
            return False
    except OSError:
        _CLOSED_LOCAL_ENDPOINTS[endpoint] = now
        return True


# --------------------------------------------------------------------------- #
# Config extraction helpers                                                    #
# --------------------------------------------------------------------------- #

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


_RTDB_HOST_RE = re.compile(
    r"https://([a-z0-9-]+?)(?:-default-rtdb)?\.(firebaseio\.com|firebasedatabase\.app)"
)
_API_KEY_RE = re.compile(r"[?&]key=([A-Za-z0-9_\-]+)")
_BUCKET_RE = re.compile(r"https://firebasestorage\.googleapis\.com/v0/b/([^/]+)/")


def detect_firebase_config(network_events: list[Any]) -> dict | None:
    cfg: dict = {}
    for event in network_events:
        url = getattr(event, "url", "") or ""
        m = _RTDB_HOST_RE.search(url)
        if m:
            project_id = m.group(1)
            domain = m.group(2)
            cfg.setdefault("projectId", project_id)
            if domain == "firebasedatabase.app":
                cfg.setdefault("databaseURL", f"https://{project_id}-default-rtdb.firebasedatabase.app")
            else:
                cfg.setdefault("databaseURL", f"https://{project_id}-default-rtdb.firebaseio.com")
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


# --------------------------------------------------------------------------- #
# ID token + CDP snippet builders                                              #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Firestore REST typed-value conversion                                        #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# RTDB REST                                                                    #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Firestore REST                                                               #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Storage REST                                                                 #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Functions REST                                                               #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Discovery helpers                                                            #
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# LLM prompt builder                                                           #
# --------------------------------------------------------------------------- #

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
