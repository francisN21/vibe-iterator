"""Unit tests for Firebase helper utilities."""
from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

from vibe_iterator.utils.firebase_helpers import (
    _CLOSED_LOCAL_ENDPOINTS,
    PROBE_PREFIX,
    REQUEST_TIMEOUT,
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


def test_constants() -> None:
    assert PROBE_PREFIX == "vibe_iterator_probe_"
    assert REQUEST_TIMEOUT == 6

def test_truncate_long_string() -> None:
    assert truncate("abcdef", 3) == "abc...[truncated]"

def test_truncate_short_string() -> None:
    assert truncate("abc", 10) == "abc"


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


def _fake_resp(body: str, status: int):
    r = MagicMock()
    r.read.return_value = body.encode()
    r.status = status
    r.__enter__ = lambda s: s
    r.__exit__ = MagicMock(return_value=False)
    return r


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


def test_detect_firebase_config_from_firebasedatabase_app_url() -> None:
    req = MagicMock()
    req.url = "https://myproject-default-rtdb.firebasedatabase.app/users.json"
    result = detect_firebase_config([req])
    assert result is not None
    assert result["projectId"] == "myproject"
    assert result["databaseURL"] == "https://myproject-default-rtdb.firebasedatabase.app"


def test_detect_firebase_config_from_regional_firebasedatabase_app_url() -> None:
    req = MagicMock()
    req.url = "https://myproject-default-rtdb.europe-west1.firebasedatabase.app/users.json"
    result = detect_firebase_config([req])
    assert result is not None
    assert result["projectId"] == "myproject"
    assert result["databaseURL"] == "https://myproject-default-rtdb.europe-west1.firebasedatabase.app"


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

def test_to_from_firestore_fields_roundtrip() -> None:
    data = {"name": "alice", "age": 30, "active": True}
    doc = _to_firestore_fields(data)
    assert doc["fields"]["name"] == {"stringValue": "alice"}
    assert doc["fields"]["age"] == {"integerValue": "30"}
    assert doc["fields"]["active"] == {"booleanValue": True}
    roundtrip = _from_firestore_fields(doc)
    assert roundtrip["name"] == "alice"
    assert roundtrip["age"] == 30


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


def test_rest_functions_call_success() -> None:
    with patch("urllib.request.urlopen", return_value=_fake_resp('{"result":"ok"}', 200)):
        body, status = rest_functions_call("us-central1", "myproj", "hello", {"x": 1})
    assert status == 200
    assert "result" in body


def test_rest_functions_call_http_error() -> None:
    import urllib.error
    err = urllib.error.HTTPError("url", 401, "Unauthorized", {}, io.BytesIO(b'{"error":"auth"}'))
    with patch("urllib.request.urlopen", side_effect=err):
        body, status = rest_functions_call("us-central1", "myproj", "hello", {})
    assert status == 401


def test_build_firebase_llm_prompt_contains_required_sections() -> None:
    from vibe_iterator.scanners.base import Severity
    result = build_firebase_llm_prompt(
        title="Test vuln",
        severity=Severity.HIGH,
        scanner="firebase_rtdb",
        page="http://localhost",
        category="Access Control",
        description="Some description",
        evidence_summary="Evidence here",
        detected_services="Realtime Database",
    )
    assert "Test vuln" in result
    assert "HIGH" in result
    assert "Firebase" in result
    assert "Realtime Database" in result
    assert "YOUR TASK" in result
