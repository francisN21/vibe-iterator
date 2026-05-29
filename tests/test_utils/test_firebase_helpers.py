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
