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
