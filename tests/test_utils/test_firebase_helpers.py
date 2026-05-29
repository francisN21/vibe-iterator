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
