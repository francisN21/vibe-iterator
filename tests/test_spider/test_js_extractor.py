"""Tests for js_extractor.py — mocks session.evaluate, no browser needed."""
from __future__ import annotations
from unittest.mock import MagicMock
from vibe_iterator.spider.js_extractor import extract_js_routes


def _session(return_value) -> MagicMock:
    s = MagicMock()
    s.evaluate.return_value = return_value
    return s


def test_routes_returned():
    result = extract_js_routes(_session(["/", "/about", "/dashboard"]))
    assert "/" in result
    assert "/about" in result
    assert "/dashboard" in result


def test_empty_list_returned_when_no_framework():
    assert extract_js_routes(_session([])) == []


def test_cdp_exception_returns_empty():
    s = MagicMock()
    s.evaluate.side_effect = RuntimeError("CDP error")
    assert extract_js_routes(s) == []


def test_none_return_is_empty():
    assert extract_js_routes(_session(None)) == []


def test_relative_path_normalized():
    result = extract_js_routes(_session(["about", "contact"]))
    assert "/about" in result
    assert "/contact" in result


def test_trailing_slash_stripped():
    result = extract_js_routes(_session(["/dashboard/"]))
    assert "/dashboard" in result
    assert "/dashboard/" not in result
