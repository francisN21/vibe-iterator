"""Tests for the ConsoleListener — uses mock CDP events, no live browser."""

from __future__ import annotations

import pytest

from vibe_iterator.listeners.console import ConsoleListener, ConsoleEntry


# ------------------------------------------------------------------ #
# Helpers                                                            #
# ------------------------------------------------------------------ #

def _fire_log_entry(listener: ConsoleListener, level: str, text: str, url: str | None = None) -> None:
    listener._on_log_entry({
        "entry": {
            "level": level,
            "text": text,
            "url": url,
            "lineNumber": 42,
            "timestamp": 1000.0,
        }
    })


def _fire_console_api(listener: ConsoleListener, level: str, *values: str) -> None:
    listener._on_console_api({
        "type": level,
        "args": [{"value": v} for v in values],
        "stackTrace": {"callFrames": [{"url": "http://app.com/main.js", "lineNumber": 10}]},
        "timestamp": 1001.0,
    })


# ------------------------------------------------------------------ #
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestConsoleListenerCapture:
    def test_captures_log_entry(self) -> None:
        listener = ConsoleListener()
        _fire_log_entry(listener, "error", "Uncaught TypeError: x is not defined", "http://app.com/app.js")

        entries = listener.get_entries()
        assert len(entries) == 1
        assert entries[0].level == "error"
        assert "TypeError" in entries[0].text
        assert entries[0].url == "http://app.com/app.js"

    def test_captures_console_api_call(self) -> None:
        listener = ConsoleListener()
        _fire_console_api(listener, "warn", "Deprecated API used")

        entries = listener.get_entries()
        assert len(entries) == 1
        assert entries[0].level == "warn"
        assert "Deprecated" in entries[0].text

    def test_console_api_joins_multiple_args(self) -> None:
        listener = ConsoleListener()
        _fire_console_api(listener, "log", "User:", "admin@example.com")

        entries = listener.get_entries()
        assert "User:" in entries[0].text
        assert "admin@example.com" in entries[0].text

    def test_multiple_entries_accumulated(self) -> None:
        listener = ConsoleListener()
        _fire_log_entry(listener, "log", "App started")
        _fire_log_entry(listener, "warn", "Slow query detected")
        _fire_console_api(listener, "error", "API key exposed")

        assert len(listener.get_entries()) == 3


class TestConsoleListenerFilter:
    def test_get_entries_by_level_filters_correctly(self) -> None:
        listener = ConsoleListener()
        _fire_log_entry(listener, "log", "info message")
        _fire_log_entry(listener, "error", "error message")
        _fire_log_entry(listener, "warn", "warn message")

        errors = listener.get_entries_by_level("error")
        assert len(errors) == 1
        assert errors[0].level == "error"

    def test_get_entries_by_level_empty_when_no_match(self) -> None:
        listener = ConsoleListener()
        _fire_log_entry(listener, "log", "just a log")

        assert listener.get_entries_by_level("error") == []


class TestConsoleListenerClear:
    def test_clear_removes_all_entries(self) -> None:
        listener = ConsoleListener()
        _fire_log_entry(listener, "log", "msg1")
        _fire_log_entry(listener, "error", "msg2")
        assert len(listener.get_entries()) == 2

        listener.clear()
        assert listener.get_entries() == []
