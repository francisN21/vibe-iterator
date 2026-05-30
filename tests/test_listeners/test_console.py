"""Tests for the ConsoleListener — uses mock Chrome browser log entries, no live browser."""

from __future__ import annotations

from vibe_iterator.listeners.console import ConsoleListener

# Chrome browser log level names
_CHROME_LEVELS = {"error": "SEVERE", "warn": "WARNING", "log": "INFO", "debug": "DEBUG"}


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _fire_log_entry(listener: ConsoleListener, level: str, text: str, url: str | None = None) -> None:
    """Inject a Chrome browser log entry (Log domain format)."""
    chrome_level = _CHROME_LEVELS.get(level, "INFO")
    if url:
        message = f"{url} 42 | {text}"
    else:
        message = text
    listener._process_entry({"level": chrome_level, "message": message, "timestamp": 1000.0})


def _fire_console_api(listener: ConsoleListener, level: str, *values: str) -> None:
    """Inject a Chrome browser log entry (Runtime.consoleAPICalled format)."""
    chrome_level = _CHROME_LEVELS.get(level, "INFO")
    combined = " ".join(values)
    message = f"http://app.com/main.js 10 | {combined}"
    listener._process_entry({"level": chrome_level, "message": message, "timestamp": 1001.0})


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
