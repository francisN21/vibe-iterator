"""CDP Console listener — captures all console output with level and source."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ConsoleEntry:
    """A single captured console message."""

    level: str          # "log" | "warn" | "error" | "info" | "debug"
    text: str           # Full message text
    url: str | None     # Source URL (if known)
    line: int | None    # Source line number (if known)
    timestamp: float    # CDP event timestamp


class ConsoleListener:
    """Attaches to Chrome's CDP Console/Log domain and records all output.

    Usage::

        listener = ConsoleListener()
        listener.attach(session)
        # ... page interactions ...
        entries = listener.get_entries()
        listener.detach()
    """

    def __init__(self) -> None:
        self._entries: list[ConsoleEntry] = []
        self._lock = threading.Lock()
        self._session: Any | None = None

    def attach(self, session: Any) -> None:
        """Register CDP event handlers on the browser session."""
        from vibe_iterator.crawler.browser import BrowserSession
        assert isinstance(session, BrowserSession)
        self._session = session

        driver = session.driver
        # Log domain gives richer context (source URL, line number) than Console domain
        driver.add_cdp_listener("Log.entryAdded", self._on_log_entry)
        # Also listen to Runtime.consoleAPICalled for console.log/warn/error calls
        driver.add_cdp_listener("Runtime.consoleAPICalled", self._on_console_api)

        # Enable Log domain (Console.enable was called in browser.launch())
        try:
            session.execute_cdp("Log.enable", {})
            session.execute_cdp("Runtime.enable", {})
        except Exception as exc:
            logger.debug("ConsoleListener.attach enable error (non-fatal): %s", exc)

    def detach(self) -> None:
        """Remove CDP listeners."""
        if self._session is None:
            return
        try:
            driver = self._session.driver
            driver.remove_cdp_listener("Log.entryAdded", self._on_log_entry)
            driver.remove_cdp_listener("Runtime.consoleAPICalled", self._on_console_api)
        except Exception as exc:
            logger.debug("ConsoleListener.detach error (non-fatal): %s", exc)
        finally:
            self._session = None

    def get_entries(self) -> list[ConsoleEntry]:
        """Return a snapshot of all captured console entries."""
        with self._lock:
            return list(self._entries)

    def get_entries_by_level(self, level: str) -> list[ConsoleEntry]:
        """Return entries matching the given level (e.g., 'error', 'warn')."""
        return [e for e in self.get_entries() if e.level == level]

    def clear(self) -> None:
        """Discard all captured entries."""
        with self._lock:
            self._entries.clear()

    # ------------------------------------------------------------------ #
    # CDP event handlers                                                 #
    # ------------------------------------------------------------------ #

    def _on_log_entry(self, params: dict) -> None:
        entry_data = params.get("entry", {})
        entry = ConsoleEntry(
            level=entry_data.get("level", "log"),
            text=entry_data.get("text", ""),
            url=entry_data.get("url"),
            line=entry_data.get("lineNumber"),
            timestamp=entry_data.get("timestamp", 0.0),
        )
        with self._lock:
            self._entries.append(entry)

    def _on_console_api(self, params: dict) -> None:
        # Map CDP console API types to standard levels
        _type_map = {"log": "log", "info": "info", "warn": "warn", "error": "error", "debug": "debug"}
        level = _type_map.get(params.get("type", "log"), "log")

        args = params.get("args", [])
        text_parts = [str(a.get("value", a.get("description", ""))) for a in args]
        text = " ".join(text_parts)

        stack = params.get("stackTrace", {})
        frames = stack.get("callFrames", [])
        url = frames[0].get("url") if frames else None
        line = frames[0].get("lineNumber") if frames else None

        entry = ConsoleEntry(
            level=level,
            text=text,
            url=url,
            line=line,
            timestamp=params.get("timestamp", 0.0),
        )
        with self._lock:
            self._entries.append(entry)
