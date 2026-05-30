"""Browser console listener — captures console output via Chrome browser log.

Selenium 4.20+ removed add_cdp_listener. We use driver.get_log("browser")
(enabled via goog:loggingPrefs {"browser": "ALL"} in browser.launch()) as the
polling-based alternative. Call flush() after page navigations to drain the
ring buffer before Chrome evicts old entries.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Chrome log level → normalized level name
_LEVEL_MAP: dict[str, str] = {
    "SEVERE": "error",
    "WARNING": "warn",
    "INFO": "log",
    "DEBUG": "debug",
    "FINE": "debug",
    "FINER": "debug",
    "FINEST": "debug",
}


@dataclass
class ConsoleEntry:
    """A single captured console message."""

    level: str          # "log" | "warn" | "error" | "info" | "debug"
    text: str           # Full message text
    url: str | None     # Source URL (if known)
    line: int | None    # Source line number (if known)
    timestamp: float    # Milliseconds since epoch


class ConsoleListener:
    """Polls Chrome's browser log to capture console output.

    Usage::

        listener = ConsoleListener()
        listener.attach(session)          # call before crawling / scanning
        # ... page interactions ...
        listener.flush()                  # drain browser log after each page
        entries = listener.get_entries()
        listener.detach()
    """

    def __init__(self) -> None:
        self._entries: list[ConsoleEntry] = []
        self._lock = threading.Lock()
        self._session: Any | None = None

    def attach(self, session: Any) -> None:
        """Register the session. Browser logging is configured in browser.launch()."""
        from vibe_iterator.crawler.browser import BrowserSession
        assert isinstance(session, BrowserSession)
        self._session = session

    def detach(self) -> None:
        """Flush remaining entries and release the session reference."""
        if self._session is not None:
            self.flush()
        self._session = None

    def flush(self) -> None:
        """Drain Chrome's browser log and populate the entry store.

        Chrome's browser log is a ring buffer consumed on each get_log() call.
        Call this after every page navigation to avoid losing messages.
        """
        if self._session is None:
            return
        driver = self._session.driver
        try:
            raw_logs = driver.get_log("browser")
        except Exception as exc:
            logger.debug("browser log unavailable: %s", exc)
            return
        for entry in raw_logs:
            self._process_entry(entry)

    def get_entries(self) -> list[ConsoleEntry]:
        """Flush, then return a snapshot of all captured console entries."""
        self.flush()
        with self._lock:
            return list(self._entries)

    def get_entries_by_level(self, level: str) -> list[ConsoleEntry]:
        """Return entries matching the given level (e.g., 'error', 'warn')."""
        return [e for e in self.get_entries() if e.level == level]

    def clear(self) -> None:
        """Discard all captured entries."""
        with self._lock:
            self._entries.clear()

    def summary(self) -> dict[str, int]:
        """Return entry counts by level."""
        counts: dict[str, int] = {"total": 0, "error": 0, "warn": 0, "log": 0, "info": 0, "debug": 0}
        for entry in self.get_entries():
            counts["total"] += 1
            lvl = entry.level
            if lvl in counts:
                counts[lvl] += 1
        return counts

    # ------------------------------------------------------------------ #
    # Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _process_entry(self, raw: dict) -> None:
        """Parse a Chrome browser log entry and append to the store."""
        level_raw = raw.get("level", "INFO")
        level = _LEVEL_MAP.get(level_raw, "log")
        timestamp = float(raw.get("timestamp", 0.0))

        # Chrome formats the message as "URL LINE | message text" or just the text.
        # Best-effort extraction of source location.
        message = raw.get("message", "")
        url: str | None = None
        line: int | None = None
        text = message

        if " | " in message:
            prefix, _, body = message.partition(" | ")
            parts = prefix.rsplit(" ", 1)
            if len(parts) == 2:
                candidate_url, candidate_line = parts
                try:
                    line = int(candidate_line)
                    url = candidate_url or None
                    text = body
                except ValueError:
                    pass  # not the expected format — keep full message as text

        with self._lock:
            self._entries.append(ConsoleEntry(
                level=level,
                text=text,
                url=url,
                line=line,
                timestamp=timestamp,
            ))
