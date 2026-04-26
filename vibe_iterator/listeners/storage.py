"""Storage listener — reads localStorage, sessionStorage, and cookies after page visits."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StorageSnapshot:
    """All client-side storage captured from a single page visit."""

    url: str
    local_storage: dict[str, str]
    session_storage: dict[str, str]
    cookies: list[dict[str, Any]]    # Selenium cookie dicts: name, value, domain, path, ...


class StorageListener:
    """Reads localStorage, sessionStorage, and cookies for each visited page.

    Unlike NetworkListener and ConsoleListener, StorageListener is not
    event-driven — it is called explicitly after each page navigation.

    Usage::

        listener = StorageListener()
        # after navigating to a page:
        snapshot = listener.capture(session)
        snapshots = listener.get_snapshots()
    """

    def __init__(self) -> None:
        self._snapshots: list[StorageSnapshot] = []

    def capture(self, session: Any) -> StorageSnapshot:
        """Read current page storage and append to snapshot history."""
        from vibe_iterator.crawler.browser import BrowserSession
        assert isinstance(session, BrowserSession)

        driver = session.driver
        url = driver.current_url

        local_storage = _read_local_storage(session)
        session_storage = _read_session_storage(session)
        cookies = _read_cookies(driver)

        snapshot = StorageSnapshot(
            url=url,
            local_storage=local_storage,
            session_storage=session_storage,
            cookies=cookies,
        )
        self._snapshots.append(snapshot)
        logger.debug(
            "Storage captured at %s: %d local, %d session, %d cookies",
            url,
            len(local_storage),
            len(session_storage),
            len(cookies),
        )
        return snapshot

    def get_snapshots(self) -> list[StorageSnapshot]:
        """Return all captured snapshots in visit order."""
        return list(self._snapshots)

    def get_latest(self) -> StorageSnapshot | None:
        """Return the most recently captured snapshot, or None."""
        return self._snapshots[-1] if self._snapshots else None

    def clear(self) -> None:
        """Discard all snapshots."""
        self._snapshots.clear()


def _read_local_storage(session: Any) -> dict[str, str]:
    """Extract all localStorage key-value pairs via CDP Runtime.evaluate."""
    try:
        script = """
        (function() {
            var result = {};
            for (var i = 0; i < localStorage.length; i++) {
                var key = localStorage.key(i);
                result[key] = localStorage.getItem(key);
            }
            return result;
        })()
        """
        data = session.evaluate(script)
        return dict(data) if isinstance(data, dict) else {}
    except Exception as exc:
        logger.debug("localStorage read failed (non-fatal): %s", exc)
        return {}


def _read_session_storage(session: Any) -> dict[str, str]:
    """Extract all sessionStorage key-value pairs via CDP Runtime.evaluate."""
    try:
        script = """
        (function() {
            var result = {};
            for (var i = 0; i < sessionStorage.length; i++) {
                var key = sessionStorage.key(i);
                result[key] = sessionStorage.getItem(key);
            }
            return result;
        })()
        """
        data = session.evaluate(script)
        return dict(data) if isinstance(data, dict) else {}
    except Exception as exc:
        logger.debug("sessionStorage read failed (non-fatal): %s", exc)
        return {}


def _read_cookies(driver: Any) -> list[dict[str, Any]]:
    """Return all cookies for the current domain via Selenium."""
    try:
        return list(driver.get_cookies())
    except Exception as exc:
        logger.debug("Cookie read failed (non-fatal): %s", exc)
        return []
