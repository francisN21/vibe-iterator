"""Tests for the StorageListener — uses mock browser session, no live Chrome."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vibe_iterator.listeners.storage import StorageListener, StorageSnapshot


# ------------------------------------------------------------------ #
# Helpers                                                            #
# ------------------------------------------------------------------ #

def _make_session(
    *,
    local: dict | None = None,
    session_storage: dict | None = None,
    cookies: list | None = None,
    url: str = "http://localhost:3000/dashboard",
) -> MagicMock:
    """Build a mock BrowserSession with controlled storage state."""
    from vibe_iterator.crawler.browser import BrowserSession
    session = MagicMock(spec=BrowserSession)
    session.driver = MagicMock()
    session.driver.current_url = url
    session.driver.get_cookies.return_value = cookies or []

    def _evaluate_side_effect(script: str):
        if "localStorage" in script:
            return local or {}
        if "sessionStorage" in script:
            return session_storage or {}
        return None

    session.evaluate.side_effect = _evaluate_side_effect
    return session


# ------------------------------------------------------------------ #
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestStorageListenerCapture:
    def test_captures_local_storage(self) -> None:
        listener = StorageListener()
        session = _make_session(local={"user_role": "free", "theme": "dark"})

        snapshot = listener.capture(session)
        assert snapshot.local_storage == {"user_role": "free", "theme": "dark"}

    def test_captures_session_storage(self) -> None:
        listener = StorageListener()
        session = _make_session(session_storage={"temp_token": "abc123"})

        snapshot = listener.capture(session)
        assert snapshot.session_storage == {"temp_token": "abc123"}

    def test_captures_cookies(self) -> None:
        listener = StorageListener()
        cookies = [{"name": "sb-auth", "value": "eyJ...", "domain": "localhost", "httpOnly": True}]
        session = _make_session(cookies=cookies)

        snapshot = listener.capture(session)
        assert len(snapshot.cookies) == 1
        assert snapshot.cookies[0]["name"] == "sb-auth"

    def test_captures_current_url(self) -> None:
        listener = StorageListener()
        session = _make_session(url="http://localhost:3000/profile")

        snapshot = listener.capture(session)
        assert snapshot.url == "http://localhost:3000/profile"

    def test_snapshot_accumulated_across_pages(self) -> None:
        listener = StorageListener()
        session1 = _make_session(url="http://localhost:3000/")
        session2 = _make_session(url="http://localhost:3000/dashboard")

        listener.capture(session1)
        listener.capture(session2)

        snapshots = listener.get_snapshots()
        assert len(snapshots) == 2
        assert snapshots[0].url == "http://localhost:3000/"
        assert snapshots[1].url == "http://localhost:3000/dashboard"


class TestStorageListenerEmpty:
    def test_empty_storage_returns_empty_dicts(self) -> None:
        listener = StorageListener()
        session = _make_session(local={}, session_storage={}, cookies=[])

        snapshot = listener.capture(session)
        assert snapshot.local_storage == {}
        assert snapshot.session_storage == {}
        assert snapshot.cookies == []

    def test_evaluate_error_returns_empty_dict(self) -> None:
        """If JS evaluate raises (e.g., cross-origin page), storage returns empty dict gracefully."""
        from vibe_iterator.crawler.browser import BrowserSession
        session = MagicMock(spec=BrowserSession)
        session.driver = MagicMock()
        session.driver.current_url = "http://localhost:3000/"
        session.driver.get_cookies.return_value = []
        session.evaluate.side_effect = RuntimeError("CDP error")

        listener = StorageListener()
        snapshot = listener.capture(session)

        assert snapshot.local_storage == {}
        assert snapshot.session_storage == {}


class TestStorageListenerUtilities:
    def test_get_latest_returns_most_recent(self) -> None:
        listener = StorageListener()
        listener.capture(_make_session(url="/page1"))
        listener.capture(_make_session(url="/page2"))

        assert listener.get_latest().url == "/page2"

    def test_get_latest_returns_none_when_empty(self) -> None:
        listener = StorageListener()
        assert listener.get_latest() is None

    def test_clear_resets_snapshots(self) -> None:
        listener = StorageListener()
        listener.capture(_make_session())
        listener.capture(_make_session())
        assert len(listener.get_snapshots()) == 2

        listener.clear()
        assert listener.get_snapshots() == []
        assert listener.get_latest() is None
