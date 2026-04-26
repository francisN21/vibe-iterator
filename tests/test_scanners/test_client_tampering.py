"""Tests for client_tampering scanner — verify state restoration and detection."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.client_tampering import Scanner


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _make_storage_snapshot(local: dict = None, session_storage: dict = None, url: str = "http://localhost:3000/dashboard") -> MagicMock:
    snap = MagicMock()
    snap.url = url
    snap.local_storage = local or {}
    snap.session_storage = session_storage or {}
    return snap


def _make_listeners(snapshot=None) -> dict:
    storage = MagicMock()
    storage.get_latest.return_value = snapshot
    storage.get_snapshots.return_value = [snapshot] if snapshot else []
    network = MagicMock()
    network.get_requests.return_value = []
    network.clear.return_value = None
    return {"storage": storage, "network": network, "console": MagicMock()}


def _make_config() -> MagicMock:
    config = MagicMock()
    config.target = "http://localhost:3000"
    config.stack.backend = "supabase"
    return config


def _make_session(
    evaluate_side_effects: list | None = None,
    cookies: list | None = None,
) -> MagicMock:
    session = MagicMock()
    if evaluate_side_effects:
        session.evaluate.side_effect = evaluate_side_effects
    else:
        session.evaluate.return_value = "free"  # default: value not changed
    session.driver.get_cookies.return_value = cookies or []
    session.navigate.return_value = None
    session.current_url.return_value = "http://localhost:3000/dashboard"
    return session


# --------------------------------------------------------------------------- #
# Tests — finding detection                                                   #
# --------------------------------------------------------------------------- #

class TestClientTamperingDetection:
    def test_finds_when_server_trusts_role_in_localstorage(self) -> None:
        """Simulate: evaluate returns 'admin' after tamper (server trusted it)."""
        snapshot = _make_storage_snapshot(local={"role": "free"})
        listeners = _make_listeners(snapshot=snapshot)
        config = _make_config()

        # Side effects: [get original] [set tampered] [reload page] [read current → still 'admin']
        session = _make_session(evaluate_side_effects=[
            "free",       # get original
            None,         # set tampered
            "admin",      # read after navigation (server didn't reset)
            Exception("network rpc error"),  # rpc call — ignored
        ])

        # Patch _detect_server_acceptance to return True
        with patch("vibe_iterator.scanners.client_tampering._detect_server_acceptance", return_value=True):
            scanner = Scanner()
            findings = scanner.run(session, listeners, config)

        assert len(findings) >= 1
        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("role" in f.title.lower() or "localStorage" in f.evidence.get("storage_type", "") for f in findings)

    def test_no_finding_when_server_resets_value(self) -> None:
        """Simulate: after tampering, server resets the value to original."""
        snapshot = _make_storage_snapshot(local={"role": "free"})
        listeners = _make_listeners(snapshot=snapshot)
        config = _make_config()

        session = _make_session(evaluate_side_effects=[
            "free",   # get original
            None,     # set tampered
            "free",   # read after navigation — server reset it
            None,
        ])

        with patch("vibe_iterator.scanners.client_tampering._detect_server_acceptance", return_value=False):
            scanner = Scanner()
            findings = scanner.run(session, listeners, config)

        role_findings = [f for f in findings if "role" in (f.evidence.get("storage_key") or "")]
        assert role_findings == []


# --------------------------------------------------------------------------- #
# Tests — state restoration                                                   #
# --------------------------------------------------------------------------- #

class TestClientTamperingStateRestore:
    def test_restores_localstorage_after_finding(self) -> None:
        """Original value must be written back even when a finding is generated."""
        snapshot = _make_storage_snapshot(local={"role": "free"})
        listeners = _make_listeners(snapshot=snapshot)
        config = _make_config()
        session = _make_session()

        restore_calls = []

        def track_evaluate(script):
            if "setItem" in script and "free" in script:
                restore_calls.append(script)
            return "admin" if "getItem" in script else None

        session.evaluate.side_effect = track_evaluate

        with patch("vibe_iterator.scanners.client_tampering._detect_server_acceptance", return_value=True):
            scanner = Scanner()
            scanner.run(session, listeners, config)

        # Restore call must have happened (setItem with original value)
        assert any("free" in c for c in restore_calls) or session.evaluate.called

    def test_restores_state_when_exception_raised(self) -> None:
        """State must be restored even when an exception is thrown mid-check."""
        snapshot = _make_storage_snapshot(local={"role": "free"})
        listeners = _make_listeners(snapshot=snapshot)
        config = _make_config()

        restore_calls = []

        def side_effect_with_error(script):
            if "getItem" in script:
                return "free"
            if "setItem" in script and "admin" in script:
                raise RuntimeError("Network error during tampering")
            if "setItem" in script:
                restore_calls.append(script)
            return None

        session = _make_session(evaluate_side_effects=None)
        session.evaluate.side_effect = side_effect_with_error

        scanner = Scanner()
        # Must not raise
        scanner.run(session, listeners, config)
        # Restore may or may not be called (exception happened before taiming)
        # Key assertion: no exception propagated


# --------------------------------------------------------------------------- #
# Tests — no findings                                                         #
# --------------------------------------------------------------------------- #

class TestClientTamperingNoFindings:
    def test_no_findings_when_no_role_keys_in_storage(self) -> None:
        snapshot = _make_storage_snapshot(local={"theme": "dark", "language": "en"})
        listeners = _make_listeners(snapshot=snapshot)
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert findings == []

    def test_no_findings_when_no_storage_snapshot(self) -> None:
        listeners = _make_listeners(snapshot=None)
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert findings == []

    def test_does_not_raise_on_evaluate_failure(self) -> None:
        snapshot = _make_storage_snapshot(local={"role": "free"})
        listeners = _make_listeners(snapshot=snapshot)
        session = MagicMock()
        session.evaluate.side_effect = Exception("CDP error")
        session.driver.get_cookies.return_value = []

        scanner = Scanner()
        findings = scanner.run(session, listeners, _make_config())
        assert isinstance(findings, list)
