"""Tests for bucket_limits scanner cleanup behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from vibe_iterator.scanners.bucket_limits import Scanner, _delete_test_object, _discover_buckets


class _FakeResponse:
    status = 201

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return b'{"ok": true}'


def test_accepted_oversized_upload_is_cleaned_up() -> None:
    """If the scanner proves an oversized upload works, it should still delete the test object."""
    scanner = Scanner()
    config = SimpleNamespace(target="http://localhost:3000")
    findings = []

    with patch("vibe_iterator.scanners.bucket_limits._TEST_SIZES_MB", [0]), \
            patch("urllib.request.urlopen", return_value=_FakeResponse()), \
            patch("vibe_iterator.scanners.bucket_limits._delete_test_object") as cleanup:
        scanner._check_size_limits(
            bucket="avatars",
            base_url="https://project.supabase.co",
            anon_key="anon",
            token="token",
            config=config,
            findings=findings,
            stack="supabase",
        )

    assert len(findings) == 1
    assert findings[0].evidence["proof_quality"] == "oversized_storage_upload_accepted"
    cleanup.assert_called_once()
    assert cleanup.call_args.args[0].endswith("/storage/v1/object/avatars/vibe_test_0mb.bin")


def test_accepted_dangerous_file_type_is_reported_and_cleaned_up() -> None:
    scanner = Scanner()
    config = SimpleNamespace(target="http://localhost:3000")
    findings = []

    with patch("vibe_iterator.scanners.bucket_limits._BLOCKED_TYPES", ["text/html"]), \
            patch("urllib.request.urlopen", return_value=_FakeResponse()), \
            patch("vibe_iterator.scanners.bucket_limits._delete_test_object") as cleanup:
        scanner._check_type_restrictions(
            bucket="public",
            base_url="https://project.supabase.co",
            anon_key="anon",
            token=None,
            config=config,
            findings=findings,
            stack="supabase",
        )

    assert len(findings) == 1
    assert findings[0].evidence["proof_quality"] == "dangerous_mime_storage_upload_accepted"
    assert findings[0].evidence["request"]["headers"]["Content-Type"] == "text/html"
    cleanup.assert_called_once()


def test_run_discovers_buckets_and_uses_session_token() -> None:
    scanner = Scanner()
    config = SimpleNamespace(
        target="http://localhost:3000",
        supabase_url="https://project.supabase.co",
        supabase_anon_key="anon",
        stack=SimpleNamespace(backend="supabase"),
    )
    session = MagicMock()
    session.evaluate.return_value = "jwt"
    network = MagicMock()
    network.get_requests.return_value = [
        SimpleNamespace(url="https://project.supabase.co/storage/v1/object/avatars/file.png"),
    ]

    with patch.object(scanner, "_check_size_limits") as size_check, \
            patch.object(scanner, "_check_type_restrictions") as type_check:
        findings = scanner.run(session, {"network": network}, config)

    assert findings == []
    size_check.assert_called_once()
    type_check.assert_called_once()
    assert size_check.call_args.args[3] == "jwt"


def test_discover_buckets_deduplicates_and_delete_is_best_effort() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        SimpleNamespace(url="https://x/storage/v1/object/avatars/a.png"),
        SimpleNamespace(url="https://x/storage/v1/object/avatars/b.png"),
        SimpleNamespace(url="https://x/storage/v1/object/documents/a.pdf"),
    ]

    assert _discover_buckets(network) == ["avatars", "documents"]

    with patch("urllib.request.urlopen", side_effect=RuntimeError("already gone")):
        _delete_test_object("https://x/storage/v1/object/avatars/a.png", "Bearer token", "anon")


def test_discover_buckets_parses_supabase_operation_paths() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        SimpleNamespace(url="https://x/storage/v1/object/public/avatars/a.png"),
        SimpleNamespace(url="https://x/storage/v1/object/sign/documents/a.pdf"),
        SimpleNamespace(url="https://x/storage/v1/object/list/invoices"),
        SimpleNamespace(url="https://x/storage/v1/object/avatars/private.png"),
    ]

    assert _discover_buckets(network) == ["avatars", "documents", "invoices"]
