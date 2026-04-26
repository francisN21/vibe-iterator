"""Tests for bucket_limits scanner cleanup behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from vibe_iterator.scanners.bucket_limits import Scanner


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
    cleanup.assert_called_once()
    assert cleanup.call_args.args[0].endswith("/storage/v1/object/avatars/vibe_test_0mb.bin")
