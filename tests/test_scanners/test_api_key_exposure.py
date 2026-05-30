"""Unit tests for the api_key_exposure scanner."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vibe_iterator.scanners.api_key_exposure import Scanner
from vibe_iterator.scanners.base import Severity
from vibe_iterator.listeners.storage import StorageSnapshot


def _make_config(target: str = "http://localhost:3000") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    return cfg


def _make_req(
    url: str = "http://localhost:3000/api/data",
    headers: dict | None = None,
    status: int = 200,
    body: str = "",
    mime: str = "application/json",
    post_data=None,
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.headers = headers or {}
    req.status_code = status
    req.response_body = body
    req.response_mime_type = mime
    req.post_data = post_data
    return req


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_storage(snapshots: list[StorageSnapshot] | None = None) -> MagicMock:
    storage = MagicMock()
    storage.get_snapshots.return_value = snapshots or []
    return storage


def _run(requests=None, snapshots=None) -> list:
    scanner = Scanner()
    config = _make_config()
    listeners = {
        "network": _make_network(requests or []),
        "storage": _make_storage(snapshots),
    }
    return scanner.run(session=None, listeners=listeners, config=config)


# ---------------------------------------------------------------------------
# Group 1 — Request headers
# ---------------------------------------------------------------------------

class TestRequestHeaders:
    def test_stripe_live_key_in_x_api_key_header(self) -> None:
        req = _make_req(
            headers={"x-api-key": "sk_live_abcdefghijklmnopqrstuvwxyz"},
        )
        findings = _run([req])
        assert any("Stripe live secret key" in f.title for f in findings)
        stripe = next(f for f in findings if "Stripe live secret key" in f.title)
        assert stripe.severity == Severity.CRITICAL

    def test_openai_key_in_x_api_key_header(self) -> None:
        key = "sk-" + "a" * 48
        req = _make_req(headers={"x-api-key": key})
        findings = _run([req])
        assert any("OpenAI" in f.title for f in findings)

    def test_clean_header_no_finding(self) -> None:
        req = _make_req(headers={"x-api-key": "short"})
        findings = _run([req])
        assert findings == []


# ---------------------------------------------------------------------------
# Group 1b — Query parameters
# ---------------------------------------------------------------------------

class TestQueryParameters:
    def test_api_key_in_query_param_flagged(self) -> None:
        req = _make_req(url="http://localhost:3000/data?api_key=" + "x" * 30)
        findings = _run([req])
        assert any("query parameter" in f.title.lower() for f in findings)
        qp = next(f for f in findings if "query parameter" in f.title.lower())
        assert qp.severity == Severity.HIGH

    def test_token_param_flagged(self) -> None:
        req = _make_req(url="http://localhost:3000/data?token=" + "y" * 32)
        findings = _run([req])
        assert any("query parameter" in f.title.lower() for f in findings)

    def test_short_param_value_ignored(self) -> None:
        req = _make_req(url="http://localhost:3000/data?api_key=short")
        findings = _run([req])
        assert not any("query parameter" in f.title.lower() for f in findings)

    def test_irrelevant_param_ignored(self) -> None:
        req = _make_req(url="http://localhost:3000/data?page=2&limit=10")
        findings = _run([req])
        assert findings == []


# ---------------------------------------------------------------------------
# Group 2 — Response bodies
# ---------------------------------------------------------------------------

class TestResponseBodies:
    def test_aws_key_in_json_response(self) -> None:
        body = '{"key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}'
        req = _make_req(body=body, mime="application/json")
        findings = _run([req])
        assert any("AWS access key ID" in f.title for f in findings)
        aws = next(f for f in findings if "AWS access key ID" in f.title)
        assert aws.severity == Severity.CRITICAL

    def test_github_pat_in_response_body(self) -> None:
        token = "ghp_" + "a" * 36
        body = f'{{"token": "{token}"}}'
        req = _make_req(body=body, mime="application/json")
        findings = _run([req])
        assert any("GitHub personal access token" in f.title for f in findings)

    def test_slack_token_in_js_response(self) -> None:
        body = f'var token = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";'
        req = _make_req(body=body, mime="application/javascript")
        findings = _run([req])
        assert any("Slack bot token" in f.title for f in findings)

    def test_binary_mime_skipped(self) -> None:
        req = _make_req(body="AKIA1234567890ABCDEF", mime="image/png")
        findings = _run([req])
        assert not any("AWS" in f.title for f in findings)

    def test_empty_body_no_finding(self) -> None:
        req = _make_req(body="", mime="application/json")
        findings = _run([req])
        assert findings == []


# ---------------------------------------------------------------------------
# Group 3 — Browser storage
# ---------------------------------------------------------------------------

class TestBrowserStorage:
    def test_stripe_key_in_local_storage(self) -> None:
        snapshot = StorageSnapshot(
            url="http://localhost:3000/",
            local_storage={"stripeKey": "sk_live_abcdefghijklmnopqrstuvwxyz"},
            session_storage={},
            cookies=[],
        )
        findings = _run(snapshots=[snapshot])
        assert any("Stripe live secret key" in f.title for f in findings)

    def test_api_key_in_session_storage(self) -> None:
        snapshot = StorageSnapshot(
            url="http://localhost:3000/",
            local_storage={},
            session_storage={"api_key": "sk_live_abcdefghijklmnopqrstuvwxyz"},
            cookies=[],
        )
        findings = _run(snapshots=[snapshot])
        assert any("Stripe" in f.title for f in findings)

    def test_openai_key_in_cookie(self) -> None:
        key = "sk-" + "b" * 48
        snapshot = StorageSnapshot(
            url="http://localhost:3000/",
            local_storage={},
            session_storage={},
            cookies=[{"name": "session_token", "value": key, "domain": "localhost"}],
        )
        findings = _run(snapshots=[snapshot])
        assert any("OpenAI" in f.title for f in findings)

    def test_clean_storage_no_finding(self) -> None:
        snapshot = StorageSnapshot(
            url="http://localhost:3000/",
            local_storage={"theme": "dark", "user": "alice"},
            session_storage={},
            cookies=[{"name": "session", "value": "sess_abc123", "domain": "localhost"}],
        )
        findings = _run(snapshots=[snapshot])
        assert findings == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_key_in_two_requests_deduped(self) -> None:
        body = '{"token": "AKIAIOSFODNN7EXAMPLE"}'
        req1 = _make_req(url="http://localhost:3000/a", body=body, mime="application/json")
        req2 = _make_req(url="http://localhost:3000/a", body=body, mime="application/json")
        findings = _run([req1, req2])
        aws = [f for f in findings if "AWS access key ID" in f.title]
        assert len(aws) == 1

    def test_same_key_different_urls_both_reported(self) -> None:
        body = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
        req1 = _make_req(url="http://localhost:3000/a", body=body, mime="application/json")
        req2 = _make_req(url="http://localhost:3000/b", body=body, mime="application/json")
        findings = _run([req1, req2])
        aws = [f for f in findings if "AWS access key ID" in f.title]
        assert len(aws) == 2
