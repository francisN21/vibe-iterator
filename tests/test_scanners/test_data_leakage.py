"""Tests for data_leakage scanner — mock network responses with injected secrets."""

from __future__ import annotations

from unittest.mock import MagicMock

from vibe_iterator.listeners.console import ConsoleEntry, ConsoleListener
from vibe_iterator.listeners.network import NetworkListener, NetworkRequest
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.data_leakage import Scanner

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _make_request(
    request_id: str, url: str, method: str = "GET",
    body: str = "", status: int = 200,
) -> NetworkRequest:
    req = NetworkRequest(
        request_id=request_id, method=method, url=url,
        headers={}, post_data=None, timestamp=1000.0,
    )
    req.status_code = status
    req.response_headers = {"Content-Type": "application/json"}
    req.response_body = body
    return req


def _make_listeners(requests: list = None, console_entries: list = None) -> dict:
    network = MagicMock(spec=NetworkListener)
    network.get_requests.return_value = requests or []
    console = MagicMock(spec=ConsoleListener)
    console.get_entries.return_value = console_entries or []
    storage = MagicMock()
    storage.get_snapshots.return_value = []
    return {"network": network, "console": console, "storage": storage}


def _make_config(target: str = "http://localhost:3000", stack: str = "supabase") -> MagicMock:
    config = MagicMock()
    config.target = target
    config.test_email = "test@example.com"
    config.stack.backend = stack
    return config


SERVICE_ROLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjAwMDAwMDAwfQ."
    "SIGNATURE_PLACEHOLDER"
)
USER_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJyb2xlIjoiYXV0aGVudGljYXRlZCIsImlhdCI6MTYwMDAwMDAwMH0."
    "SIGNATURE_PLACEHOLDER"
)


# --------------------------------------------------------------------------- #
# Tests — vulnerability present                                               #
# --------------------------------------------------------------------------- #

class TestDataLeakageFindsVulnerabilities:
    def test_detects_service_role_key_in_response(self) -> None:
        body = f'{{"config": {{"supabaseKey": "{SERVICE_ROLE_JWT}", "service_role": true}}}}'
        listeners = _make_listeners(requests=[
            _make_request("r1", "http://localhost:3000/api/init", body=body)
        ])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())

        critical = [f for f in findings if f.severity == Severity.CRITICAL and "service role" in f.title.lower()]
        assert len(critical) >= 1
        assert critical[0].evidence["leak_type"] == "supabase_service_key"
        assert critical[0].evidence["proof_quality"] == "supabase_service_role_jwt_in_response_body"

    def test_detects_jwt_in_url(self) -> None:
        url = f"http://localhost:3000/api/data?access_token={SERVICE_ROLE_JWT}"
        listeners = _make_listeners(requests=[_make_request("r1", url, body="{}")])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())

        jwt_url = [f for f in findings if "url" in f.title.lower() and "jwt" in f.title.lower()]
        assert len(jwt_url) >= 1
        assert jwt_url[0].evidence["proof_quality"] == "jwt_token_in_url_query_string"

    def test_detects_bulk_pii_emails_in_api_response(self) -> None:
        emails = [f"user{i}@company.com" for i in range(10)]
        email_list = ", ".join(f'"{e}"' for e in emails)
        body = f'{{"users": [{email_list}]}}'
        listeners = _make_listeners(requests=[
            _make_request("r1", "http://localhost:3000/api/users", body=body)
        ])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())

        pii = [f for f in findings if "email" in f.title.lower()]
        assert len(pii) >= 1
        assert pii[0].severity == Severity.MEDIUM
        assert pii[0].evidence["proof_quality"] == "multiple_unique_non_test_emails_in_api_response"

    def test_detects_jwt_in_console_log(self) -> None:
        entry = ConsoleEntry(
            level="log", text=f"Session: {USER_JWT}",
            url="http://localhost:3000/app.js", line=42, timestamp=1000.0,
        )
        listeners = _make_listeners(console_entries=[entry])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())

        console_findings = [f for f in findings if "console" in f.title.lower() or "logged" in f.title.lower()]
        assert len(console_findings) >= 1
        assert console_findings[0].evidence["proof_quality"] == "sensitive_jwt_logged_to_console"

    def test_dedupes_same_console_token(self) -> None:
        entries = [
            ConsoleEntry(
                level="log", text=f"Session: {SERVICE_ROLE_JWT}",
                url="http://localhost:3000/app.js", line=42, timestamp=1000.0,
            ),
            ConsoleEntry(
                level="debug", text=f"Session again: {SERVICE_ROLE_JWT}",
                url="http://localhost:3000/app.js", line=43, timestamp=1001.0,
            ),
        ]
        listeners = _make_listeners(console_entries=entries)
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())

        console_findings = [f for f in findings if "console" in f.title.lower() or "logged" in f.title.lower()]
        assert len(console_findings) == 1
        assert console_findings[0].evidence["proof_quality"] == "supabase_service_role_jwt_logged_to_console"

    def test_console_dedupe_keeps_new_token_when_first_token_repeats(self) -> None:
        entries = [
            ConsoleEntry(
                level="log", text=f"Session: {USER_JWT}",
                url="http://localhost:3000/app.js", line=42, timestamp=1000.0,
            ),
            ConsoleEntry(
                level="debug", text=f"Tokens: {USER_JWT} {SERVICE_ROLE_JWT}",
                url="http://localhost:3000/app.js", line=43, timestamp=1001.0,
            ),
        ]
        listeners = _make_listeners(console_entries=entries)
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())

        console_findings = [f for f in findings if "console" in f.title.lower() or "logged" in f.title.lower()]
        assert len(console_findings) == 2
        assert console_findings[1].evidence["proof_quality"] == "supabase_service_role_jwt_logged_to_console"


# --------------------------------------------------------------------------- #
# Tests — no vulnerability (empty list returned)                             #
# --------------------------------------------------------------------------- #

class TestDataLeakageNoFindings:
    def test_no_findings_for_clean_response(self) -> None:
        body = '{"id": 1, "name": "Alice"}'
        listeners = _make_listeners(requests=[
            _make_request("r1", "http://localhost:3000/api/profile", body=body)
        ])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert findings == []

    def test_no_findings_for_static_assets(self) -> None:
        listeners = _make_listeners(requests=[
            _make_request("r1", "http://localhost:3000/static/main.js", body="console.log('hello')"),
            _make_request("r2", "http://localhost:3000/favicon.ico", body=""),
        ])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert findings == []

    def test_no_findings_for_empty_responses(self) -> None:
        listeners = _make_listeners(requests=[], console_entries=[])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert findings == []

    def test_no_finding_for_repeated_single_email(self) -> None:
        body = '{"contacts": ["support@company.com", "support@company.com", "support@company.com"]}'
        listeners = _make_listeners(requests=[
            _make_request("r1", "http://localhost:3000/api/support", body=body)
        ])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert [f for f in findings if "email" in f.title.lower()] == []

    def test_no_finding_for_reserved_example_domain_emails(self) -> None:
        body = (
            '{"examples": ['
            '"alice@example.org", "bob@example.net", "carol@example.test", "dave@example.invalid"'
            ']}'
        )
        listeners = _make_listeners(requests=[
            _make_request("r1", "http://localhost:3000/api/docs", body=body)
        ])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert [f for f in findings if "email" in f.title.lower()] == []


# --------------------------------------------------------------------------- #
# Tests — resilience (no exception on bad input)                             #
# --------------------------------------------------------------------------- #

class TestDataLeakageResilience:
    def test_does_not_raise_on_null_body(self) -> None:
        req = _make_request("r1", "http://localhost:3000/api/test", body="")
        req.response_body = None
        listeners = _make_listeners(requests=[req])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert isinstance(findings, list)

    def test_does_not_raise_on_binary_body(self) -> None:
        req = _make_request("r1", "http://localhost:3000/api/test", body="\x00\x01\x02\xff")
        listeners = _make_listeners(requests=[req])
        scanner = Scanner()
        findings = scanner.run(MagicMock(), listeners, _make_config())
        assert isinstance(findings, list)
