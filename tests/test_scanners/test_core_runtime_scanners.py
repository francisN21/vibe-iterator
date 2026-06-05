"""Smoke coverage for the deep runtime scanners that carry the product promise."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import vibe_iterator.scanners.auth_check as auth_mod
import vibe_iterator.scanners.sql_injection as sql_mod
from vibe_iterator.scanners.auth_check import Scanner as AuthScanner
from vibe_iterator.scanners.auth_check import _extract_error_text, _make_alg_none_token
from vibe_iterator.scanners.rls_bypass import Scanner as RlsScanner
from vibe_iterator.scanners.rls_bypass import _discover_tables, _extract_sub
from vibe_iterator.scanners.sql_injection import Scanner as SqlScanner
from vibe_iterator.scanners.sql_injection import _has_sql_error, _inject_postgrest_filter
from vibe_iterator.scanners.tier_escalation import Scanner as TierScanner
from vibe_iterator.scanners.tier_escalation import _network_reflects_tier
from vibe_iterator.scanners.tier_escalation import _rpc_reflects_tier


def _jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.signature"


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        target="http://localhost:3000",
        test_email="test@example.com",
        test_password="password",
        pages=["/", "/login", "/dashboard"],
        second_account_configured=False,
        supabase_url=None,
        supabase_anon_key=None,
        stack=SimpleNamespace(backend="supabase"),
    )


def _request(
    url: str,
    *,
    body: str = "",
    status: int = 200,
    method: str = "GET",
    post_data: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        method=method,
        url=url,
        headers={},
        post_data=post_data,
        status_code=status,
        response_body=body,
        response_headers={},
    )


def test_auth_token_security_reports_jwt_in_localstorage() -> None:
    scanner = AuthScanner()
    storage = MagicMock()
    storage.get_latest.return_value = SimpleNamespace(
        url="http://localhost:3000/dashboard",
        local_storage={"sb-token": _jwt({"sub": "user-1"})},
    )
    network = MagicMock()
    network.get_requests.return_value = []
    session = MagicMock()
    session.evaluate.return_value = None
    findings = []

    scanner._group1_token_security(session, storage, network, _config(), findings, "supabase")

    assert len(findings) == 1
    assert findings[0].scanner == "auth_check"
    assert "localStorage" in findings[0].title


def test_auth_helpers_decode_and_rewrite_jwt() -> None:
    token = _jwt({"sub": "user-123"})
    tampered = _make_alg_none_token(token)

    assert tampered is not None
    assert tampered.endswith(".")
    assert _extract_sub(token) == "user-123"
    assert _extract_error_text('{"error":"Invalid password"}') == "Invalid password"


def test_auth_http_helpers_handle_success_and_http_errors() -> None:
    class _Response:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def read(self) -> bytes:
            return b'{"message":"Invalid email or password"}'

    class _HttpError(Exception):
        code = 403

        def read(self) -> bytes:
            return b'{"error_description":"Forbidden"}'

    with patch("urllib.request.urlopen", return_value=_Response()):
        assert auth_mod._replay_with_token("token", "http://localhost") == 204
        assert auth_mod._replay_without_auth("http://localhost/api", "POST", "{}") == 204
        assert auth_mod._get_login_error_message("http://localhost", "a@b.com", "pw") == "Invalid email or password"

    # Use urllib's real HTTPError type for the scanner's specific except blocks.
    import urllib.error
    err = urllib.error.HTTPError("http://localhost", 403, "Forbidden", hdrs=None, fp=None)
    err.read = lambda: b'{"error_description":"Forbidden"}'
    with patch("urllib.request.urlopen", side_effect=err):
        assert auth_mod._replay_with_token("token", "http://localhost") == 403
        assert auth_mod._replay_without_auth("http://localhost/api", "GET", None) == 403
        assert auth_mod._get_login_error_message("http://localhost", "a@b.com", "pw") == "Forbidden"


def test_auth_session_management_flags_logout_and_cookie_issues() -> None:
    scanner = AuthScanner()
    session = MagicMock()
    session.driver.get_cookies.return_value = [
        {"name": "sb-session", "httpOnly": False, "secure": False, "sameSite": "None"},
    ]
    findings = []

    with patch.object(auth_mod, "_get_session_token", return_value=_jwt({"sub": "user-1"})), \
            patch.object(auth_mod, "_replay_with_token", return_value=200), \
            patch("vibe_iterator.crawler.auth.login"), \
            patch.object(auth_mod.time, "sleep"):
        scanner._group2_session_management(session, _config(), findings, "supabase", MagicMock())

    assert [f.title for f in findings] == [
        "Logout does not invalidate session token server-side",
        "Session cookie `sb-session` missing security flags",
    ]


def test_auth_login_security_reports_rate_limit_and_enumeration() -> None:
    scanner = AuthScanner()
    findings = []

    with patch("urllib.request.urlopen", side_effect=RuntimeError("connection refused")), \
            patch.object(auth_mod, "_get_login_error_message", side_effect=["Wrong password", "User not found"]):
        scanner._group3_login_security(MagicMock(), _config(), findings, "custom", MagicMock())

    assert [f.evidence["check_name"] for f in findings] == [
        "Brute force protection",
        "Username enumeration",
    ]


def test_auth_password_bypass_and_oauth_checks_report_findings() -> None:
    scanner = AuthScanner()
    cfg = _config()
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/user", body='{"password":"plaintext-secret"}'),
        _request("http://localhost:3000/api/private", body='{"secret":true}', method="GET"),
        _request("https://auth.example.com/oauth/authorize?client_id=abc"),
    ]
    session = MagicMock()
    session.current_url.return_value = "http://localhost:3000/dashboard"
    session.driver.page_source = "private dashboard"
    findings = []

    with patch("vibe_iterator.crawler.auth.login"), \
            patch.object(auth_mod, "_replay_without_auth", return_value=200), \
            patch.object(auth_mod.time, "sleep"):
        scanner._group4_password_account(session, cfg, findings, "custom", network)
        scanner._group5_auth_bypass(session, cfg, findings, "custom", network)
        scanner._group6_oauth(session, cfg, findings, "custom", network)

    titles = [f.title for f in findings]
    assert "Password field returned in API response" in titles
    route_finding = next(f for f in findings if "Protected route `/dashboard`" in f.title)
    assert route_finding.evidence["proof_quality"] == "protected_route_path_loaded_without_auth"
    assert any("API endpoint accessible without authentication" in title for title in titles)
    assert "OAuth flow missing CSRF state parameter" in titles


def test_sql_passive_analysis_reports_database_error() -> None:
    scanner = SqlScanner()
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/users?id=1", body='{"error":"syntax error near SELECT"}', status=500),
    ]
    findings = []

    scanner._group1_passive_analysis(network, _config(), findings, "custom")

    assert len(findings) == 1
    assert findings[0].scanner == "sql_injection"
    assert _has_sql_error("relation \"profiles\" does not exist") is True
    assert "name=eq.abc%27" in _inject_postgrest_filter(
        "https://p.supabase.co/rest/v1/profiles?name=eq.abc", "name", "abc", "abc'"
    )


def test_sql_postgrest_injection_reports_active_error() -> None:
    scanner = SqlScanner()
    network = MagicMock()
    network.get_requests.return_value = [
        _request("https://p.supabase.co/rest/v1/profiles?name=eq.alice"),
    ]
    findings = []

    with patch.object(sql_mod, "_make_request", return_value=("syntax error at or near", 500, 0.1)):
        scanner._group2_postgrest_injection(network, _config(), findings, "supabase")

    assert len(findings) == 1
    assert findings[0].evidence["injection_point"] == "url_param:name"


def test_sql_classic_injection_reports_url_and_json_fields() -> None:
    scanner = SqlScanner()
    cfg = _config()

    url_network = MagicMock()
    url_network.get_requests.return_value = [_request("http://localhost:3000/api/search?q=alice")]
    url_findings = []
    with patch.object(sql_mod, "_make_request", return_value=("column \"x\" does not exist", 500, 0.1)):
        scanner._group3_classic_injection(url_network, cfg, url_findings, "custom")

    body_network = MagicMock()
    body_network.get_requests.return_value = [
        _request(
            "http://localhost:3000/api/search",
            method="POST",
            post_data=json.dumps({"term": "alice"}),
        )
    ]
    body_findings = []
    with patch.object(sql_mod, "_make_request", return_value=("operator does not exist", 500, 0.1)):
        scanner._group3_classic_injection(body_network, cfg, body_findings, "custom")

    assert url_findings[0].evidence["injection_point"] == "url_param:q"
    assert body_findings[0].evidence["injection_point"] == "json_field:term"


def test_sql_blind_input_vector_and_schema_checks_report_findings() -> None:
    scanner = SqlScanner()
    cfg = _config()

    blind_network = MagicMock()
    blind_network.get_requests.return_value = [_request("http://localhost:3000/api/items?id=1")]
    blind_findings = []
    with patch.object(sql_mod, "_make_request", return_value=("", 200, 3.2)):
        scanner._group4_blind_injection(blind_network, cfg, blind_findings, "custom")

    input_el = MagicMock()
    input_el.get_attribute.side_effect = lambda attr: {"name": "search", "placeholder": "Search"}.get(attr, "")
    input_el.find_element.return_value.submit.return_value = None
    form_network = MagicMock()
    form_network.get_requests.return_value = [
        _request("http://localhost:3000/api/search", body="syntax error near OR", status=500),
    ]
    session = MagicMock()
    session.driver.find_elements.return_value = [input_el]
    form_findings = []
    with patch.object(sql_mod.time, "sleep"):
        scanner._group5_input_vectors(session, form_network, cfg, form_findings, "custom")

    schema_network = MagicMock()
    schema_network.get_requests.return_value = [
        _request("http://localhost:3000/api/debug", body="information_schema.tables leaked"),
    ]
    schema_findings = []
    scanner._group6_post_exploitation(schema_network, cfg, schema_findings, "custom")

    assert blind_findings[0].evidence["payload_type"] == "time_based"
    assert form_findings[0].evidence["injection_point"] == "form_input:search"
    assert schema_findings[0].title == "Database schema information exposed in API response"


def test_rls_run_reports_unfiltered_table_response() -> None:
    scanner = RlsScanner()
    rows = [{"id": i} for i in range(6)]
    network = MagicMock()
    network.get_requests.return_value = [
        _request("https://p.supabase.co/rest/v1/profiles?select=*", body=json.dumps(rows)),
    ]

    findings = scanner.run(MagicMock(), {"network": network}, _config())

    assert len(findings) == 1
    assert findings[0].scanner == "rls_bypass"
    assert _discover_tables(network) == ["profiles"]
    assert _extract_sub(_jwt({"sub": "user-1"})) == "user-1"


def test_rls_unauthenticated_and_cross_user_checks_report_findings() -> None:
    scanner = RlsScanner()
    cfg = _config()
    cfg.supabase_url = "https://project.supabase.co"
    cfg.supabase_anon_key = "anon"
    cfg.second_account_configured = True
    findings = []

    class _RowsResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def read(self) -> bytes:
            return b'[{"id": 1, "user_id": "other"}]'

    with patch("urllib.request.urlopen", return_value=_RowsResponse()):
        scanner._check_unauthenticated_access(MagicMock(), ["profiles"], cfg, findings, "supabase")

    session = MagicMock()
    session.evaluate.side_effect = [
        _jwt({"sub": "user-1"}),
        {"data": [{"id": 1, "user_id": "user-1"}], "error": None},
    ]
    with patch("vibe_iterator.crawler.auth.login"):
        scanner._check_cross_user_access(session, ["profiles"], cfg, findings, "supabase")

    assert [f.scanner for f in findings] == ["rls_bypass", "rls_bypass"]
    assert "readable without authentication" in findings[0].title
    assert "Cross-user data access" in findings[1].title


def test_tier_escalation_reports_client_side_plan_trust_and_restores() -> None:
    scanner = TierScanner()
    snapshot = SimpleNamespace(
        url="http://localhost:3000/dashboard",
        local_storage={"plan": "free"},
        session_storage={},
    )
    storage = MagicMock()
    storage.get_snapshots.return_value = [snapshot]
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/subscription", body='{"plan":"premium"}'),
    ]
    session = MagicMock()
    session.evaluate.side_effect = ["free", None, "premium", None, None]
    session.navigate.return_value = None

    findings = scanner.run(session, {"storage": storage, "network": network}, _config())

    assert len(findings) == 1
    assert findings[0].scanner == "tier_escalation"
    assert findings[0].evidence["storage_key"] == "plan"
    assert findings[0].evidence["proof_quality"] == "structured_api_response_contains_tampered_tier"
    assert findings[0].evidence["server_acceptance_evidence"]["json_path"] == "plan"
    assert session.evaluate.call_args_list[-1].args[0].find("setItem('plan'") != -1


def test_tier_escalation_does_not_report_when_tampered_plan_only_persists_locally() -> None:
    scanner = TierScanner()
    snapshot = SimpleNamespace(
        url="http://localhost:3000/dashboard",
        local_storage={"plan": "free"},
        session_storage={},
    )
    storage = MagicMock()
    storage.get_snapshots.return_value = [snapshot]
    network = MagicMock()
    network.get_requests.return_value = []
    session = MagicMock()
    session.evaluate.side_effect = ["free", None, "premium", None, None]
    session.navigate.return_value = None

    findings = scanner.run(session, {"storage": storage, "network": network}, _config())

    assert findings == []


def test_tier_escalation_does_not_report_unrelated_textual_plan_match() -> None:
    scanner = TierScanner()
    snapshot = SimpleNamespace(
        url="http://localhost:3000/dashboard",
        local_storage={"plan": "free"},
        session_storage={},
    )
    storage = MagicMock()
    storage.get_snapshots.return_value = [snapshot]
    network = MagicMock()
    network.get_requests.return_value = [
        _request(
            "http://localhost:3000/api/subscription",
            body='{"copy":"Premium plans are available in billing"}',
        ),
    ]
    session = MagicMock()
    session.evaluate.side_effect = ["free", None, "premium", None, None]
    session.navigate.return_value = None

    findings = scanner.run(session, {"storage": storage, "network": network}, _config())

    assert findings == []


def test_network_reflects_tier_returns_structured_json_path() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/subscription", body='{"subscription":{"tier":"premium"}}'),
    ]

    proof = _network_reflects_tier(network, "plan", "premium")

    assert proof == {
        "url": "http://localhost:3000/api/subscription",
        "status": 200,
        "json_path": "subscription.tier",
        "matched_value": "premium",
    }


def test_network_reflects_tier_accepts_nested_subscription_path() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/tier/structured", body='{"subscription":{"tier":"premium"}}'),
    ]

    proof = _network_reflects_tier(network, "plan", "premium")

    assert proof == {
        "url": "http://localhost:3000/api/tier/structured",
        "status": 200,
        "json_path": "subscription.tier",
        "matched_value": "premium",
    }


def test_network_reflects_tier_ignores_unstructured_text_match() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/subscription", body='{"copy":"Premium plans are available"}'),
    ]

    assert _network_reflects_tier(network, "plan", "premium") is None


def test_network_reflects_tier_ignores_rpc_error_text() -> None:
    network = MagicMock()
    network.get_requests.return_value = [
        _request("http://localhost:3000/api/tier/rpc-error", body='{"data":null,"error":"Premium tier function unavailable"}'),
    ]

    assert _network_reflects_tier(network, "plan", "premium") is None


def test_rpc_reflects_tier_uses_rpc_data_only() -> None:
    assert _rpc_reflects_tier({"data": {"tier": "premium"}, "error": None}, "premium") is True


def test_rpc_reflects_tier_ignores_error_text_match() -> None:
    rpc_result = {
        "data": None,
        "error": "Premium tier function is not available",
    }

    assert _rpc_reflects_tier(rpc_result, "premium") is False
