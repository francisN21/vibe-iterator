"""Tests for Supabase helper utilities shared by scanners."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from vibe_iterator.utils.supabase_helpers import (
    build_rpc_snippet,
    build_table_query_snippet,
    detect_supabase_url,
    extract_session_token,
    find_jwts,
    is_postgrest_error,
    is_service_role_key,
    parse_postgrest_url,
    truncate,
)


def _jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.signature"


def test_snippet_builders_escape_filters_and_include_rpc_args() -> None:
    table = build_table_query_snippet("profiles", filters={"name": "O'Hara"})
    rpc = build_rpc_snippet("get_plan", {"user_id": "u1"})
    token = extract_session_token()

    assert ".eq('name', 'O\\'Hara')" in table
    assert "client.rpc('get_plan'" in rpc
    assert '"user_id": "u1"' in rpc
    assert "client.auth.getSession" in token


def test_postgrest_parser_and_error_detection() -> None:
    parsed = parse_postgrest_url("https://p.supabase.co/rest/v1/profiles?select=id&user_id=eq.1&limit=10")

    assert parsed["table"] == "profiles"
    assert parsed["select"] == "id"
    assert parsed["filters"] == {"user_id": "eq.1"}
    assert parsed["limit"] == "10"
    assert parse_postgrest_url("https://example.com/api") == {}
    assert is_postgrest_error('{"code":"42501","message":"denied"}') is True
    assert is_postgrest_error("not-json") is False


def test_jwt_detection_service_role_detection_and_truncation() -> None:
    service_role = _jwt({"role": "service_role"})
    anon = _jwt({"role": "anon"})
    text = f"tokens: {service_role} {anon}"

    assert find_jwts(text) == [service_role, anon]
    assert is_service_role_key(service_role) is True
    assert is_service_role_key(anon) is False
    assert is_service_role_key("not-a-token") is False
    assert truncate("abcdef", 3) == "abc...[truncated]"


def test_detect_supabase_url_from_network_events() -> None:
    events = [
        SimpleNamespace(url="https://example.com"),
        SimpleNamespace(url="https://abc123.supabase.co/rest/v1/profiles"),
    ]

    assert detect_supabase_url(events) == "https://abc123.supabase.co"
    assert detect_supabase_url([SimpleNamespace(url="https://example.com")]) is None
