"""Shared utilities for Supabase-specific scanners."""

from __future__ import annotations

import json
import re
from typing import Any


# --------------------------------------------------------------------------- #
# CDP snippet builders                                                         #
# --------------------------------------------------------------------------- #

def build_table_query_snippet(
    table: str,
    *,
    select: str = "*",
    filters: dict[str, str] | None = None,
) -> str:
    """Return a JS snippet that queries a Supabase table using the live page session.

    Executes via CDP Runtime.evaluate in the page context — uses the user's
    current auth JWT automatically through the Supabase JS client.
    """
    filter_chain = ""
    if filters:
        for col, val in filters.items():
            safe_col = col.replace("'", "\\'")
            safe_val = val.replace("'", "\\'")
            filter_chain += f".eq('{safe_col}', '{safe_val}')"

    return f"""
(async () => {{
    try {{
        const client = window.supabase || window._supabase;
        if (!client) return {{ error: 'Supabase client not found on window' }};
        const {{ data, error }} = await client.from('{table}').select('{select}'){filter_chain};
        return {{ data, error }};
    }} catch(e) {{
        return {{ error: e.message }};
    }}
}})()
""".strip()


def build_rpc_snippet(fn_name: str, args: dict[str, Any] | None = None) -> str:
    """Return a JS snippet that calls a Supabase RPC function."""
    args_json = json.dumps(args or {})
    return f"""
(async () => {{
    try {{
        const client = window.supabase || window._supabase;
        if (!client) return {{ error: 'Supabase client not found on window' }};
        const {{ data, error }} = await client.rpc('{fn_name}', {args_json});
        return {{ data, error }};
    }} catch(e) {{
        return {{ error: e.message }};
    }}
}})()
""".strip()


def extract_session_token() -> str:
    """Return a JS snippet that extracts the current Supabase session JWT."""
    return """
(async () => {
    try {
        const client = window.supabase || window._supabase;
        if (!client) return null;
        const { data: { session } } = await client.auth.getSession();
        return session ? session.access_token : null;
    } catch(e) {
        return null;
    }
})()
""".strip()


# --------------------------------------------------------------------------- #
# PostgREST URL parser                                                        #
# --------------------------------------------------------------------------- #

def parse_postgrest_url(url: str) -> dict[str, Any]:
    """Extract components from a PostgREST REST URL.

    Returns dict with keys: table, select, filters, order, limit, offset.
    Returns empty dict if URL doesn't look like a PostgREST URL.
    """
    # PostgREST URLs look like: /rest/v1/tablename?select=*&column=eq.value
    match = re.search(r"/rest/v1/([^?/]+)", url)
    if not match:
        return {}

    table = match.group(1).split("?")[0]

    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    filters: dict[str, str] = {}
    reserved = {"select", "order", "limit", "offset", "on_conflict", "columns"}
    for key, vals in params.items():
        if key not in reserved:
            filters[key] = vals[0] if vals else ""

    return {
        "table": table,
        "select": params.get("select", ["*"])[0],
        "filters": filters,
        "order": params.get("order", [None])[0],
        "limit": params.get("limit", [None])[0],
        "offset": params.get("offset", [None])[0],
    }


# --------------------------------------------------------------------------- #
# Response helpers                                                             #
# --------------------------------------------------------------------------- #

def is_postgrest_error(response_body: str | None) -> bool:
    """Return True if the response body is a PostgREST error object."""
    if not response_body:
        return False
    try:
        data = json.loads(response_body)
        if isinstance(data, dict):
            return "code" in data and "message" in data
    except (json.JSONDecodeError, TypeError):
        pass
    return False


def detect_supabase_url(network_events: list[Any]) -> str | None:
    """Scan captured network events for a Supabase project URL.

    Returns the base URL (e.g. https://xyz.supabase.co) or None.
    """
    pattern = re.compile(r"https://([a-z0-9]+)\.supabase\.co")
    for event in network_events:
        url = getattr(event, "url", "") or ""
        m = pattern.search(url)
        if m:
            return f"https://{m.group(1)}.supabase.co"
    return None


# --------------------------------------------------------------------------- #
# JWT helpers                                                                  #
# --------------------------------------------------------------------------- #

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
_SUPABASE_ANON_PATTERN = re.compile(r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")


def find_jwts(text: str) -> list[str]:
    """Return all JWT-like strings found in text."""
    return _JWT_PATTERN.findall(text)


def is_service_role_key(token: str) -> bool:
    """Return True if the token appears to be a Supabase service_role key."""
    try:
        import base64
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        return payload.get("role") == "service_role"
    except Exception:
        return False


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate a string for safe inclusion in evidence dicts."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...[truncated]"
