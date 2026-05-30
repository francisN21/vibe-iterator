# vibe_iterator/spider/endpoint_harvester.py
"""Collect and normalize API endpoints from captured network traffic."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from vibe_iterator.listeners.network import NetworkListener

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_INT_RE = re.compile(r"^\d+$")

_API_PREFIXES = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/")


def harvest_endpoints(network: NetworkListener) -> list[str]:
    """Return sorted, deduplicated 'METHOD /normalized/path' strings for API calls."""
    seen: set[str] = set()
    results: list[str] = []
    for req in network.get_requests():
        entry = _classify(req)
        if entry and entry not in seen:
            seen.add(entry)
            results.append(entry)
    return sorted(results)


def _classify(req) -> str | None:
    try:
        path = urlparse(req.url).path
    except Exception:
        return None
    if not _is_api_path(path):
        return None
    return f"{req.method.upper()} {_normalize_path(path)}"


def _is_api_path(path: str) -> bool:
    for prefix in _API_PREFIXES:
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return True
    # REST resource pattern: /word/id (e.g. /users/123 or /items/uuid)
    parts = [p for p in path.split("/") if p]
    if len(parts) == 2 and re.match(r"^[a-z][a-z_-]*$", parts[0], re.I):
        if _UUID_RE.fullmatch(parts[1]) or _INT_RE.fullmatch(parts[1]):
            return True
    return False


def _normalize_path(path: str) -> str:
    parts = path.split("/")
    normalized = []
    for part in parts:
        if _UUID_RE.fullmatch(part) or _INT_RE.fullmatch(part):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/".join(normalized)
