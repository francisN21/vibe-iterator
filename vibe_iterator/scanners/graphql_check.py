"""GraphQL scanner - probes introspection, auth bypass, and bounded depth abuse."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_MAX_ENDPOINTS = 8
_INTROSPECTION_QUERY = "query VibeIteratorIntrospection { __schema { queryType { name } types { name } } }"
_SENSITIVE_QUERY = (
    "query VibeIteratorUnauthData { "
    "viewer { id email role } me { id email role } currentUser { id email role } "
    "}"
)
_SENSITIVE_FIELD_RE = re.compile(r"(email|token|secret|role|permission|admin)", re.IGNORECASE)


@dataclass
class _InventoryGraphQLRequest:
    url: str
    method: str
    headers: dict[str, str]
    inventory_source: str
    inventory_confidence: str
    inventory_endpoint: str


class Scanner(BaseScanner):
    """Tests discovered GraphQL endpoints for common runtime security gaps."""

    name = "graphql_check"
    category = "API Security"
    stages = ["pre-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target
        backend_url = getattr(config, "backend_url", None)
        backend_url = backend_url if isinstance(backend_url, str) and backend_url else None

        seen: set[str] = set()
        for req in _graphql_candidates(listeners.get("api_inventory"), network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            endpoint = rewrite_to_backend_url(str(req.url).split("?", 1)[0], config)
            if endpoint in seen:
                continue
            seen.add(endpoint)

            headers = _probe_headers(dict(getattr(req, "headers", {}) or {}))
            inventory_evidence = _inventory_evidence(req)
            findings.extend(self._probe_introspection(endpoint, headers, stack, inventory_evidence))
            findings.extend(self._probe_unauth_data(endpoint, headers, stack, inventory_evidence))
            findings.extend(self._probe_depth(endpoint, headers, stack, inventory_evidence))

        return findings

    def _probe_introspection(
        self,
        endpoint: str,
        headers: dict[str, str],
        stack: str,
        inventory_evidence: dict[str, Any] | None = None,
    ) -> list[Finding]:
        status, response_headers, body = _post_graphql(endpoint, _INTROSPECTION_QUERY, headers=headers)
        proof = _has_introspection_schema(body)
        if status != 200 or proof is None:
            return []
        path, query_type, type_count = proof
        desc = (
            f"The GraphQL endpoint `{endpoint}` returned schema introspection without authentication. "
            "Attackers can enumerate types, fields, and relationships to plan targeted data access and mutation attacks."
        )
        return [self.new_finding(
            scanner=self.name,
            severity=Severity.MEDIUM,
            title="Unauthenticated GraphQL introspection is enabled",
            description=desc,
            evidence={
                "endpoint": endpoint,
                "test_performed": "unauthenticated_graphql_introspection_probe",
                "request": {"method": "POST", "url": endpoint, "headers": headers, "query": _INTROSPECTION_QUERY},
                "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(body, 240)},
                "schema_evidence": {"json_path": path, "query_type": query_type, "type_count": type_count},
                "expected_response": "Disable public introspection or require admin authentication outside trusted development environments",
                "proof_quality": "unauthenticated_graphql_introspection",
                "network_events": [],
                **(inventory_evidence or {}),
            },
            llm_prompt=self.build_llm_prompt(
                title="Unauthenticated GraphQL introspection is enabled",
                severity=Severity.MEDIUM,
                scanner=self.name,
                page=endpoint,
                category=self.category,
                description=desc,
                evidence_summary=f"POST {endpoint} returned __schema queryType={query_type} with {type_count} types",
                stack=stack,
            ),
            remediation=(
                "**What to fix:** Public GraphQL introspection is enabled.\n\n"
                "**How to fix:** Disable introspection in production or gate it behind trusted admin authentication. "
                "Keep schema documentation in private developer tooling, not on unauthenticated runtime endpoints.\n\n"
                "**Verify the fix:** Re-run graphql_check; unauthenticated introspection should return 401/403 or a validation error."
            ),
            category=self.category,
            page=endpoint,
        )]

    def _probe_unauth_data(
        self,
        endpoint: str,
        headers: dict[str, str],
        stack: str,
        inventory_evidence: dict[str, Any] | None = None,
    ) -> list[Finding]:
        status, response_headers, body = _post_graphql(endpoint, _SENSITIVE_QUERY, headers=headers)
        proof = _has_sensitive_graphql_data(body)
        if status != 200 or proof is None:
            return []
        path, value = proof
        desc = (
            f"The GraphQL endpoint `{endpoint}` returned sensitive user data without authentication. "
            "This indicates resolver-level authorization is missing or enforced only in the client."
        )
        return [self.new_finding(
            scanner=self.name,
            severity=Severity.HIGH,
            title="Unauthenticated GraphQL query returned sensitive data",
            description=desc,
            evidence={
                "endpoint": endpoint,
                "test_performed": "unauthenticated_graphql_sensitive_data_probe",
                "request": {"method": "POST", "url": endpoint, "headers": headers, "query": _SENSITIVE_QUERY},
                "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(body, 240)},
                "sensitive_data_evidence": {"json_path": path, "value": value},
                "expected_response": "Require resolver-level authentication and authorization for sensitive fields",
                "proof_quality": "unauthenticated_graphql_sensitive_data",
                "network_events": [],
                **(inventory_evidence or {}),
            },
            llm_prompt=self.build_llm_prompt(
                title="Unauthenticated GraphQL query returned sensitive data",
                severity=Severity.HIGH,
                scanner=self.name,
                page=endpoint,
                category=self.category,
                description=desc,
                evidence_summary=f"POST {endpoint} without auth returned {path}={value}",
                stack=stack,
            ),
            remediation=(
                "**What to fix:** Sensitive GraphQL resolvers return data without authentication.\n\n"
                "**How to fix:** Enforce auth in resolver middleware or schema directives, check object ownership before returning fields, "
                "and deny sensitive fields by default unless the authenticated principal is authorized.\n\n"
                "**Verify the fix:** Re-run graphql_check; unauthenticated sensitive queries should return 401/403 or null protected fields."
            ),
            category=self.category,
            page=endpoint,
        )]

    def _probe_depth(
        self,
        endpoint: str,
        headers: dict[str, str],
        stack: str,
        inventory_evidence: dict[str, Any] | None = None,
    ) -> list[Finding]:
        query = _build_depth_query(depth=5)
        status, response_headers, body = _post_graphql(endpoint, query, headers=headers)
        depth = _has_depth_accepted(body)
        if status != 200 or depth is None:
            return []
        desc = (
            f"The GraphQL endpoint `{endpoint}` accepted a nested depth-{depth} probe without a depth or complexity error. "
            "Attackers can use expensive nested GraphQL queries to exhaust application resources."
        )
        return [self.new_finding(
            scanner=self.name,
            severity=Severity.MEDIUM,
            title=f"GraphQL depth-{depth} query accepted without complexity guard",
            description=desc,
            evidence={
                "endpoint": endpoint,
                "test_performed": "graphql_bounded_depth_probe",
                "request": {"method": "POST", "url": endpoint, "headers": headers, "query": query},
                "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(body, 240)},
                "depth_evidence": {"accepted_depth": depth},
                "expected_response": "Reject excessive nested GraphQL queries with depth or complexity limits",
                "proof_quality": "graphql_depth_query_accepted",
                "network_events": [],
                **(inventory_evidence or {}),
            },
            llm_prompt=self.build_llm_prompt(
                title=f"GraphQL depth-{depth} query accepted without complexity guard",
                severity=Severity.MEDIUM,
                scanner=self.name,
                page=endpoint,
                category=self.category,
                description=desc,
                evidence_summary=f"POST {endpoint} accepted a bounded nested GraphQL query with depth {depth}",
                stack=stack,
            ),
            remediation=(
                "**What to fix:** GraphQL accepts nested queries without practical depth or complexity controls.\n\n"
                "**How to fix:** Add query depth and complexity limits, reject recursive or overly nested selections, "
                "set per-request execution timeouts, and apply rate limits to GraphQL operations.\n\n"
                "**Verify the fix:** Re-run graphql_check; the bounded depth probe should return a depth/complexity validation error."
            ),
            category=self.category,
            page=endpoint,
        )]


def _discover_graphql_endpoints(network: Any, target: str, backend_url: str | None = None) -> list[Any]:
    discovered: list[Any] = []
    seen: set[str] = set()
    for req in network.get_requests():
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        parsed = urlparse(url)
        if "graphql" not in parsed.path.lower():
            continue
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if endpoint in seen:
            continue
        seen.add(endpoint)
        discovered.append(req)
    return discovered


def _graphql_candidates(inventory: Any, network: Any, target: str, backend_url: str | None = None) -> list[Any]:
    candidates: list[Any] = []
    seen: set[str] = set()

    for req in _inventory_graphql_endpoints(inventory, target, backend_url):
        endpoint = str(req.url).split("?", 1)[0]
        if endpoint in seen:
            continue
        seen.add(endpoint)
        candidates.append(req)

    for req in _discover_graphql_endpoints(network, target, backend_url):
        endpoint = str(req.url).split("?", 1)[0]
        if endpoint in seen:
            continue
        seen.add(endpoint)
        candidates.append(req)

    return candidates


def _inventory_graphql_endpoints(inventory: Any, target: str, backend_url: str | None = None) -> list[Any]:
    if inventory is None:
        return []

    candidates: list[Any] = []
    for endpoint in getattr(inventory, "endpoints", []):
        method = str(getattr(endpoint, "method", "")).upper()
        url = getattr(endpoint, "url", "")
        risk_tags = {str(tag).lower() for tag in getattr(endpoint, "risk_tags", [])}
        if method != "POST" or "graphql" not in risk_tags:
            continue
        if not isinstance(url, str) or not _is_same_app_url(url, target, backend_url):
            continue

        candidates.append(_InventoryGraphQLRequest(
            url=url,
            method=method,
            headers={"Content-Type": "application/json"},
            inventory_source=",".join(getattr(endpoint, "sources", [])),
            inventory_confidence=getattr(endpoint, "confidence", "") or "",
            inventory_endpoint=f"{method} {getattr(endpoint, 'normalized_path', getattr(endpoint, 'path', url))}",
        ))

    return candidates


def _inventory_evidence(req: Any) -> dict[str, Any]:
    endpoint = getattr(req, "inventory_endpoint", None)
    if not endpoint:
        return {}
    return {
        "inventory_source": getattr(req, "inventory_source", "") or "",
        "inventory_confidence": getattr(req, "inventory_confidence", "") or "",
        "inventory_endpoint": endpoint,
        "inventory_parameters_used": [],
    }


def _is_same_app_url(url: str, target: str, backend_url: str | None = None) -> bool:
    parsed = urlparse(url)
    if any(parsed.path.endswith(ext) for ext in _STATIC_EXTS):
        return False
    if any(frag in parsed.path for frag in _SKIP_FRAGMENTS):
        return False
    allowed = {urlparse(target).netloc}
    if backend_url:
        allowed.add(urlparse(backend_url).netloc)
    return parsed.netloc in allowed


def _probe_headers(original: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in original.items():
        lowered = str(key).lower()
        if lowered in {"authorization", "cookie", "host", "content-length", "origin", "referer"}:
            continue
        if lowered == "content-type":
            headers["Content-Type"] = "application/json"
    headers.setdefault("Content-Type", "application/json")
    return headers


def _post_graphql(
    url: str,
    query: str,
    headers: dict[str, str] | None = None,
    timeout: int = 5,
) -> tuple[int | None, dict[str, str], str]:
    body = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers or {"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _normalize_headers(resp.headers), resp.read(8192).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, _normalize_headers(exc.headers), exc.read(2048).decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""


def _normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}


def _has_introspection_schema(body: str) -> tuple[str, str, int] | None:
    parsed = _json(body)
    schema = _path(parsed, ["data", "__schema"])
    if not isinstance(schema, dict):
        return None
    query_type = _path(schema, ["queryType", "name"])
    types = schema.get("types")
    if not isinstance(query_type, str) or not isinstance(types, list) or not types:
        return None
    return "__schema", query_type, len(types)


def _has_sensitive_graphql_data(body: str) -> tuple[str, Any] | None:
    parsed = _json(body)
    data = parsed.get("data") if isinstance(parsed, dict) else None
    if not isinstance(data, dict):
        return None
    return _find_sensitive(data, "data")


def _find_sensitive(value: Any, path: str) -> tuple[str, Any] | None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _SENSITIVE_FIELD_RE.search(str(key)) and _looks_sensitive(child):
                return child_path, child
            nested = _find_sensitive(child, child_path)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for idx, child in enumerate(value[:5]):
            nested = _find_sensitive(child, f"{path}[{idx}]")
            if nested is not None:
                return nested
    return None


def _looks_sensitive(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return "@" in value or len(value) >= 4
    if isinstance(value, bool):
        return value is True
    return isinstance(value, (int, float))


def _build_depth_query(depth: int = 5) -> str:
    depth = max(1, min(depth, 8))
    inner = "id"
    for _ in range(depth):
        inner = f"node {{ {inner} }}"
    return f"query VibeIteratorDepthProbe {{ {inner} }}"


def _has_depth_accepted(body: str) -> int | None:
    parsed = _json(body)
    if not isinstance(parsed, dict) or "errors" in parsed:
        return None
    data = parsed.get("data")
    depth = _max_node_depth(data)
    return depth if depth >= 5 else None


def _max_node_depth(value: Any) -> int:
    if isinstance(value, dict):
        depths = []
        for key, child in value.items():
            child_depth = _max_node_depth(child)
            depths.append(child_depth + 1 if key == "node" else child_depth)
        return max(depths) if depths else 0
    if isinstance(value, list):
        return max((_max_node_depth(child) for child in value[:5]), default=0)
    return 0


def _path(value: Any, keys: list[str]) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _json(body: str) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return {}
