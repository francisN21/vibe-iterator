"""Mass assignment scanner — tests POST/PUT/PATCH endpoints for unfiltered field acceptance."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import add_frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

# (field_name, value, is_financial)
_PRIVILEGE_FIELDS: list[tuple[str, Any, bool]] = [
    ("role", "admin", False),
    ("is_admin", True, False),
    ("isAdmin", True, False),
    ("admin", True, False),
    ("user_role", "admin", False),
    ("permissions", ["admin"], False),
    ("credits", 99999, True),
    ("balance", 99999, True),
    ("price", 0, True),
    ("discount", 100, True),
    ("account_type", "enterprise", False),
    ("subscription", "premium", False),
    ("verified", True, False),
    ("email_verified", True, False),
]

_WRITE_METHODS = {"POST", "PUT", "PATCH"}


@dataclass(frozen=True)
class _MassAssignmentCandidate:
    method: str
    url: str
    original_body: dict[str, Any]
    privilege_fields: tuple[tuple[str, Any, bool], ...]
    inventory_source: str | None = None
    inventory_confidence: str | None = None
    inventory_endpoint: str | None = None
    inventory_parameters_used: tuple[str, ...] = ()


class Scanner(BaseScanner):
    """Replays write endpoints with injected privilege fields to detect mass assignment."""

    name = "mass_assignment"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        inventory = listeners.get("api_inventory")
        token = _get_auth_headers(config)

        tested: set[str] = set()

        for candidate in [*_inventory_candidates(inventory), *_network_candidates(network)]:
            endpoint_key = f"{candidate.method}:{candidate.url}"
            if endpoint_key in tested:
                continue
            tested.add(endpoint_key)

            for field_name, field_value, is_financial in candidate.privilege_fields:
                if field_name in candidate.original_body:
                    continue

                injected_body = {**candidate.original_body, field_name: field_value}
                probe_url = rewrite_to_backend_url(candidate.url, config)
                resp_body, status, _ = _make_request(
                    probe_url, candidate.method,
                    json.dumps(injected_body).encode(),
                    token,
                )

                if status not in (200, 201) or not resp_body:
                    continue

                try:
                    resp_data = json.loads(resp_body)
                except (json.JSONDecodeError, ValueError):
                    continue

                if not isinstance(resp_data, dict):
                    continue

                if _is_non_persistent_echo_response(resp_data, injected_body):
                    continue

                field_match = _find_matching_field(resp_data, field_name, field_value)
                if field_match is None:
                    continue

                response_field_path, returned_val = field_match
                if not _has_resource_write_proof(resp_data, status):
                    continue

                sev = Severity.CRITICAL if is_financial else Severity.HIGH
                desc = (
                    f"The endpoint `{candidate.method} {probe_url}` accepted the injected field "
                    f"`{field_name}={field_value}` and returned it from `{response_field_path}` "
                    "in a resource write response. "
                    "The server does not filter unexpected fields from the request body. "
                    "An attacker can escalate privileges or manipulate protected attributes "
                    "(such as account role or pricing) by adding extra fields to legitimate API requests."
                )
                findings.append(self.new_finding(
                    scanner=self.name,
                    severity=sev,
                    title=f"Mass assignment: server accepted `{field_name}` in {candidate.method} {candidate.url}",
                    description=desc,
                    evidence={
                        "request": {
                            "method": candidate.method,
                            "url": probe_url,
                            "body": truncate(json.dumps(injected_body), 300),
                        },
                        "response": {"status": status, "body_excerpt": truncate(resp_body, 300)},
                        "injected_field": field_name,
                        "injected_value": str(field_value),
                        "returned_value": str(returned_val),
                        "response_field_path": response_field_path,
                        "proof_quality": "resource_write_response_contains_injected_privileged_field",
                        "payload_used": json.dumps({field_name: field_value}),
                        "payload_type": "mass_assignment",
                        "injection_point": f"json_body:{field_name}",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Mass assignment: server accepted `{field_name}`",
                        severity=sev,
                        scanner=self.name,
                        page=probe_url,
                        category=self.category,
                        description=desc,
                        evidence_summary=(
                            f"{candidate.method} {probe_url}\n"
                            f"Injected: {field_name}={field_value}\n"
                            f"Resource response returned {response_field_path}={returned_val}"
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{field_name}` field is accepted from the client and "
                        "stored/processed without an allowlist filter.\n\n"
                        "**How to fix:** Use an explicit allowlist of permitted fields before saving. "
                        "Never use `Object.assign(record, req.body)` or `model.create(req.body)` directly. "
                        "In JavaScript: `const safe = pick(req.body, ['name', 'email'])`. "
                        "For Supabase: use column-level grants — "
                        f"`REVOKE UPDATE ({field_name}) ON profiles FROM authenticated;`\n\n"
                        "**Verify the fix:** Re-run mass_assignment scanner — injected field must not appear in response."
                    ),
                    category=self.category,
                    page=probe_url,
                ))
                if candidate.inventory_endpoint:
                    findings[-1].evidence.update({
                        "inventory_source": candidate.inventory_source or "",
                        "inventory_confidence": candidate.inventory_confidence or "",
                        "inventory_endpoint": candidate.inventory_endpoint,
                        "inventory_parameters_used": list(candidate.inventory_parameters_used),
                    })

        return findings


def _inventory_candidates(inventory: Any) -> list[_MassAssignmentCandidate]:
    if inventory is None:
        return []

    candidates: list[_MassAssignmentCandidate] = []
    for endpoint in getattr(inventory, "endpoints", []):
        method = str(getattr(endpoint, "method", "")).upper()
        url = getattr(endpoint, "url", "")
        if method not in _WRITE_METHODS:
            continue
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        if any(skip in url for skip in ["/static/", ".js", ".css", "/auth/", "/login"]):
            continue

        body_params = [
            param for param in getattr(endpoint, "parameters", [])
            if getattr(param, "location", "") == "body"
        ]
        if not body_params:
            continue

        privileged_params = [
            param for param in body_params
            if _privilege_field_for_param(param) is not None
            and (
                bool(getattr(param, "sensitive_hint", False))
                or getattr(param, "source", "") != "observed"
                or getattr(param, "confidence", "") != "confirmed"
            )
        ]
        if not privileged_params:
            privileged_params = [
                param for param in body_params
                if _privilege_field_for_param(param) is not None
            ]

        selected_params = privileged_params or body_params

        original_body = _body_from_observed_params(body_params)
        privilege_fields = _privilege_fields_for_params(selected_params) or tuple(_PRIVILEGE_FIELDS)
        candidates.append(_MassAssignmentCandidate(
            method=method,
            url=url,
            original_body=original_body,
            privilege_fields=privilege_fields,
            inventory_source=",".join(getattr(endpoint, "sources", [])),
            inventory_confidence=getattr(endpoint, "confidence", ""),
            inventory_endpoint=f"{method} {getattr(endpoint, 'normalized_path', getattr(endpoint, 'path', url))}",
            inventory_parameters_used=tuple(getattr(param, "name", "") for param in selected_params),
        ))

    return candidates


def _network_candidates(network: Any) -> list[_MassAssignmentCandidate]:
    candidates: list[_MassAssignmentCandidate] = []
    for req in network.get_requests():
        if req.method not in _WRITE_METHODS:
            continue
        if not req.post_data:
            continue
        if not req.url.startswith("http"):
            continue
        if any(skip in req.url for skip in ["/static/", ".js", ".css", "/auth/", "/login"]):
            continue

        try:
            original_body = json.loads(req.post_data)
            if not isinstance(original_body, dict):
                continue
        except (json.JSONDecodeError, TypeError):
            continue

        candidates.append(_MassAssignmentCandidate(
            method=req.method,
            url=req.url,
            original_body=original_body,
            privilege_fields=tuple(_PRIVILEGE_FIELDS),
        ))

    return candidates


def _privilege_field_for_param(param: Any) -> tuple[str, Any, bool] | None:
    name = getattr(param, "name", "")
    if not isinstance(name, str) or not name:
        return None

    for field_name, field_value, is_financial in _PRIVILEGE_FIELDS:
        if field_name.lower() == name.lower():
            return name, field_value, is_financial

    return None


def _privilege_fields_for_params(params: list[Any]) -> tuple[tuple[str, Any, bool], ...]:
    return tuple(
        field for param in params
        if (field := _privilege_field_for_param(param)) is not None
    )


def _body_from_observed_params(params: list[Any]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for param in params:
        values = getattr(param, "observed_values", [])
        if not values:
            continue
        name = getattr(param, "name", "")
        if isinstance(name, str) and name:
            body[name] = _coerce_observed_value(values[0])
    return body


def _coerce_observed_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def _make_request(
    url: str, method: str, data: bytes | None, headers: dict, timeout: int = 6
) -> tuple[str, int | None, float]:
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(50_000).decode("utf-8", errors="replace")
            return body, resp.status, time.monotonic() - start
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(50_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return body, e.code, time.monotonic() - start
    except Exception:
        return "", None, time.monotonic() - start


def _get_auth_headers(config: Any) -> dict:
    headers: dict = {"Content-Type": "application/json"}
    anon_key = getattr(config, "supabase_anon_key", None)
    if anon_key:
        headers["apikey"] = anon_key
        headers["Authorization"] = f"Bearer {anon_key}"
    return add_frontend_origin(headers, config)


def _is_non_persistent_echo_response(resp_data: dict, injected_body: dict) -> bool:
    """Return True when a response looks like validation, preview, or request echo."""
    if resp_data == injected_body:
        return True

    echo_markers = {
        "dry_run", "dryRun", "preview", "validate_only", "validateOnly",
        "validation_only", "validationOnly", "would_update", "wouldUpdate",
        "echo", "received", "request", "payload",
    }
    return any(marker in resp_data for marker in echo_markers)


def _find_matching_field(data: Any, field_name: str, field_value: Any, path: str = "") -> tuple[str, Any] | None:
    if isinstance(data, dict):
        for key, value in data.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key == field_name and _values_match(value, field_value):
                return child_path, value
            nested = _find_matching_field(value, field_name, field_value, child_path)
            if nested is not None:
                return nested
    elif isinstance(data, list):
        for index, value in enumerate(data):
            nested = _find_matching_field(value, field_name, field_value, f"{path}[{index}]")
            if nested is not None:
                return nested
    return None


def _values_match(actual: Any, expected: Any) -> bool:
    return str(actual).lower() == str(expected).lower()


def _has_resource_write_proof(resp_data: dict, status: int | None) -> bool:
    if status == 201:
        return True

    resource_markers = {
        "id", "uuid", "_id", "created_at", "createdAt", "updated_at", "updatedAt",
        "inserted_at", "insertedAt",
    }
    return _contains_any_key(resp_data, resource_markers)


def _contains_any_key(data: Any, keys: set[str]) -> bool:
    if isinstance(data, dict):
        for key, value in data.items():
            if key in keys:
                return True
            if _contains_any_key(value, keys):
                return True
    elif isinstance(data, list):
        return any(_contains_any_key(value, keys) for value in data)
    return False
