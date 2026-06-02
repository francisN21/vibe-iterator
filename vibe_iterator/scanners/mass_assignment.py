"""Mass assignment scanner — tests POST/PUT/PATCH endpoints for unfiltered field acceptance."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
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
        token = _get_auth_headers(config)

        tested: set[str] = set()

        for req in network.get_requests():
            if req.method not in _WRITE_METHODS:
                continue
            if not req.post_data:
                continue
            if not req.url.startswith("http"):
                continue
            if any(skip in req.url for skip in ["/static/", ".js", ".css", "/auth/", "/login"]):
                continue

            endpoint_key = f"{req.method}:{req.url}"
            if endpoint_key in tested:
                continue
            tested.add(endpoint_key)

            try:
                original_body = json.loads(req.post_data)
                if not isinstance(original_body, dict):
                    continue
            except (json.JSONDecodeError, TypeError):
                continue

            for field_name, field_value, is_financial in _PRIVILEGE_FIELDS:
                if field_name in original_body:
                    continue

                injected_body = {**original_body, field_name: field_value}
                probe_url = rewrite_to_backend_url(req.url, config)
                resp_body, status, _ = _make_request(
                    probe_url, req.method,
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
                    f"The endpoint `{req.method} {probe_url}` accepted the injected field "
                    f"`{field_name}={field_value}` and returned it from `{response_field_path}` "
                    "in a resource write response. "
                    "The server does not filter unexpected fields from the request body. "
                    "An attacker can escalate privileges or manipulate protected attributes "
                    "(such as account role or pricing) by adding extra fields to legitimate API requests."
                )
                findings.append(self.new_finding(
                    scanner=self.name,
                    severity=sev,
                    title=f"Mass assignment: server accepted `{field_name}` in {req.method} {req.url}",
                    description=desc,
                    evidence={
                        "request": {
                            "method": req.method,
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
                            f"{req.method} {probe_url}\n"
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

        return findings


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
