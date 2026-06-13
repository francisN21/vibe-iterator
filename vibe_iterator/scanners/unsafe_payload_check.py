"""Unsafe payload scanner - probes harmless SSTI markers and parser error signatures."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import add_frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_TARGET_PATH_HINTS = ("render", "template", "deserialize", "parse", "preview", "import")
_SSTI_FIELDS = ("template", "content", "body", "message", "html", "text")
_PARSER_FIELDS = ("payload", "data", "state", "object", "serialized", "blob")
_SSTI_MARKER = "{{7*7}}"
_SSTI_EXPECTED = "49"
_INVALID_PARSER_PAYLOAD = "__vibe_invalid_pickle__"
_PARSER_SIGNATURES = (
    "pickle.UnpicklingError",
    "yaml.constructor.ConstructorError",
    "yaml.scanner.ScannerError",
    "java.io.StreamCorruptedException",
    "System.Runtime.Serialization.SerializationException",
    "unserialize(): Error",
    "invalid load key",
)
_MAX_ENDPOINTS = 12


class Scanner(BaseScanner):
    """Tests render/parse endpoints for SSTI and unsafe parser/deserialization signatures."""

    name = "unsafe_payload_check"
    category = "Injection"
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
        for req in _discover_unsafe_payload_targets(network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            endpoint = rewrite_to_backend_url(str(req.url), config)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            headers = add_frontend_origin(_safe_headers(dict(getattr(req, "headers", {}) or {})), config)
            original_body = getattr(req, "post_data", None)

            findings.extend(self._probe_ssti(endpoint, headers, original_body, stack))
            findings.extend(self._probe_parser(endpoint, headers, original_body, stack))

        return findings

    def _probe_ssti(self, endpoint: str, headers: dict[str, str], original_body: Any, stack: str) -> list[Finding]:
        for field in _SSTI_FIELDS:
            body = _inject_json_field(original_body, field, _SSTI_MARKER)
            if body is None:
                continue
            status, response_headers, response_body = _send_probe(endpoint, headers, body)
            proof = _has_ssti_evaluation(response_body)
            if status not in {200, 201, 202} or proof is None:
                continue
            value, proof_detail = proof
            desc = (
                f"The endpoint `{endpoint}` evaluated the harmless SSTI marker `{_SSTI_MARKER}` to `{value}` "
                f"when injected into JSON field `{field}`. Server-side template injection can lead to data disclosure "
                "or remote code execution depending on the template engine and sandboxing."
            )
            return [self.new_finding(
                scanner=self.name,
                severity=Severity.HIGH,
                title=f"SSTI marker evaluated in `{field}` field",
                description=desc,
                evidence={
                    "endpoint": endpoint,
                    "test_performed": "ssti_marker_probe",
                    "injection_point": f"json_field:{field}",
                    "payload_used": _SSTI_MARKER,
                    "request": {"method": "POST", "url": endpoint, "headers": headers, "body_excerpt": truncate(body.decode("utf-8", errors="replace"), 240)},
                    "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(response_body, 240)},
                    "evaluation_evidence": {"expected_value": _SSTI_EXPECTED, "observed_value": value, "detail": proof_detail},
                    "expected_response": "Treat template text as data or render only trusted server-side templates",
                    "proof_quality": "ssti_marker_evaluated",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"SSTI marker evaluated in `{field}` field",
                    severity=Severity.HIGH,
                    scanner=self.name,
                    page=endpoint,
                    category=self.category,
                    description=desc,
                    evidence_summary=f"POST {endpoint} with {field}={_SSTI_MARKER} returned evaluated value {value}",
                    stack=stack,
                ),
                remediation=(
                    "**What to fix:** User-controlled input is rendered as a server-side template.\n\n"
                    "**How to fix:** Do not pass user input to template engines as template source. Render trusted templates only, "
                    "escape untrusted values, disable dangerous filters/functions, and use sandboxed rendering when user-authored templates are a required feature.\n\n"
                    "**Verify the fix:** Re-run unsafe_payload_check; `{{7*7}}` should be escaped or returned literally, not evaluated to 49."
                ),
                category=self.category,
                page=endpoint,
            )]
        return []

    def _probe_parser(self, endpoint: str, headers: dict[str, str], original_body: Any, stack: str) -> list[Finding]:
        for field in _PARSER_FIELDS:
            body = _inject_json_field(original_body, field, _INVALID_PARSER_PAYLOAD)
            if body is None:
                continue
            status, response_headers, response_body = _send_probe(endpoint, headers, body)
            signature = _has_parser_error_signature(response_body)
            if status not in {400, 422, 500} or signature is None:
                continue
            desc = (
                f"The endpoint `{endpoint}` exposed `{signature}` when the harmless marker `{_INVALID_PARSER_PAYLOAD}` "
                f"was sent in JSON field `{field}`. This suggests user-controlled data reaches an unsafe parser or "
                "deserialization boundary."
            )
            return [self.new_finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                title=f"Unsafe parser/deserialization error exposed in `{field}` field",
                description=desc,
                evidence={
                    "endpoint": endpoint,
                    "test_performed": "unsafe_parser_error_probe",
                    "injection_point": f"json_field:{field}",
                    "payload_used": _INVALID_PARSER_PAYLOAD,
                    "request": {"method": "POST", "url": endpoint, "headers": headers, "body_excerpt": truncate(body.decode("utf-8", errors="replace"), 240)},
                    "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(response_body, 240)},
                    "parser_error_evidence": {"signature": signature},
                    "expected_response": "Reject untrusted serialized objects before they reach unsafe parsers",
                    "proof_quality": "unsafe_parser_error_signature",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"Unsafe parser/deserialization error exposed in `{field}` field",
                    severity=Severity.MEDIUM,
                    scanner=self.name,
                    page=endpoint,
                    category=self.category,
                    description=desc,
                    evidence_summary=f"POST {endpoint} with malformed parser marker returned {signature}",
                    stack=stack,
                ),
                remediation=(
                    "**What to fix:** User-controlled input appears to reach an unsafe parser/deserialization boundary.\n\n"
                    "**How to fix:** Avoid deserializing untrusted objects. Prefer JSON with schema validation, reject unexpected content types and fields, "
                    "disable polymorphic/object deserialization, and return generic validation errors that do not expose parser internals.\n\n"
                    "**Verify the fix:** Re-run unsafe_payload_check; malformed parser markers should return a generic 400 without unsafe parser signatures."
                ),
                category=self.category,
                page=endpoint,
            )]
        return []


def _discover_unsafe_payload_targets(network: Any, target: str, backend_url: str | None = None) -> list[Any]:
    discovered: list[Any] = []
    seen: set[str] = set()
    for req in network.get_requests():
        if str(getattr(req, "method", "GET")).upper() not in {"POST", "PUT", "PATCH"}:
            continue
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        parsed = urlparse(url)
        if not any(hint in parsed.path.lower() for hint in _TARGET_PATH_HINTS):
            continue
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if endpoint in seen:
            continue
        seen.add(endpoint)
        discovered.append(req)
    return discovered


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


def _safe_headers(headers: dict[str, Any]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in {"host", "content-length", "origin", "referer"}:
            continue
        safe[str(key)] = str(value)
    safe.setdefault("Content-Type", "application/json")
    return safe


def _inject_json_field(body: Any, field: str, value: str) -> bytes | None:
    raw = _body_bytes(body)
    if raw is None:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(parsed, dict) or field not in parsed:
        return None
    parsed[field] = value
    return json.dumps(parsed).encode("utf-8")


def _body_bytes(body: Any) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    return str(body).encode("utf-8")


def _send_probe(
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: int = 5,
) -> tuple[int | None, dict[str, str], str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _normalize_headers(resp.headers), resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, _normalize_headers(exc.headers), exc.read(2048).decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""


def _normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}


def _has_ssti_evaluation(body: str) -> tuple[str, str] | None:
    if _SSTI_MARKER in body:
        return None
    if re.search(r"(?<![0-9])49(?![0-9])", body):
        return _SSTI_EXPECTED, "arithmetic_marker_evaluated"
    return None


def _has_parser_error_signature(body: str) -> str | None:
    for signature in _PARSER_SIGNATURES:
        if signature.lower() in body.lower():
            return signature
    return None
