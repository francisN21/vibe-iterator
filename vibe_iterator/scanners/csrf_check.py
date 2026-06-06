"""CSRF scanner - probes cookie-authenticated state-changing requests."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_CSRF_HEADER_NAMES = {
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
    "x-csrf",
    "x-xsrf",
    "x-requested-with",
}
_ATTACK_ORIGIN = "https://evil.example"
_MAX_ENDPOINTS = 12
_SUCCESS_KEYS = {"updated", "created", "deleted", "success", "ok", "accepted"}
_NEGATIVE_KEYS = {"preview", "dry_run", "valid", "allowed"}


class Scanner(BaseScanner):
    """Tests state-changing cookie-authenticated requests for missing CSRF defenses."""

    name = "csrf_check"
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
        for req in _discover_state_changing_requests(network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            method = str(getattr(req, "method", "GET")).upper()
            parsed = urlparse(str(getattr(req, "url", "")))
            key = f"{method}:{parsed.netloc}{parsed.path}"
            if key in seen:
                continue
            seen.add(key)

            probe_url = rewrite_to_backend_url(str(req.url), config)
            headers, stripped = _strip_csrf_headers(dict(getattr(req, "headers", {}) or {}))
            body = _body_bytes(getattr(req, "post_data", None))
            status, response_headers, response_body = _send_cross_site_probe(probe_url, method, headers, body)
            success = _has_state_change_success(response_body)
            if status not in {200, 201, 202} or success is None:
                continue
            success_path, success_value = success

            desc = (
                f"The `{method}` request to `{probe_url}` accepted a cross-site request from `{_ATTACK_ORIGIN}` "
                "after CSRF headers were removed, while preserving the captured session cookie. "
                "An attacker-controlled site could trigger state-changing actions for signed-in users."
            )
            findings.append(self.new_finding(
                scanner=self.name,
                severity=Severity.HIGH,
                title=f"CSRF state change accepted on `{parsed.path}`",
                description=desc,
                evidence={
                    "endpoint": probe_url,
                    "test_performed": "cross_site_state_change_probe",
                    "method": method,
                    "request": {"method": method, "url": probe_url, "headers": _redact_cookie(headers)},
                    "response": {
                        "status": status,
                        "headers": dict(response_headers),
                        "body_excerpt": truncate(response_body, 240),
                    },
                    "stripped_headers": stripped,
                    "mutation_success_evidence": {"json_path": success_path, "value": success_value},
                    "expected_response": "Reject cross-site state-changing requests without a valid CSRF token",
                    "proof_quality": "cross_site_state_change_accepted",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"CSRF state change accepted on `{parsed.path}`",
                    severity=Severity.HIGH,
                    scanner=self.name,
                    page=probe_url,
                    category=self.category,
                    description=desc,
                    evidence_summary=f"{method} {probe_url} accepted Origin {_ATTACK_ORIGIN} and returned {success_path}=true",
                    stack=stack,
                ),
                remediation=(
                    "**What to fix:** A cookie-authenticated state-changing endpoint accepts cross-site requests "
                    "without valid CSRF proof.\n\n"
                    "**How to fix:** Require synchronizer or double-submit CSRF tokens for unsafe methods, validate "
                    "`Origin`/`Referer` against the application origin, reject missing/invalid tokens before mutation, "
                    "and set session cookies to `SameSite=Lax` or `SameSite=Strict` where product flows allow it.\n\n"
                    "**Verify the fix:** Re-run csrf_check; the cross-site probe should return 403 or omit mutation success evidence."
                ),
                category=self.category,
                page=probe_url,
            ))
            return findings

        return findings


def _discover_state_changing_requests(network: Any, target: str, backend_url: str | None = None) -> list[Any]:
    discovered: list[Any] = []
    seen: set[tuple[str, str]] = set()
    for req in network.get_requests():
        method = str(getattr(req, "method", "GET")).upper()
        if method not in _UNSAFE_METHODS:
            continue
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        headers = dict(getattr(req, "headers", {}) or {})
        if not _has_cookie(headers):
            continue
        parsed = urlparse(url)
        key = (method, f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
        if key in seen:
            continue
        seen.add(key)
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


def _has_cookie(headers: dict[str, Any]) -> bool:
    return any(str(k).lower() == "cookie" and bool(v) for k, v in headers.items())


def _strip_csrf_headers(headers: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    clean: dict[str, str] = {}
    stripped: list[str] = []
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in _CSRF_HEADER_NAMES:
            stripped.append(lowered)
            continue
        if lowered in {"origin", "referer", "host", "content-length"}:
            continue
        clean[str(key)] = str(value)
    clean["Origin"] = _ATTACK_ORIGIN
    clean["Referer"] = f"{_ATTACK_ORIGIN}/csrf-proof"
    return clean, sorted(stripped)


def _body_bytes(body: Any) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    return str(body).encode("utf-8")


def _send_cross_site_probe(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: int = 5,
) -> tuple[int | None, dict[str, str], str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _normalize_headers(resp.headers), resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, _normalize_headers(exc.headers), exc.read(1024).decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""


def _normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}


def _has_state_change_success(body: str) -> tuple[str, Any] | None:
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    return _find_success_signal(parsed)


def _find_success_signal(value: Any, path: str = "") -> tuple[str, Any] | None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if lowered in _SUCCESS_KEYS and lowered not in _NEGATIVE_KEYS and child is True:
                return child_path, child
            nested = _find_success_signal(child, child_path)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for idx, child in enumerate(value[:5]):
            nested = _find_success_signal(child, f"{path}[{idx}]")
            if nested is not None:
                return nested
    return None


def _redact_cookie(headers: dict[str, str]) -> dict[str, str]:
    redacted = dict(headers)
    for key in list(redacted):
        if key.lower() == "cookie":
            redacted[key] = "<redacted>"
    return redacted
