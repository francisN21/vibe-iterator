"""Webhook scanner - verifies signature enforcement on webhook endpoints."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_WEBHOOK_PATH_HINTS = ("webhook", "webhooks", "hooks", "stripe", "github", "clerk", "svix", "slack")
_SIGNATURE_HEADERS = {
    "stripe-signature",
    "x-hub-signature",
    "x-hub-signature-256",
    "x-slack-signature",
    "svix-signature",
    "webhook-signature",
    "x-webhook-signature",
    "x-signature",
    "x-clerk-signature",
}
_DROP_HEADERS = {"host", "content-length", "origin", "referer"}
_MAX_ENDPOINTS = 12
_SUCCESS_KEYS = {"received", "processed", "handled", "accepted", "success", "ok"}
_NEGATIVE_KEYS = {"preview", "dry_run", "valid", "verified"}


class Scanner(BaseScanner):
    """Tests webhook endpoints for missing or invalid signature acceptance."""

    name = "webhook_check"
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
        for req in _discover_webhook_endpoints(network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            endpoint = rewrite_to_backend_url(str(req.url), config)
            if endpoint in seen:
                continue
            seen.add(endpoint)

            body = _body_bytes(getattr(req, "post_data", None))
            headers, stripped = _strip_signature_headers(dict(getattr(req, "headers", {}) or {}))

            finding = self._probe(endpoint, headers, body, stripped, "unsigned_webhook_accepted", stack)
            if finding is not None:
                findings.append(finding)
                continue

            invalid_headers = _invalid_signature_headers(headers, stripped)
            finding = self._probe(endpoint, invalid_headers, body, stripped, "invalid_webhook_signature_accepted", stack)
            if finding is not None:
                findings.append(finding)

        return findings

    def _probe(
        self,
        endpoint: str,
        headers: dict[str, str],
        body: bytes | None,
        stripped: list[str],
        proof_quality: str,
        stack: str,
    ) -> Finding | None:
        status, response_headers, response_body = _send_webhook_probe(endpoint, headers, body)
        acceptance = _has_webhook_acceptance(response_body)
        if status not in {200, 201, 202} or acceptance is None:
            return None
        accepted_path, accepted_value = acceptance
        title = (
            "Unsigned webhook event accepted"
            if proof_quality == "unsigned_webhook_accepted"
            else "Webhook event accepted with invalid signature"
        )
        desc = (
            f"The webhook endpoint `{endpoint}` accepted a webhook delivery with "
            f"{'no signature header' if proof_quality == 'unsigned_webhook_accepted' else 'an invalid signature header'}. "
            "Attackers can forge payment, auth, or integration events if webhook signatures are not verified before processing."
        )
        return self.new_finding(
            scanner=self.name,
            severity=Severity.HIGH,
            title=title,
            description=desc,
            evidence={
                "endpoint": endpoint,
                "test_performed": proof_quality,
                "request": {"method": "POST", "url": endpoint, "headers": headers, "body_excerpt": truncate((body or b"").decode("utf-8", errors="replace"), 240)},
                "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(response_body, 240)},
                "stripped_headers": stripped,
                "acceptance_evidence": {"json_path": accepted_path, "value": accepted_value},
                "expected_response": "Reject missing or invalid webhook signatures before processing the event",
                "proof_quality": proof_quality,
                "network_events": [],
            },
            llm_prompt=self.build_llm_prompt(
                title=title,
                severity=Severity.HIGH,
                scanner=self.name,
                page=endpoint,
                category=self.category,
                description=desc,
                evidence_summary=f"POST {endpoint} returned {accepted_path}=true with proof={proof_quality}",
                stack=stack,
            ),
            remediation=(
                "**What to fix:** Webhook events are processed without strong signature verification.\n\n"
                "**How to fix:** Verify provider signatures using the raw request body and endpoint secret before parsing or mutating state. "
                "Reject missing, malformed, stale timestamp, or invalid signatures with 401/403 and log the rejection safely.\n\n"
                "**Verify the fix:** Re-run webhook_check; unsigned and invalid-signature probes should return 401/403."
            ),
            category=self.category,
            page=endpoint,
        )


def _discover_webhook_endpoints(network: Any, target: str, backend_url: str | None = None) -> list[Any]:
    discovered: list[Any] = []
    seen: set[str] = set()
    for req in network.get_requests():
        if str(getattr(req, "method", "GET")).upper() != "POST":
            continue
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        parsed = urlparse(url)
        if not any(hint in parsed.path.lower() for hint in _WEBHOOK_PATH_HINTS):
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


def _strip_signature_headers(headers: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    clean: dict[str, str] = {}
    stripped: list[str] = []
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in _SIGNATURE_HEADERS:
            stripped.append(lowered)
            continue
        if lowered in _DROP_HEADERS:
            continue
        clean[str(key)] = str(value)
    clean.setdefault("Content-Type", "application/json")
    return clean, sorted(stripped)


def _invalid_signature_headers(headers: dict[str, str], stripped: list[str]) -> dict[str, str]:
    invalid = dict(headers)
    header = _canonical_signature_header(stripped[0]) if stripped else "Stripe-Signature"
    invalid[header] = "t=0,v1=invalid"
    return invalid


def _canonical_signature_header(lowered: str) -> str:
    return {
        "stripe-signature": "Stripe-Signature",
        "x-hub-signature": "X-Hub-Signature",
        "x-hub-signature-256": "X-Hub-Signature-256",
        "x-slack-signature": "X-Slack-Signature",
        "svix-signature": "Svix-Signature",
        "webhook-signature": "Webhook-Signature",
        "x-webhook-signature": "X-Webhook-Signature",
        "x-signature": "X-Signature",
        "x-clerk-signature": "X-Clerk-Signature",
    }.get(lowered, "Stripe-Signature")


def _body_bytes(body: Any) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    return str(body).encode("utf-8")


def _send_webhook_probe(
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
        return exc.code, _normalize_headers(exc.headers), exc.read(1024).decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""


def _normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}


def _has_webhook_acceptance(body: str) -> tuple[str, Any] | None:
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    return _find_acceptance(parsed)


def _find_acceptance(value: Any, path: str = "") -> tuple[str, Any] | None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if lowered in _SUCCESS_KEYS and lowered not in _NEGATIVE_KEYS and child is True:
                return child_path, child
            nested = _find_acceptance(child, child_path)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for idx, child in enumerate(value[:5]):
            nested = _find_acceptance(child, f"{path}[{idx}]")
            if nested is not None:
                return nested
    return None
