"""API key exposure scanner — detects leaked API keys in network traffic and browser storage.

Three scan groups:
  1. Request headers / query parameters — API keys sent over the wire
  2. Response bodies — service keys returned by the app to the browser
  3. Browser storage — localStorage, sessionStorage, cookies
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from vibe_iterator.scanners.base import BaseScanner, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# (compiled_pattern, label, severity)
_KEY_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # --- Stripe ---
    (re.compile(r"sk_live_[a-zA-Z0-9]{24,}"), "Stripe live secret key", Severity.CRITICAL),
    (re.compile(r"rk_live_[a-zA-Z0-9]{24,}"), "Stripe live restricted key", Severity.CRITICAL),
    (re.compile(r"sk_test_[a-zA-Z0-9]{24,}"), "Stripe test secret key", Severity.HIGH),
    (re.compile(r"pk_live_[a-zA-Z0-9]{24,}"), "Stripe live publishable key", Severity.HIGH),
    (re.compile(r"pk_test_[a-zA-Z0-9]{24,}"), "Stripe test publishable key", Severity.MEDIUM),
    # --- AWS ---
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID", Severity.CRITICAL),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key ID", Severity.HIGH),
    (re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})", re.I), "AWS secret access key", Severity.CRITICAL),
    # --- GitHub ---
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token", Severity.CRITICAL),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{82}"), "GitHub fine-grained PAT", Severity.CRITICAL),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth token", Severity.CRITICAL),
    (re.compile(r"ghs_[a-zA-Z0-9]{36}"), "GitHub app installation token", Severity.HIGH),
    # --- Slack ---
    (re.compile(r"xoxb-[0-9]+-[a-zA-Z0-9-]+"), "Slack bot token", Severity.CRITICAL),
    (re.compile(r"xoxp-[0-9]+-[a-zA-Z0-9-]+"), "Slack user token", Severity.CRITICAL),
    (re.compile(r"xoxa-2-[a-zA-Z0-9-]+"), "Slack app token", Severity.HIGH),
    # --- OpenAI ---
    (re.compile(r"sk-proj-[a-zA-Z0-9_\-]{48,}"), "OpenAI project API key", Severity.CRITICAL),
    (re.compile(r"sk-[a-zA-Z0-9]{48}"), "OpenAI API key", Severity.CRITICAL),
    # --- Anthropic ---
    (re.compile(r"sk-ant-[a-zA-Z0-9_\-]{95,}"), "Anthropic API key", Severity.CRITICAL),
    # --- Google ---
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key", Severity.HIGH),
    # --- Twilio ---
    (re.compile(r"AC[a-z0-9]{32}"), "Twilio account SID", Severity.HIGH),
    (re.compile(r"SK[a-z0-9]{32}"), "Twilio API key SID", Severity.HIGH),
    # --- SendGrid ---
    (re.compile(r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}"), "SendGrid API key", Severity.CRITICAL),
    # --- Mailgun ---
    (re.compile(r"key-[0-9a-f]{32}"), "Mailgun API key", Severity.HIGH),
    # --- Supabase ---
    (re.compile(r"sbp_[a-zA-Z0-9]{40}"), "Supabase personal access token", Severity.CRITICAL),
    # --- Generic hardcoded patterns ---
    (re.compile(r"""(?:api[_-]?key|apikey|API[_-]?KEY)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{24,})['"]""", re.I), "Hardcoded API key value", Severity.HIGH),
    (re.compile(r"""(?:api[_-]?secret|API[_-]?SECRET)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{24,})['"]""", re.I), "Hardcoded API secret value", Severity.HIGH),
    (re.compile(r"""(?:access[_-]?token|ACCESS[_-]?TOKEN)\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{24,})['"]""", re.I), "Hardcoded access token", Severity.HIGH),
]

# Request headers that carry credentials — flag if value looks like a key
_SENSITIVE_HEADERS = {"x-api-key", "api-key", "x-auth-token", "x-access-token", "x-secret-key"}

# Query parameters that commonly carry API keys
_SENSITIVE_PARAMS = {"api_key", "apikey", "key", "token", "access_token", "auth", "secret", "api_secret"}

_TEXT_MIME_TYPES = {"text/", "application/json", "application/javascript", "application/xml"}


class Scanner(BaseScanner):
    """Detects API keys and tokens leaked in network traffic or browser storage."""

    name = "api_key_exposure"
    category = "Data Leakage"
    stages = ["post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners.get("network")
        storage = listeners.get("storage")

        if network:
            self._check_network(network, findings)
        if storage:
            self._check_storage(storage, findings)

        return findings

    # ------------------------------------------------------------------ #
    # Group 1 + 2 — Network traffic                                       #
    # ------------------------------------------------------------------ #

    def _check_network(self, network: Any, findings: list[Finding]) -> None:
        seen: set[str] = set()
        for req in network.get_requests():
            # Request headers
            for name, value in (req.headers or {}).items():
                if name.lower() in _SENSITIVE_HEADERS:
                    self._scan_text(
                        value, f"request header '{name}'", req.url, "request_header", seen, findings
                    )

            # Query parameters containing raw key values
            if "?" in req.url:
                self._check_url_params(req.url, seen, findings)

            # Response bodies (text/JSON/JS only; skip binary)
            body = req.response_body or ""
            mime = (req.response_mime_type or "").lower()
            if body and any(t in mime for t in _TEXT_MIME_TYPES):
                self._scan_text(body, "response body", req.url, "response_body", seen, findings)

    def _check_url_params(self, url: str, seen: set, findings: list[Finding]) -> None:
        try:
            params = parse_qs(urlparse(url).query)
        except Exception:
            return
        for param, values in params.items():
            if param.lower() not in _SENSITIVE_PARAMS:
                continue
            for value in values:
                if len(value) < 16:
                    continue
                key = f"url-param:{param}:{url}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(BaseScanner.new_finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title=f"API key in URL query parameter: {param}",
                    description=(
                        f"The query parameter `{param}` in `{truncate(url, 80)}` carries a value "
                        "that appears to be an API key or token. Keys in URLs are logged by servers, "
                        "stored in browser history, and leaked in `Referer` headers to third parties."
                    ),
                    evidence={
                        "url": url,
                        "parameter": param,
                        "payload_type": "api_key_in_url",
                        "payload_used": f"{param}=<value>",
                        "injection_point": "query_string",
                        "network_events": [],
                    },
                    llm_prompt=BaseScanner.build_llm_prompt(
                        title=f"API key in URL query parameter: {param}",
                        severity=Severity.HIGH,
                        scanner=self.name,
                        page=url,
                        category=self.category,
                        description=f"API key detected in query param `{param}` at `{truncate(url, 80)}`.",
                        evidence_summary=f"Parameter: {param}\nURL: {truncate(url, 80)}",
                    ),
                    remediation=(
                        "**How to fix:** Pass API keys in the `Authorization` request header "
                        "(`Authorization: Bearer <token>`) instead of URL query parameters. "
                        "Rotate any key that has appeared in a URL."
                    ),
                    category=self.category,
                    page=url,
                ))

    # ------------------------------------------------------------------ #
    # Group 3 — Browser storage                                           #
    # ------------------------------------------------------------------ #

    def _check_storage(self, storage: Any, findings: list[Finding]) -> None:
        seen: set[str] = set()
        for snapshot in storage.get_snapshots():
            page_url = snapshot.url

            for store_name, store_dict in [
                ("localStorage", snapshot.local_storage),
                ("sessionStorage", snapshot.session_storage),
            ]:
                for key, value in store_dict.items():
                    self._scan_text(
                        f"{key}={value}",
                        f"{store_name} key '{key}'",
                        page_url,
                        store_name,
                        seen,
                        findings,
                    )

            for cookie in snapshot.cookies:
                name = cookie.get("name", "")
                value = cookie.get("value", "")
                self._scan_text(
                    f"{name}={value}",
                    f"cookie '{name}'",
                    page_url,
                    "cookie",
                    seen,
                    findings,
                )

    # ------------------------------------------------------------------ #
    # Shared pattern matching                                             #
    # ------------------------------------------------------------------ #

    def _scan_text(
        self,
        text: str,
        context: str,
        url: str,
        location: str,
        seen: set,
        findings: list[Finding],
    ) -> None:
        for pattern, label, severity in _KEY_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            dedup_key = f"{label}:{url}:{location}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            raw = m.group(0)
            fp = hashlib.sha256(raw.encode()).hexdigest()[:8]
            masked = f"{raw[:4]}***{raw[-2:]} (sha256:{fp})"
            title = f"API key exposed in {context}: {label}"
            desc = (
                f"A `{label}` was detected in {context} at `{truncate(url, 80)}`. "
                f"Masked value: `{masked}`. "
                "Exposed API keys can be extracted by any user monitoring network traffic, "
                "reading browser DevTools, or running a script on your page."
            )
            remediation = (
                f"**Immediate:** Rotate the exposed `{label}` — treat it as compromised.\n\n"
                "**How to fix:** Move API keys to your server-side backend and never include "
                "them in responses sent to the browser. For SDKs that require a public key "
                "(e.g., Stripe publishable key), ensure only the publishable (non-secret) "
                "variant is used client-side.\n\n"
                "**Verify the fix:** Re-run `api_key_exposure` — zero findings expected."
            )
            findings.append(BaseScanner.new_finding(
                scanner=self.name,
                severity=severity,
                title=title,
                description=desc,
                evidence={
                    "url": url,
                    "location": location,
                    "key_type": label,
                    "masked_value": masked,
                    "payload_type": "api_key_exposure",
                    "payload_used": "passive — pattern match",
                    "injection_point": location,
                    "network_events": [],
                },
                llm_prompt=BaseScanner.build_llm_prompt(
                    title=title,
                    severity=severity,
                    scanner=self.name,
                    page=url,
                    category=self.category,
                    description=desc,
                    evidence_summary=f"Location: {location}\nKey type: {label}\nMasked value: {masked}",
                ),
                remediation=remediation,
                category=self.category,
                page=url,
            ))
