"""CORS misconfiguration scanner — tests cross-origin request policies."""

from __future__ import annotations

import ssl
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_MAX_ENDPOINTS = 12


def _fetch_with_origin(url: str, origin: str, timeout: int = 5) -> dict[str, str] | None:
    """Send a request with a custom Origin header, return lowercased response headers."""
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, headers={"Origin": origin, "User-Agent": "vibe-iterator/cors-check"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return None


def _is_api_endpoint(url: str, target: str) -> bool:
    if any(url.endswith(ext) for ext in _STATIC_EXTS):
        return False
    parsed = urlparse(url)
    return parsed.netloc == urlparse(target).netloc


def _dedup_endpoints(requests: list, target: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for req in requests:
        if not _is_api_endpoint(req.url, target):
            continue
        parsed = urlparse(req.url)
        key = f"{parsed.netloc}{parsed.path}"
        if key not in seen:
            seen.add(key)
            result.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
        if len(result) >= _MAX_ENDPOINTS:
            break
    return result


class Scanner(BaseScanner):
    """Tests CORS headers for overly permissive configurations."""

    name = "cors_check"
    category = "Misconfiguration"
    stages = ["post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target

        endpoints = _dedup_endpoints(network.get_requests(), target)
        if not endpoints:
            endpoints = [target.rstrip("/")]

        seen_fps: set[str] = set()
        for url in endpoints:
            try:
                self._test_endpoint(url, stack, findings, seen_fps)
            except Exception:
                continue

        return findings

    def _test_endpoint(
        self, url: str, stack: str, findings: list[Finding], seen: set[str],
    ) -> None:
        evil_origin = "https://evil-attacker.com"

        headers = _fetch_with_origin(url, evil_origin)
        if headers:
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()

            if acao == "*" and acac == "true":
                fp = self.make_fingerprint(self.name, "CORS credentials with wildcard origin", url)
                if fp not in seen:
                    seen.add(fp)
                    desc = (
                        "The server allows any origin with credentials (cookies/auth headers). "
                        "An attacker on any website can make authenticated requests to your API "
                        "using the victim's session cookie. "
                        "This is the most dangerous CORS misconfiguration and enables full account takeover."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.CRITICAL,
                        title="CORS: credentials allowed with wildcard origin",
                        description=desc,
                        evidence={
                            "test_origin_sent": evil_origin,
                            "request": {"method": "GET", "url": url, "headers": {"Origin": evil_origin}},
                            "response_headers": {
                                "Access-Control-Allow-Origin": acao,
                                "Access-Control-Allow-Credentials": acac,
                            },
                            "issue": "credentials_with_wildcard",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="CORS: credentials allowed with wildcard origin",
                            severity=Severity.CRITICAL, scanner=self.name, page=url,
                            category=self.category, description=desc,
                            evidence_summary=(
                                f"URL: {url}\n"
                                f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}"
                            ),
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** `Access-Control-Allow-Origin: *` must never be combined "
                            "with `Access-Control-Allow-Credentials: true`.\n\n"
                            "**How to fix:** Replace the wildcard with an explicit allowlist of trusted "
                            "origins. Validate the request `Origin` header against that list before "
                            "reflecting it in the response.\n\n"
                            "**Verify the fix:** Re-run cors_check — 0 findings expected."
                        ),
                        category=self.category, page=url,
                    ))

            elif acao == evil_origin:
                fp = self.make_fingerprint(self.name, "CORS origin reflected without validation", url)
                if fp not in seen:
                    seen.add(fp)
                    desc = (
                        "The server reflects any request Origin header directly into the response. "
                        "This bypasses CORS protection entirely — any website can make cross-origin "
                        "requests to your API using the victim's session. "
                        "An attacker can exfiltrate authenticated API responses."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title="CORS: origin header reflected without validation",
                        description=desc,
                        evidence={
                            "test_origin_sent": evil_origin,
                            "request": {"method": "GET", "url": url, "headers": {"Origin": evil_origin}},
                            "response_headers": {
                                "Access-Control-Allow-Origin": acao,
                                "Access-Control-Allow-Credentials": acac or "not set",
                            },
                            "issue": "reflected_origin",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="CORS origin reflected without validation",
                            severity=Severity.HIGH, scanner=self.name, page=url,
                            category=self.category, description=desc,
                            evidence_summary=f"Sent Origin: {evil_origin}\nReceived ACAO: {acao}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** The CORS origin allowlist is not enforced.\n\n"
                            "**How to fix:** Maintain an explicit list of allowed origins and only "
                            "set `Access-Control-Allow-Origin` when the request Origin matches. "
                            "Never reflect the request Origin value blindly.\n\n"
                            "**Verify the fix:** Re-run cors_check scanner."
                        ),
                        category=self.category, page=url,
                    ))

            elif acao == "*":
                fp = self.make_fingerprint(self.name, "CORS wildcard origin on API endpoint", url)
                if fp not in seen:
                    seen.add(fp)
                    desc = (
                        "This API endpoint allows requests from any origin via a wildcard CORS policy. "
                        "Any website can read the response of unauthenticated requests to this endpoint. "
                        "If the endpoint returns user-specific data, this may expose sensitive information."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.LOW,
                        title="CORS: wildcard origin on API endpoint",
                        description=desc,
                        evidence={
                            "test_origin_sent": evil_origin,
                            "request": {"method": "GET", "url": url, "headers": {"Origin": evil_origin}},
                            "response_headers": {"Access-Control-Allow-Origin": acao},
                            "issue": "wildcard_origin",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="CORS wildcard origin on API endpoint",
                            severity=Severity.LOW, scanner=self.name, page=url,
                            category=self.category, description=desc,
                            evidence_summary=f"URL: {url}\nAccess-Control-Allow-Origin: *",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** Restrict CORS to known trusted origins.\n\n"
                            "**How to fix:** Replace `Access-Control-Allow-Origin: *` with an "
                            "explicit allowlist for any endpoint that returns data. "
                            "Wildcard is acceptable only on fully public resources with no user data.\n\n"
                            "**Verify the fix:** Confirm sensitive endpoints return specific origins."
                        ),
                        category=self.category, page=url,
                    ))

        # ---- Test: null origin ----
        null_headers = _fetch_with_origin(url, "null")
        if null_headers:
            acao = null_headers.get("access-control-allow-origin", "")
            if acao == "null":
                fp = self.make_fingerprint(self.name, "CORS null origin accepted", url)
                if fp not in seen:
                    seen.add(fp)
                    desc = (
                        "The server accepts cross-origin requests from a `null` origin. "
                        "Sandboxed iframes and local HTML files send a `null` Origin. "
                        "An attacker can exploit this to make cross-origin requests from a "
                        "sandboxed iframe on any website they control."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="CORS: null origin accepted",
                        description=desc,
                        evidence={
                            "test_origin_sent": "null",
                            "request": {"method": "GET", "url": url, "headers": {"Origin": "null"}},
                            "response_headers": {"Access-Control-Allow-Origin": acao},
                            "issue": "null_origin_accepted",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="CORS null origin accepted",
                            severity=Severity.MEDIUM, scanner=self.name, page=url,
                            category=self.category, description=desc,
                            evidence_summary=f"Sent Origin: null\nReceived ACAO: {acao}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** Remove `null` from the CORS origins allowlist.\n\n"
                            "**How to fix:** Update your CORS configuration to only allow explicit "
                            "https:// origins. The `null` origin should never appear in an allowlist.\n\n"
                            "**Verify the fix:** Re-run cors_check scanner."
                        ),
                        category=self.category, page=url,
                    ))
