"""API exposure scanner — unauthenticated access, security headers, rate limiting."""

from __future__ import annotations

import ssl
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_AUTH_INDICATORS = {"authorization", "x-api-key", "cookie"}
_SENSITIVE_PATH_FRAGMENTS = ["/admin", "/api/admin", "/api/user", "/api/account", "/api/profile", "/api/delete", "/api/update"]
_RATE_LIMIT_HEADERS = {"x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit", "retry-after"}
_AUTH_PATHS = ["/auth", "/login", "/signin", "/token", "/api/auth", "/api/login"]
_MAX_ENDPOINTS = 15

# Required security response headers
_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": None,  # DENY or SAMEORIGIN
    "strict-transport-security": None,
}


def _fetch_without_auth(
    url: str, method: str = "GET", body: bytes | None = None, timeout: int = 5,
) -> tuple[int, dict[str, str]] | None:
    """Make an HTTP request without auth headers; return (status, headers) or None."""
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(
            url, data=body, method=method,
            headers={"Content-Type": "application/json", "User-Agent": "vibe-iterator/api-check"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}
    except Exception:
        return None


def _has_auth_header(req: Any) -> bool:
    headers = req.headers or {}
    lowered = {k.lower() for k in headers}
    return bool(lowered & _AUTH_INDICATORS)


def _is_api_url(url: str, target: str) -> bool:
    if any(url.endswith(ext) for ext in _STATIC_EXTS):
        return False
    parsed = urlparse(url)
    return parsed.netloc == urlparse(target).netloc


class Scanner(BaseScanner):
    """Discovers and tests API endpoints for auth gaps and missing security headers."""

    name = "api_exposure"
    category = "API Security"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target

        requests = [r for r in network.get_requests() if _is_api_url(r.url, target)]

        self._check_security_headers(requests, target, stack, findings)
        self._check_unauth_access(requests, target, stack, findings)
        self._check_rate_limiting(requests, target, stack, findings)
        return findings

    # ------------------------------------------------------------------ #
    # Security response headers (passive)                                 #
    # ------------------------------------------------------------------ #

    def _check_security_headers(
        self, requests: list, target: str, stack: str, findings: list[Finding],
    ) -> None:
        seen_fps: set[str] = set()

        for req in requests:
            if req.response_headers is None:
                continue
            lowered = {k.lower(): v for k, v in req.response_headers.items()}

            for header_key, expected_val in _SECURITY_HEADERS.items():
                if header_key in lowered:
                    continue
                fp = self.make_fingerprint(self.name, f"Missing header {header_key}", target)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                sev = Severity.LOW
                if header_key == "strict-transport-security":
                    sev = Severity.MEDIUM

                desc = (
                    f"The `{header_key}` HTTP security header is missing from API responses. "
                    f"This header provides browser-level protection against common web attacks. "
                    f"{'HSTS prevents downgrade attacks and cookie hijacking over HTTP.' if header_key == 'strict-transport-security' else 'This helps prevent MIME sniffing and framing attacks.'}"
                )
                expected_str = f"{header_key}: {expected_val}" if expected_val else f"{header_key}: <value>"
                findings.append(self.new_finding(
                    scanner=self.name, severity=sev,
                    title=f"Missing security header: {header_key}",
                    description=desc,
                    evidence={
                        "endpoint": req.url,
                        "test_performed": "header_inspection",
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": getattr(req, "status_code", "?"), "headers": dict(lowered)},
                        "expected_response": f"Response should include: {expected_str}",
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Missing security header: {header_key}",
                        severity=sev, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"Header `{header_key}` absent.\nExpected: {expected_str}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** Add the `{header_key}` header to all responses.\n\n"
                        f"**How to fix:** In your server middleware, set: `{expected_str}`. "
                        "For Next.js, add to `next.config.js` headers configuration. "
                        "For Express: use the `helmet` middleware package which sets these automatically.\n\n"
                        "**Verify the fix:** Run `curl -I <your-endpoint>` and verify the header is present."
                    ),
                    category=self.category, page=req.url,
                ))

    # ------------------------------------------------------------------ #
    # Unauthenticated access check (active)                              #
    # ------------------------------------------------------------------ #

    def _check_unauth_access(
        self, requests: list, target: str, stack: str, findings: list[Finding],
    ) -> None:
        seen_fps: set[str] = set()
        tested: set[str] = set()

        for req in requests:
            if not _has_auth_header(req):
                continue

            parsed = urlparse(req.url)
            endpoint_key = f"{req.method}:{parsed.netloc}{parsed.path}"
            if endpoint_key in tested:
                continue

            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if len(tested) >= _MAX_ENDPOINTS:
                break
            tested.add(endpoint_key)

            result = _fetch_without_auth(base_url, method=req.method)
            if result is None:
                continue
            status, resp_headers = result

            if status == 200:
                fp = self.make_fingerprint(self.name, "Authenticated endpoint accessible without auth", base_url)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                sev = Severity.HIGH
                if any(frag in base_url for frag in _SENSITIVE_PATH_FRAGMENTS):
                    sev = Severity.CRITICAL

                desc = (
                    f"The endpoint `{req.method} {base_url}` returned a 200 response when accessed "
                    "without any authentication headers. "
                    "The authenticated user's session was not required — any unauthenticated caller "
                    "can access this endpoint and potentially read or modify data."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=sev,
                    title=f"Unauthenticated access: {req.method} {parsed.path}",
                    description=desc,
                    evidence={
                        "endpoint": base_url,
                        "test_performed": "replay_without_auth",
                        "request": {"method": req.method, "url": base_url, "headers": {}},
                        "response": {"status": status, "body_excerpt": "(response received)"},
                        "expected_response": "401 Unauthorized or 403 Forbidden",
                        "actual_response": f"{status} OK — endpoint accessible without auth",
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Unauthenticated access: {req.method} {parsed.path}",
                        severity=sev, scanner=self.name, page=base_url,
                        category=self.category, description=desc,
                        evidence_summary=(
                            f"Endpoint: {req.method} {base_url}\n"
                            f"Replayed without Authorization header → received: {status} OK\n"
                            f"Expected: 401 or 403"
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** `{req.method} {parsed.path}` does not require authentication.\n\n"
                        "**How to fix:** Add authentication middleware to this endpoint. "
                        "For Supabase/Next.js: verify `session` on the server side before returning data. "
                        "For Express: add a `requireAuth` middleware that checks the JWT before the route handler.\n\n"
                        "**Verify the fix:** Re-run api_exposure scanner — the endpoint should now return 401."
                    ),
                    category=self.category, page=base_url,
                ))

    # ------------------------------------------------------------------ #
    # Rate limiting on sensitive endpoints (passive)                     #
    # ------------------------------------------------------------------ #

    def _check_rate_limiting(
        self, requests: list, target: str, stack: str, findings: list[Finding],
    ) -> None:
        seen_fps: set[str] = set()

        for req in requests:
            parsed = urlparse(req.url)
            is_auth_path = any(frag in parsed.path.lower() for frag in _AUTH_PATHS)
            if not is_auth_path:
                continue

            headers = req.response_headers or {}
            lowered = {k.lower() for k in headers}
            has_rate_limit = bool(lowered & _RATE_LIMIT_HEADERS)

            if not has_rate_limit:
                fp = self.make_fingerprint(self.name, "No rate limiting on auth endpoint", req.url)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                desc = (
                    f"The authentication endpoint `{req.url}` does not appear to implement rate limiting. "
                    "No standard rate limit headers (`X-RateLimit-Limit`, `Retry-After`) were observed. "
                    "Without rate limiting, an attacker can attempt unlimited password guesses against user accounts."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title=f"No rate limiting on auth endpoint: {parsed.path}",
                    description=desc,
                    evidence={
                        "endpoint": req.url,
                        "test_performed": "rate_limit_header_check",
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": getattr(req, "status_code", "?"), "headers": dict(headers)},
                        "expected_response": "Response should include X-RateLimit-Limit or Retry-After headers",
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"No rate limiting on auth endpoint: {parsed.path}",
                        severity=Severity.MEDIUM, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=(
                            f"Endpoint: {req.url}\n"
                            "No X-RateLimit-Limit or Retry-After headers in response.\n"
                            "Brute-force attacks are possible."
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Add rate limiting to authentication endpoints.\n\n"
                        "**How to fix:** "
                        "For Supabase Auth: it has built-in rate limiting — ensure it is not disabled. "
                        "For custom auth: use a rate limiter (e.g., `express-rate-limit` for Express, "
                        "`slowapi` for FastAPI, or Cloudflare rate limit rules). "
                        "Add exponential backoff after 5 failed attempts.\n\n"
                        "**Verify the fix:** Check that rapid repeated requests return 429 Too Many Requests."
                    ),
                    category=self.category, page=req.url,
                ))
