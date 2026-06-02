"""HTTP method tampering scanner — tests DELETE/PUT on read-only endpoints and method override headers."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".jpg", ".gif", ".map", ".woff2"}
_SKIP_FRAGMENTS = ["/static/", "/assets/", "/_next/", "/__next/", "/favicon"]
_DANGEROUS_METHODS = ["DELETE", "PUT", "PATCH"]
_OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "_method"]
_MAX_ENDPOINTS = 10


def _is_api_endpoint(url: str, target: str, backend_url: str | None = None) -> bool:
    if any(url.endswith(ext) for ext in _STATIC_EXTS):
        return False
    if any(frag in url for frag in _SKIP_FRAGMENTS):
        return False
    parsed = urlparse(url)
    allowed_netlocs = {urlparse(target).netloc}
    if backend_url:
        allowed_netlocs.add(urlparse(backend_url).netloc)
    return parsed.netloc in allowed_netlocs


class Scanner(BaseScanner):
    """Tests API endpoints for dangerous method acceptance and method override bypass."""

    name = "http_method_tampering"
    category = "Misconfiguration"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target
        origin = frontend_origin(config)

        get_endpoints = _discover_get_endpoints(network, target, getattr(config, "backend_url", None))

        seen_fps: set[str] = set()
        for url in get_endpoints[:_MAX_ENDPOINTS]:
            probe_url = rewrite_to_backend_url(url, config)
            # Active preflight: skip HTML page routes. Next.js returns 200 for every
            # HTTP method on page routes (they just re-render HTML), producing false
            # positives. Check the actual GET response body rather than relying on
            # captured response headers, which vary in key casing across CDN layers.
            preflight_status, preflight_body = _fetch(probe_url, "GET", origin=origin)
            if preflight_status is None:
                continue
            if preflight_body and preflight_body.lstrip()[:9].lower().startswith("<!doctype"):
                continue
            self._test_dangerous_methods(probe_url, stack, target, findings, seen_fps, origin)
            self._test_method_override(probe_url, stack, target, findings, seen_fps, origin)

        return findings

    def _test_dangerous_methods(
        self, url: str, stack: str, target: str,
        findings: list[Finding], seen: set[str], origin: str | None,
    ) -> None:
        for method in _DANGEROUS_METHODS:
            status, body = _fetch(url, method, origin=origin)
            if status is None:
                continue
            if status in (405, 501, 404, 403, 401):
                continue

            fp = self.make_fingerprint(self.name, f"{method} accepted on GET endpoint", url)
            if fp in seen:
                continue
            seen.add(fp)

            sev = Severity.CRITICAL if method == "DELETE" else Severity.HIGH
            desc = (
                f"The endpoint `{url}` accepted an HTTP `{method}` request and returned HTTP {status}. "
                "This endpoint was discovered as a GET-only resource. "
                f"Accepting {method} without authorization checks allows attackers to "
                f"{'delete' if method == 'DELETE' else 'modify'} resources they should not be able to touch."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=sev,
                title=f"HTTP method tampering: {method} accepted on {urlparse(url).path}",
                description=desc,
                evidence={
                    "request": {"method": method, "url": url, "headers": {}},
                    "response": {"status": status, "body_excerpt": truncate(body, 200)},
                    "payload_type": "method_tampering",
                    "payload_used": method,
                    "injection_point": "http_method",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"HTTP method tampering: {method} accepted",
                    severity=sev, scanner=self.name, page=url,
                    category=self.category, description=desc,
                    evidence_summary=f"{method} {url} → HTTP {status}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** The endpoint accepts {method} requests it should not handle.\n\n"
                    "**How to fix:** Explicitly define which HTTP methods each route accepts. "
                    "In Express: `router.get('/resource', handler)` — this automatically returns 404 for other methods. "
                    "Add a catch-all: `router.all('/resource', (req, res) => res.status(405).send())`. "
                    "In FastAPI: only define the method you want to expose.\n\n"
                    "**Verify the fix:** Re-run http_method_tampering scanner — endpoint should return 405."
                ),
                category=self.category, page=url,
            ))

    def _test_method_override(
        self, url: str, stack: str, target: str,
        findings: list[Finding], seen: set[str], origin: str | None,
    ) -> None:
        for override_header in _OVERRIDE_HEADERS:
            status, body = _fetch_with_override(url, override_header, "DELETE", origin=origin)
            if status is None:
                continue
            if status in (405, 501, 404, 403, 401):
                continue

            fp = self.make_fingerprint(self.name, f"Method override: {override_header}", url)
            if fp in seen:
                continue
            seen.add(fp)

            desc = (
                f"The server processed a DELETE operation via the `{override_header}: DELETE` header "
                f"in a POST request to `{url}` (HTTP {status}). "
                "Method override headers allow attackers to bypass WAF rules or middleware that "
                "only restricts HTTP methods at the routing layer."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title=f"HTTP method override accepted: `{override_header}: DELETE` on {urlparse(url).path}",
                description=desc,
                evidence={
                    "request": {"method": "POST", "url": url, "headers": {override_header: "DELETE"}},
                    "response": {"status": status, "body_excerpt": truncate(body, 200)},
                    "payload_type": "method_override",
                    "payload_used": f"{override_header}: DELETE",
                    "injection_point": f"request_header:{override_header}",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"HTTP method override accepted: {override_header}",
                    severity=Severity.HIGH, scanner=self.name, page=url,
                    category=self.category, description=desc,
                    evidence_summary=f"POST {url} + {override_header}: DELETE → HTTP {status}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** The `{override_header}` header is processed by the server.\n\n"
                    "**How to fix:** Disable method override middleware in production. "
                    "In Express: remove `methodOverride()` middleware.\n\n"
                    "**Verify the fix:** Re-run http_method_tampering scanner."
                ),
                category=self.category, page=url,
            ))
            break  # one override finding per endpoint


def _discover_get_endpoints(network: Any, target: str, backend_url: str | None = None) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for req in network.get_requests():
        if req.method != "GET":
            continue
        if not _is_api_endpoint(req.url, target, backend_url if isinstance(backend_url, str) else None):
            continue
        # Skip HTML page routes using CDP's normalised mimeType field.
        # The active preflight in run() is the authoritative filter; this is
        # a cheap early-out to avoid collecting page URLs in the first place.
        if req.response_mime_type and "text/html" in req.response_mime_type:
            continue
        parsed = urlparse(req.url)
        key = f"{parsed.netloc}{parsed.path}"
        if key not in seen:
            seen.add(key)
            result.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
    return result


def _fetch(url: str, method: str, origin: str | None = None, timeout: int = 5) -> tuple[int | None, str]:
    try:
        headers = {"User-Agent": "vibe-iterator/method-check"}
        if origin:
            headers["Origin"] = origin
        req = urllib.request.Request(
            url, method=method,
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(2000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def _fetch_with_override(
    url: str, override_header: str, method: str, origin: str | None = None, timeout: int = 5
) -> tuple[int | None, str]:
    try:
        headers = {
            override_header: method,
            "Content-Type": "application/json",
            "User-Agent": "vibe-iterator/method-override-check",
        }
        if origin:
            headers["Origin"] = origin
        req = urllib.request.Request(
            url, data=b"",
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(2000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""
