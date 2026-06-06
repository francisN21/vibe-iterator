"""Open redirect scanner - probes redirect parameters for external Location headers."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import frontend_origin, rewrite_to_backend_url

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_url", "return", "return_url",
    "return_to", "continue", "callback", "destination",
}
_EVIL_URL = "https://evil.example/vibe-redirect-proof"
_MAX_ENDPOINTS = 12


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class Scanner(BaseScanner):
    """Tests whether redirect parameters can send users to attacker-controlled origins."""

    name = "open_redirect_check"
    category = "Misconfiguration"
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
        origin = frontend_origin(config)

        seen: set[str] = set()
        for url, param in _discover_redirect_targets(network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            probe_frontend_url = _replace_param(url, param, _EVIL_URL)
            probe_url = rewrite_to_backend_url(probe_frontend_url, config)
            parsed = urlparse(probe_url)
            key = f"{parsed.netloc}{parsed.path}:{param}"
            if key in seen:
                continue
            seen.add(key)

            status, headers = _fetch_no_redirect(probe_url, origin=origin)
            location = headers.get("location", "")
            proof_quality = _external_redirect_proof_quality(location, target, backend_url, status)
            if proof_quality is None:
                continue

            desc = (
                f"The endpoint `{probe_url}` redirected to `{location}` when the `{param}` "
                "parameter was set to an attacker-controlled absolute URL. "
                "Attackers can use this to craft trusted-looking links for phishing, token leakage, "
                "or OAuth-style redirect abuse."
            )
            findings.append(self.new_finding(
                scanner=self.name,
                severity=Severity.HIGH,
                title=f"Open redirect via `{param}` parameter",
                description=desc,
                evidence={
                    "endpoint": probe_url,
                    "test_performed": "external_redirect_parameter_probe",
                    "injection_point": f"query_param:{param}",
                    "payload_used": _EVIL_URL,
                    "request": {"method": "GET", "url": probe_url, "headers": {"Origin": origin} if origin else {}},
                    "response": {"status": status, "location": location},
                    "expected_response": "Reject external absolute URLs or normalize to a same-origin path",
                    "proof_quality": proof_quality,
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"Open redirect via `{param}` parameter",
                    severity=Severity.HIGH,
                    scanner=self.name,
                    page=probe_url,
                    category=self.category,
                    description=desc,
                    evidence_summary=f"GET {probe_url} -> HTTP {status} Location: {location}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** The `{param}` redirect parameter accepts external absolute URLs.\n\n"
                    "**How to fix:** Only allow relative same-origin paths, or validate redirect targets "
                    "against a strict allowlist of trusted origins. Reject protocol-relative URLs, "
                    "`http://`, `https://`, and encoded variants unless they are explicitly allowed.\n\n"
                    "**Verify the fix:** Re-run open_redirect_check; the probe should not return a "
                    "`Location` header pointing to `evil.example`."
                ),
                category=self.category,
                page=probe_url,
            ))
            break

        return findings


def _discover_redirect_targets(network: Any, target: str, backend_url: str | None = None) -> list[tuple[str, str]]:
    discovered: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for req in network.get_requests():
        if getattr(req, "method", "GET") != "GET":
            continue
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        parsed = urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            if param.lower() not in _REDIRECT_PARAMS:
                continue
            key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", param)
            if key in seen:
                continue
            seen.add(key)
            discovered.append((url, param))
    return discovered


def _is_same_app_url(url: str, target: str, backend_url: str | None = None) -> bool:
    if any(url.endswith(ext) for ext in _STATIC_EXTS):
        return False
    if any(frag in url for frag in _SKIP_FRAGMENTS):
        return False
    parsed = urlparse(url)
    allowed = {urlparse(target).netloc}
    if backend_url:
        allowed.add(urlparse(backend_url).netloc)
    return parsed.netloc in allowed


def _replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def _fetch_no_redirect(url: str, origin: str | None = None, timeout: int = 5) -> tuple[int | None, dict[str, str]]:
    headers = {"User-Agent": "vibe-iterator/open-redirect-check"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}
    except Exception:
        return None, {}


def _external_redirect_proof_quality(
    location: str, target: str, backend_url: str | None, status: int | None,
) -> str | None:
    if status is None or status < 300 or status >= 400:
        return None
    parsed = urlparse(location)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    allowed = {urlparse(target).netloc}
    if backend_url:
        allowed.add(urlparse(backend_url).netloc)
    if parsed.netloc in allowed:
        return None
    if location.startswith(_EVIL_URL):
        return "external_absolute_location_header"
    return "external_absolute_redirect_to_untrusted_origin"
