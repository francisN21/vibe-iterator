"""Information disclosure scanner — exposes debug endpoints, docs, secrets, and version headers."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# (path, label, severity)
_SENSITIVE_PATHS: list[tuple[str, str, Severity]] = [
    ("/.env", "Environment file", Severity.CRITICAL),
    ("/.env.local", "Environment file", Severity.CRITICAL),
    ("/.env.production", "Environment file", Severity.CRITICAL),
    ("/.env.development", "Environment file", Severity.HIGH),
    ("/swagger.json", "API documentation", Severity.MEDIUM),
    ("/swagger.yaml", "API documentation", Severity.MEDIUM),
    ("/openapi.json", "API documentation", Severity.MEDIUM),
    ("/openapi.yaml", "API documentation", Severity.MEDIUM),
    ("/api-docs", "API documentation", Severity.MEDIUM),
    ("/api-docs.json", "API documentation", Severity.MEDIUM),
    ("/v1/api-docs", "API documentation", Severity.MEDIUM),
    ("/swagger-ui/", "Swagger UI", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI", Severity.MEDIUM),
    ("/redoc", "API documentation", Severity.MEDIUM),
    ("/__debug__", "Debug endpoint", Severity.HIGH),
    ("/debug", "Debug endpoint", Severity.HIGH),
    ("/debug-info", "Debug endpoint", Severity.HIGH),
    ("/actuator/env", "Spring Actuator env", Severity.HIGH),
    ("/actuator/health", "Health endpoint", Severity.LOW),
    ("/actuator", "Spring Actuator", Severity.MEDIUM),
    ("/.git/config", "Git repository", Severity.HIGH),
    ("/.git/HEAD", "Git repository", Severity.HIGH),
    ("/phpinfo.php", "PHP info", Severity.HIGH),
    ("/server-status", "Apache server status", Severity.MEDIUM),
    ("/console", "Admin console", Severity.HIGH),
]

_VERSION_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"}

# Patterns that indicate version numbers in header values
_VERSION_PATTERN = re.compile(r"\d+\.\d+")

_STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at \S+\.\S+\([\w.]+:\d+\)"),  # Java/JS stack
    re.compile(r"java\.lang\.\w+Exception", re.I),
    re.compile(r"System\.Exception", re.I),
    re.compile(r"in .*?\.php on line \d+", re.I),
    re.compile(r"RuntimeError|AttributeError|TypeError|ValueError", re.I),
]

# (compiled_pattern, label, severity)
_SECRET_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"sk_live_[a-zA-Z0-9]{24,}"), "Stripe live secret key", Severity.CRITICAL),
    (re.compile(r"sk_test_[a-zA-Z0-9]{24,}"), "Stripe test secret key", Severity.HIGH),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID", Severity.CRITICAL),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token", Severity.CRITICAL),
    (re.compile(r"xoxb-[0-9]+-[a-zA-Z0-9-]+"), "Slack bot token", Severity.HIGH),
    (re.compile(r"xoxp-[0-9]+-[a-zA-Z0-9-]+"), "Slack user token", Severity.HIGH),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key", Severity.HIGH),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})", re.I), "Hardcoded password", Severity.HIGH),
    (re.compile(r"(?:secret_?key|SECRET_?KEY)\s*[=:]\s*['\"]([^'\"]{8,})", re.I), "Hardcoded secret key", Severity.HIGH),
]

_JS_CONTENT_TYPES = {"application/javascript", "text/javascript", "application/x-javascript"}


class Scanner(BaseScanner):
    """Four-group information disclosure audit."""

    name = "info_disclosure"
    category = "Misconfiguration"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target.rstrip("/")

        self._probe_sensitive_paths(target, stack, findings)
        self._check_version_headers(network, target, stack, findings)
        self._check_stack_traces(network, target, stack, findings)
        self._check_js_secrets(network, target, stack, findings)

        return findings

    # ------------------------------------------------------------------ #
    # Group 1 — Probe sensitive paths                                      #
    # ------------------------------------------------------------------ #

    def _probe_sensitive_paths(
        self, target: str, stack: str, findings: list[Finding]
    ) -> None:
        ctx = ssl._create_unverified_context()
        seen_fps: set[str] = set()

        for path, label, severity in _SENSITIVE_PATHS:
            url = target + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "vibe-iterator/info-check"})
                with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                    status = resp.status
                    body = resp.read(2048).decode("utf-8", errors="replace")
            except urllib.error.HTTPError:
                continue  # 401/403/404 — expected, not exposed
            except Exception:
                continue

            if status != 200:
                continue

            fp = self.make_fingerprint(self.name, f"Sensitive path exposed: {path}", target)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)

            desc = (
                f"The path `{path}` ({label}) returned HTTP 200 and is accessible without authentication. "
                "Exposed documentation, configuration files, or debug endpoints can reveal API structure, "
                "internal credentials, or server configuration to attackers."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=severity,
                title=f"Sensitive path exposed: {path} ({label})",
                description=desc,
                evidence={
                    "request": {"method": "GET", "url": url},
                    "response": {"status": status, "body_excerpt": truncate(body, 300)},
                    "payload_type": "path_probe",
                    "payload_used": path,
                    "injection_point": "url_path",
                    "network_events": [],
                },
                llm_prompt=self.build_llm_prompt(
                    title=f"Sensitive path exposed: {path}",
                    severity=severity, scanner=self.name, page=url,
                    category=self.category, description=desc,
                    evidence_summary=f"GET {url} → HTTP {status}\nContent: {truncate(body, 200)}",
                    stack=stack,
                ),
                remediation=(
                    f"**What to fix:** `{path}` is publicly accessible.\n\n"
                    "**How to fix:** "
                    "For `.env` files: ensure your web server never serves them. "
                    "In nginx: `location ~ /\\.env { deny all; }`. "
                    "For swagger/api-docs: require authentication middleware on documentation routes. "
                    "For debug endpoints: disable them in production via environment variables.\n\n"
                    "**Verify the fix:** Re-run info_disclosure scanner — path should return 401 or 404."
                ),
                category=self.category, page=url,
            ))

    # ------------------------------------------------------------------ #
    # Group 2 — Version disclosure in response headers                    #
    # ------------------------------------------------------------------ #

    def _check_version_headers(
        self, network: Any, target: str, stack: str, findings: list[Finding]
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            if req.response_headers is None:
                continue
            lowered = {k.lower(): v for k, v in req.response_headers.items()}

            for header_key in _VERSION_HEADERS:
                val = lowered.get(header_key, "")
                if not val:
                    continue
                # Only flag if it contains a version number
                if not _VERSION_PATTERN.search(val):
                    # Still flag X-Powered-By even without version (leaks tech stack)
                    if header_key != "x-powered-by":
                        continue

                fp = self.make_fingerprint(self.name, f"Version disclosure: {header_key}", target)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                desc = (
                    f"The `{header_key}: {val}` response header reveals the server software and version. "
                    "Attackers use version information to look up known vulnerabilities (CVEs) for the "
                    "specific version in use and craft targeted exploits."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.LOW,
                    title=f"Version disclosure via `{header_key}` header",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": getattr(req, "status_code", "?"), "headers": {header_key: val}},
                        "payload_type": "header_inspection",
                        "payload_used": f"{header_key}: {val}",
                        "injection_point": f"response_header:{header_key}",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Version disclosure via `{header_key}`",
                        severity=Severity.LOW, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"Header: {header_key}: {val}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** Remove or redact the `{header_key}` header.\n\n"
                        "**How to fix:** "
                        "For nginx: `server_tokens off;`. "
                        "For Express/Node.js: `app.disable('x-powered-by')` or use `helmet`. "
                        "For Apache: `ServerTokens Prod; ServerSignature Off`.\n\n"
                        "**Verify the fix:** Re-run info_disclosure scanner."
                    ),
                    category=self.category, page=req.url,
                ))

    # ------------------------------------------------------------------ #
    # Group 3 — Stack traces in error responses                           #
    # ------------------------------------------------------------------ #

    def _check_stack_traces(
        self, network: Any, target: str, stack: str, findings: list[Finding]
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            if req.status_code not in (500, 502, 503):
                continue
            body = req.response_body or ""
            if not body:
                continue

            for pattern in _STACK_TRACE_PATTERNS:
                m = pattern.search(body)
                if not m:
                    continue

                fp = self.make_fingerprint(self.name, "Stack trace in error response", req.url)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                desc = (
                    f"A server error response from `{req.url}` contains a stack trace or verbose error message. "
                    "Stack traces reveal internal file paths, library versions, function names, and line numbers — "
                    "information that significantly aids attackers in understanding the system's architecture."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Stack trace / verbose error exposed in HTTP response",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": req.status_code, "body_excerpt": truncate(body, 400)},
                        "payload_type": "passive_analysis",
                        "payload_used": "none (passive)",
                        "injection_point": "response_body",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title="Stack trace exposed in HTTP response",
                        severity=Severity.MEDIUM, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"Stack trace in {req.method} {req.url} 500 response:\n{truncate(body, 200)}",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Verbose error details and stack traces are returned in HTTP responses.\n\n"
                        "**How to fix:** Return generic error messages in production: `{'error': 'Internal server error'}`. "
                        "Log full stack traces server-side only. "
                        "For Express: use a global error handler that omits stack traces in non-dev environments. "
                        "For Next.js: disable `productionBrowserSourceMaps`.\n\n"
                        "**Verify the fix:** Re-run info_disclosure scanner."
                    ),
                    category=self.category, page=req.url,
                ))
                break  # one finding per request

    # ------------------------------------------------------------------ #
    # Group 4 — Hardcoded secrets in JavaScript files                    #
    # ------------------------------------------------------------------ #

    def _check_js_secrets(
        self, network: Any, target: str, stack: str, findings: list[Finding]
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            ct = ""
            if req.response_headers:
                ct = req.response_headers.get("Content-Type", req.response_headers.get("content-type", ""))
            if not any(js_ct in ct for js_ct in _JS_CONTENT_TYPES) and not req.url.endswith(".js"):
                continue

            body = req.response_body or ""
            if not body:
                continue

            for pattern, label, severity in _SECRET_PATTERNS:
                m = pattern.search(body)
                if not m:
                    continue

                fp = self.make_fingerprint(self.name, f"Secret in JS: {label}", req.url)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                matched_text = m.group(0)
                desc = (
                    f"A {label} was found in the JavaScript file at `{req.url}`. "
                    "Any user who visits your application can read this file and extract the secret. "
                    "This can lead to immediate compromise of the associated service."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=severity,
                    title=f"Hardcoded secret in JavaScript: {label}",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {
                            "status": getattr(req, "status_code", "?"),
                            "body_excerpt": truncate(matched_text, 80) + "...",
                        },
                        "payload_type": "passive_analysis",
                        "payload_used": "none (passive — pattern match)",
                        "injection_point": "response_body:js_file",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Hardcoded secret: {label}",
                        severity=severity, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"{label} found in {req.url}:\n{truncate(matched_text, 80)}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** A {label} is hardcoded in a client-side JavaScript file.\n\n"
                        "**How to fix:** Move all secrets to server-side environment variables. "
                        "Never bundle API keys in frontend code. "
                        "If exposed: rotate the key immediately in the provider dashboard. "
                        "Use a secrets manager (Vault, AWS Secrets Manager) for production credentials.\n\n"
                        "**Verify the fix:** Re-run info_disclosure scanner — no secrets in JS files."
                    ),
                    category=self.category, page=req.url,
                ))
                break  # one finding per JS file
