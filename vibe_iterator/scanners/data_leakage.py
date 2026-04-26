"""Data leakage scanner — tokens, JWTs, UUIDs, and PII in network/console."""

from __future__ import annotations

import re
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import find_jwts, is_service_role_key, truncate

_PII_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_SUPABASE_SERVICE_HINT = re.compile(r"service_role")
_SAFE_URL_FRAGMENTS = ["/static/", ".js", ".css", ".png", ".svg", ".ico", "/favicon"]


class Scanner(BaseScanner):
    """Scans network responses and console output for leaked sensitive data."""

    name = "data_leakage"
    category = "Data Leakage"
    stages = ["dev", "pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        console = listeners["console"]

        self._check_network(network, config, findings, stack)
        self._check_console(console, config, findings, stack)
        return findings

    # ------------------------------------------------------------------ #
    # Network checks                                                       #
    # ------------------------------------------------------------------ #

    def _check_network(self, network: Any, config: Any, findings: list[Finding], stack: str) -> None:
        for req in network.get_requests():
            if any(frag in req.url for frag in _SAFE_URL_FRAGMENTS):
                continue

            body = req.response_body or ""

            # Check 1 — Supabase service role key in response body
            if _SUPABASE_SERVICE_HINT.search(body):
                jwts = find_jwts(body)
                service_keys = [j for j in jwts if is_service_role_key(j)]
                if service_keys:
                    excerpt = truncate(service_keys[0])
                    desc = (
                        "A Supabase service_role JWT was found in a network response body. "
                        "The service_role key bypasses Row Level Security and grants full database access. "
                        "Any user who can see network traffic can steal this key and read, write, or "
                        "delete all data in your database."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.CRITICAL,
                        title="Supabase service role key exposed in network response",
                        description=desc,
                        evidence={
                            "leak_type": "supabase_service_key",
                            "leak_location": "network_response",
                            "url": req.url,
                            "leaked_value_excerpt": excerpt,
                            "context": f"Found in response body of {req.method} {req.url}",
                            "response_excerpt": truncate(body, 300),
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="Supabase service role key exposed in network response",
                            severity=Severity.CRITICAL, scanner=self.name,
                            page=req.url, category=self.category, description=desc,
                            evidence_summary=f"Service role key in {req.method} {req.url}:\n{excerpt}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** Remove the service_role key from all client-side code and API responses.\n\n"
                            "**How to fix:** The service_role key must only exist in server-side environment variables. "
                            "Use the `anon` key in your frontend Supabase client. "
                            "If the key was ever exposed, rotate it immediately in Supabase project settings → API → Regenerate keys.\n\n"
                            "**Verify the fix:** Re-run data_leakage scanner — 0 findings expected."
                        ),
                        category=self.category, page=req.url,
                    ))
                    continue

            # Check 2 — JWT in URL parameters
            if "eyJ" in req.url and "?" in req.url:
                jwts_in_url = find_jwts(req.url)
                if jwts_in_url:
                    desc = (
                        "A JWT authentication token was found in a URL query parameter. "
                        "URLs are logged in browser history, server access logs, and CDN logs. "
                        "Anyone with access to those logs can steal the token and impersonate the user."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title="JWT token exposed in URL parameter",
                        description=desc,
                        evidence={
                            "leak_type": "jwt",
                            "leak_location": "url_param",
                            "url": truncate(req.url),
                            "leaked_value_excerpt": truncate(jwts_in_url[0]),
                            "context": "JWT found in URL query string",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="JWT token exposed in URL parameter",
                            severity=Severity.HIGH, scanner=self.name,
                            page=req.url, category=self.category, description=desc,
                            evidence_summary=f"JWT in URL: {truncate(req.url, 150)}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** Never pass JWTs or session tokens in URL parameters.\n\n"
                            "**How to fix:** Pass tokens only in the `Authorization: Bearer <token>` header "
                            "or in HttpOnly cookies. Audit OAuth callbacks to ensure tokens are not appended to redirect URLs.\n\n"
                            "**Verify the fix:** Re-run data_leakage scanner — token should not appear in URLs."
                        ),
                        category=self.category, page=req.url,
                    ))

            # Check 3 — PII (bulk emails) in API responses
            if "/api/" in req.url or "supabase.co" in req.url:
                emails = _PII_EMAIL.findall(body)
                test_email = getattr(config, "test_email", "")
                foreign = [e for e in emails if e != test_email and not e.endswith(".example.com")]
                if len(foreign) > 2:
                    desc = (
                        "An API response contains multiple user email addresses beyond the authenticated user's own. "
                        "This may indicate a data over-exposure issue where the endpoint returns more records "
                        "than the logged-in user is authorised to see. "
                        "Attackers could enumerate all registered users' email addresses."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="Multiple user email addresses exposed in API response",
                        description=desc,
                        evidence={
                            "leak_type": "pii_email",
                            "leak_location": "network_response",
                            "url": req.url,
                            "leaked_value_excerpt": ", ".join(foreign[:5]),
                            "context": f"{len(foreign)} emails found in {req.method} {req.url}",
                            "response_excerpt": truncate(body, 300),
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="Multiple user email addresses exposed in API response",
                            severity=Severity.MEDIUM, scanner=self.name,
                            page=req.url, category=self.category, description=desc,
                            evidence_summary=f"{len(foreign)} emails found at {req.url}:\n{', '.join(foreign[:3])}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** The endpoint returns email addresses belonging to other users.\n\n"
                            "**How to fix:** Apply RLS policies so each user can only query their own data. "
                            "For Supabase: `CREATE POLICY \"own rows\" ON profiles FOR SELECT USING (auth.uid() = user_id);`\n\n"
                            "**Verify the fix:** Re-run rls_bypass and data_leakage scanners."
                        ),
                        category=self.category, page=req.url,
                    ))

    # ------------------------------------------------------------------ #
    # Console checks                                                       #
    # ------------------------------------------------------------------ #

    def _check_console(self, console: Any, config: Any, findings: list[Finding], stack: str) -> None:
        for entry in console.get_entries():
            text = entry.text or ""
            jwts = find_jwts(text)
            if not jwts:
                continue

            service_keys = [j for j in jwts if is_service_role_key(j)]
            severity = Severity.CRITICAL if service_keys else Severity.HIGH
            title = (
                "Supabase service role key logged to console"
                if service_keys else
                "JWT token logged to browser console"
            )
            desc = (
                "A sensitive authentication token was found in a browser console.log statement. "
                "Any user who opens DevTools can see this token and use it to authenticate as "
                "the victim or gain elevated privileges. "
                "Debug logging left in production is a common source of token exposure."
            )
            page = entry.url or config.target
            findings.append(self.new_finding(
                scanner=self.name, severity=severity,
                title=title, description=desc,
                evidence={
                    "leak_type": "supabase_service_key" if service_keys else "jwt",
                    "leak_location": "console_log",
                    "url": page,
                    "leaked_value_excerpt": truncate(jwts[0]),
                    "context": f"console.{entry.level}: {truncate(text, 150)}",
                },
                llm_prompt=self.build_llm_prompt(
                    title=title, severity=severity, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"console.{entry.level} output:\n{truncate(text, 200)}",
                    stack=stack,
                ),
                remediation=(
                    "**What to fix:** Remove console.log statements that output tokens or credentials.\n\n"
                    "**How to fix:** Search for `console.log` calls referencing `session`, `token`, "
                    "`access_token`, `key`, or `supabase`. Remove them or use a debug logger "
                    "that is disabled in production builds.\n\n"
                    "**Verify the fix:** Re-run data_leakage scanner."
                ),
                category=self.category, page=page,
            ))
