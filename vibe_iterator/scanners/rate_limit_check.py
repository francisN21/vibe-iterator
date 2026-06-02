"""Rate limit check scanner — detects missing rate limiting, lockout DoS, and missing Retry-After."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity

_PROBE_BODY = json.dumps({
    "email": "probe@vibe-iterator-test.invalid",
    "password": "VI_PROBE_xXx",
}).encode()
_REQUEST_TIMEOUT = 3
_BURST_COUNT = 10
_DEEP_SCAN_CAP = 20
_LOCKOUT_BODY_SIGNALS = ("locked", "suspended", "too many attempts", "too many requests")

_AUTH_ENDPOINTS: list[tuple[list[str], str]] = [
    (["/api/auth/login", "/api/login", "/auth/login"], "Login"),
    (["/api/auth/forgot-password", "/api/auth/reset-password", "/api/reset-password"], "Password Reset"),
    (["/api/auth/signup", "/api/auth/register", "/api/register"], "Signup"),
    (["/api/auth/otp", "/api/auth/magic-link"], "OTP / Magic Link"),
    (["/api/auth/verify", "/api/auth/resend"], "Email Verification"),
    (["/auth/v1/token?grant_type=password"], "Supabase Auth"),
]


class Scanner(BaseScanner):
    """Two-pass probe for rate limiting across all auth-sensitive endpoints."""

    name = "rate_limit_check"
    category = "Rate Limiting"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        target = config.target.rstrip("/")
        backend_base = (getattr(config, "backend_url", None) or target).rstrip("/")
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        # Origin is always the frontend URL — what the browser sends when hitting the backend
        origin = target

        probed_paths: set[str] = set()
        for path_variants, label in _AUTH_ENDPOINTS:
            path = _find_active_path(backend_base, path_variants, origin)
            if path is None or path in probed_paths:
                continue
            probed_paths.add(path)
            _probe_endpoint(backend_base, path, label, stack, findings, self, origin)

        if getattr(config, "rate_limit_deep_scan", False):
            network = listeners.get("network")
            if network:
                extra: list[str] = []
                seen_paths: set[str] = set(probed_paths)
                for req in network.get_requests():
                    # Network requests come from the browser hitting the frontend
                    if req.method != "POST" or not req.url.startswith(target):
                        continue
                    path = req.url[len(target):]
                    if path and path not in seen_paths:
                        seen_paths.add(path)
                        extra.append(path)
                    if len(extra) >= _DEEP_SCAN_CAP:
                        break
                for path in extra:
                    label = path.rstrip("/").split("/")[-1].replace("-", " ").title()
                    _probe_endpoint(backend_base, path, label, stack, findings, self, origin)

        return findings


def _find_active_path(base: str, variants: list[str], origin: str) -> str | None:
    """Return first path variant that does not 404/405/501, or None."""
    for path in variants:
        code = _post_once(base + path, origin)
        if code not in (404, 405, 501, None):
            return path
    return None


def _probe_endpoint(
    base: str,
    path: str,
    label: str,
    stack: str,
    findings: list[Finding],
    scanner: BaseScanner,
    origin: str,
) -> None:
    """Phase 1 burst + Phase 2 Retry-After check for one endpoint."""
    url = base + path
    codes: list[int] = []
    found_429 = False
    retry_after: str | None = None
    lockout_at: int | None = None
    lockout_code_before: int | None = None
    lockout_code_after: int | None = None
    lockout_body: str = ""

    for i in range(_BURST_COUNT):
        code, headers, body = _post_full(url, origin)
        if code is None:
            # Connection error or timeout — silently skip; not enough signal to classify
            break

        if code == 429:
            found_429 = True
            retry_after = headers.get("retry-after") or headers.get("Retry-After")
            break

        body_lower = body.lower()
        if any(sig in body_lower for sig in _LOCKOUT_BODY_SIGNALS):
            lockout_at = i + 1
            lockout_code_before = codes[-1] if codes else None
            lockout_code_after = code
            lockout_body = body[:200]
            break

        if codes and code != codes[0]:
            lockout_at = i + 1
            lockout_code_before = codes[0]
            lockout_code_after = code
            lockout_body = body[:200]
            break

        codes.append(code)

    if found_429:
        if not retry_after:
            findings.append(_finding_c(scanner, url, path, label, stack))
        return

    if lockout_at is not None:
        findings.append(_finding_b(
            scanner, url, path, label, stack,
            lockout_at, lockout_code_before or 0, lockout_code_after or 0, lockout_body,
        ))
        return

    if len(codes) >= _BURST_COUNT and not all(c == 403 for c in codes):
        findings.append(_finding_a(scanner, url, path, label, stack, codes))


def _post_once(url: str, origin: str) -> int | None:
    try:
        req = urllib.request.Request(
            url, data=_PROBE_BODY, method="POST",
            headers={"Content-Type": "application/json", "Origin": origin},
        )
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _post_full(url: str, origin: str) -> tuple[int | None, dict, str]:
    try:
        req = urllib.request.Request(
            url, data=_PROBE_BODY, method="POST",
            headers={"Content-Type": "application/json", "Origin": origin},
        )
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, headers, body
    except Exception:
        return None, {}, ""


def _finding_a(
    scanner: BaseScanner, url: str, path: str,
    label: str, stack: str, codes: list[int],
) -> Finding:
    desc = (
        f"{label} endpoint has no rate limiting — "
        f"{len(codes)} consecutive attempts all returned {codes[0]} with no 429 response. "
        "An attacker can make unlimited attempts without being slowed down, "
        "enabling automated credential attacks."
    )
    return scanner.new_finding(
        scanner=scanner.name,
        severity=Severity.MEDIUM,
        title=f"No rate limiting on {label} endpoint ({path})",
        description=desc,
        evidence={
            "check_group": "Rate Limiting",
            "check_name": "Burst probe",
            "evidence_type": "request_replay",
            "endpoint": url,
            "label": label,
            "attempts_sent": len(codes),
            "response_codes_seen": codes,
            "expected_behavior": "Endpoint should return 429 by attempt 6 with a Retry-After header",
        },
        llm_prompt=scanner.build_llm_prompt(
            title=f"No rate limiting on {label} endpoint",
            severity=Severity.MEDIUM,
            scanner=scanner.name,
            page=url,
            category=scanner.category,
            description=desc,
            evidence_summary=f"{len(codes)} attempts to {url} — all returned {codes[0]}, no 429.",
            stack=stack,
        ),
        remediation=_REMEDIATION_A.format(label=label),
        category=scanner.category,
        page=url,
    )


def _finding_b(
    scanner: BaseScanner, url: str, path: str, label: str, stack: str,
    lockout_at: int, code_before: int, code_after: int, body_excerpt: str,
) -> Finding:
    desc = (
        f"{label} endpoint locks accounts after {lockout_at} failed attempts "
        f"(response changed from {code_before} to {code_after}). "
        "An attacker only needs a valid email address — no password required — to permanently "
        "lock out any user. The locked account owner must then go through manual recovery: "
        "opening an IT support ticket, waiting for a timed reset, or contacting the service. "
        "The attacker pays nothing; the victim pays with lost access. "
        "This is a denial-of-service vector disguised as a security feature."
    )
    return scanner.new_finding(
        scanner=scanner.name,
        severity=Severity.LOW,
        title=f"Account lockout on {label} endpoint — DoS risk ({path})",
        description=desc,
        evidence={
            "check_group": "Rate Limiting",
            "check_name": "Lockout detection",
            "evidence_type": "request_replay",
            "endpoint": url,
            "label": label,
            "lockout_detected_at_attempt": lockout_at,
            "code_before": code_before,
            "code_after": code_after,
            "body_excerpt": body_excerpt,
            "expected_behavior": "Endpoint should return 429 + Retry-After, not lock the account",
        },
        llm_prompt=scanner.build_llm_prompt(
            title=f"Account lockout on {label} endpoint — DoS risk",
            severity=Severity.LOW,
            scanner=scanner.name,
            page=url,
            category=scanner.category,
            description=desc,
            evidence_summary=(
                f"Attempt {lockout_at} on {url}: status changed {code_before} → {code_after} "
                f"(lockout triggered). "
                "This is a DoS vector: an attacker only needs a target's email address to permanently "
                "lock their account — no password required. The victim must open an IT ticket or wait "
                "for a manual reset to regain access. "
                "Fix: replace lockout with 429 + Retry-After progressive throttling keyed on "
                "(IP + email). Never lock the account — throttle the attacker instead."
            ),
            stack=stack,
        ),
        remediation=_REMEDIATION_B.format(label=label),
        category=scanner.category,
        page=url,
    )


def _finding_c(
    scanner: BaseScanner, url: str, path: str, label: str, stack: str,
) -> Finding:
    desc = (
        f"{label} endpoint returns 429 but does not include a Retry-After header. "
        "HTTP clients, mobile apps, and retry libraries use this header to know when to retry. "
        "Without it they either retry immediately (defeating the rate limit) or back off arbitrarily."
    )
    return scanner.new_finding(
        scanner=scanner.name,
        severity=Severity.INFO,
        title=f"429 response missing Retry-After header on {label} endpoint ({path})",
        description=desc,
        evidence={
            "check_group": "Rate Limiting",
            "check_name": "Retry-After header",
            "evidence_type": "response_analysis",
            "endpoint": url,
            "label": label,
            "response_code": 429,
            "expected_behavior": "429 response must include Retry-After: <seconds>",
        },
        llm_prompt=scanner.build_llm_prompt(
            title=f"429 response missing Retry-After header on {label} endpoint",
            severity=Severity.INFO,
            scanner=scanner.name,
            page=url,
            category=scanner.category,
            description=desc,
            evidence_summary=f"429 received on {url} but no Retry-After header in response.",
            stack=stack,
        ),
        remediation=_REMEDIATION_C,
        category=scanner.category,
        page=url,
    )


_REMEDIATION_A = (
    "**What to fix:** {label} endpoint has no rate limiting — an attacker can "
    "make unlimited attempts without being slowed down.\n\n"
    "**How to fix (Next.js + Upstash):**\n"
    "Install: npm install @upstash/ratelimit @upstash/redis\n\n"
    "```js\n"
    'import {{ Ratelimit }} from "@upstash/ratelimit";\n'
    'import {{ Redis }} from "@upstash/redis";\n\n'
    "const ratelimit = new Ratelimit({{\n"
    '  redis: Redis.fromEnv(),\n'
    '  limiter: Ratelimit.slidingWindow(10, "60 s"),\n'
    "  analytics: true,\n"
    "}});\n\n"
    "export async function POST(req) {{\n"
    '  const ip = req.headers.get("x-forwarded-for") ?? "anonymous";\n'
    "  const email = (await req.json()).email ?? \"\";\n"
    "  const key = `rl:login:${{ip}}:${{email}}`;\n"
    "  const {{ success, reset }} = await ratelimit.limit(key);\n"
    "  if (!success) {{\n"
    "    return Response.json(\n"
    '      {{ error: "Too many attempts. Try again later." }},\n'
    "      {{ status: 429, headers: {{ \"Retry-After\": String(Math.ceil((reset - Date.now()) / 1000)) }} }}\n"
    "    );\n"
    "  }}\n"
    "  // ... rest of handler\n"
    "}}\n"
    "```\n\n"
    "**Alternative (rate-limiter-flexible, no external service):**\n"
    "Install: npm install rate-limiter-flexible\n\n"
    "```js\n"
    'import {{ RateLimiterMemory }} from "rate-limiter-flexible";\n'
    "const limiter = new RateLimiterMemory({{ points: 10, duration: 60 }});\n\n"
    "const key = `${{ip}}_${{email}}`;\n"
    "try {{ await limiter.consume(key); }}\n"
    "catch {{ return Response.json({{ error: \"Too many attempts.\" }},\n"
    '        {{ status: 429, headers: {{ "Retry-After": "60" }} }}); }}\n'
    "```\n\n"
    "**For Supabase:** Enable Auth → Rate Limits in your Supabase project "
    "dashboard. Set \"Email logins per hour\" to a value ≤ 10.\n\n"
    "**Verify the fix:** Re-run rate_limit_check — the 6th attempt must return 429."
)

_REMEDIATION_B = (
    "**What to fix:** {label} endpoint locks accounts after failed attempts. "
    "A locked account requires manual recovery — the victim must open an IT support ticket "
    "or wait for a timed reset. An attacker only needs a valid email address to trigger this; "
    "no password required. They lock you out; you pay the recovery cost.\n\n"
    "**How to fix:** Remove the lockout. Replace it with 429 + Retry-After progressive throttling "
    "keyed on (IP + email) together:\n\n"
    "```js\n"
    "// Next.js route handler (app router)\n"
    "import {{ RateLimiterMemory }} from 'rate-limiter-flexible';\n\n"
    "const limiter = new RateLimiterMemory({{\n"
    "  points: 5,      // allow 5 attempts\n"
    "  duration: 60,   // per 60-second window\n"
    "}});\n\n"
    "export async function POST(req) {{\n"
    "  const {{ email }} = await req.json();\n"
    '  const ip = req.headers.get("x-forwarded-for") ?? "anon";\n'
    "  const key = `${{ip}}:${{email}}`;\n\n"
    "  try {{\n"
    "    await limiter.consume(key);\n"
    "  }} catch (e) {{\n"
    "    const retryAfter = Math.ceil(e.msBeforeNextReset / 1000);\n"
    "    return Response.json(\n"
    '      {{ error: "Too many attempts. Try again later." }},\n'
    '      {{ status: 429, headers: {{ "Retry-After": String(retryAfter) }} }}\n'
    "    );\n"
    "  }}\n\n"
    "  // ... authenticate normally, return 401 on wrong password\n"
    "  // NEVER return 403/423/locked — always 401 until the rate limit kicks in\n"
    "}}\n"
    "```\n\n"
    "**Progressive throttling tiers (optional, for high-value endpoints):**\n"
    "- Attempts 1–5:   allow (normal 401)\n"
    "- Attempts 6–20:  return 429, Retry-After: 60\n"
    "- Attempts 21–50: return 429, Retry-After: 300\n"
    "- Attempts 51+:   return 429, Retry-After: 3600\n\n"
    "**Key rule:** Key on (IP + target email) together. Not email alone — that lets the attacker "
    "lock out real users. Not IP alone — trivially bypassed with proxies.\n\n"
    "**Verify the fix:** Re-run rate_limit_check — the lockout finding must be gone "
    "and a 429 must appear by attempt 6."
)

_REMEDIATION_C = (
    "**What to fix:** The 429 response does not include a Retry-After header. "
    "HTTP clients, mobile apps, and retry libraries use this header to know "
    "when to try again. Without it they either hammer immediately (defeating "
    "the rate limit) or back off arbitrarily.\n\n"
    "**How to fix:** Add the header to every 429 response:\n"
    "  Retry-After: 60   (seconds until the window resets)\n\n"
    "In Next.js:\n"
    '  return Response.json({ error: "Too many attempts." },\n'
    '    { status: 429, headers: { "Retry-After": "60" } });\n\n'
    "**Verify the fix:** Re-run rate_limit_check — INFO finding must be gone."
)
