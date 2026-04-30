"""XSS scanner — CSP headers, DOM sinks, reflected markers, and security headers."""

from __future__ import annotations

import re
import ssl
import urllib.request
import urllib.parse
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity

# Marker injected into URL params to detect reflection in response body
_REFLECT_MARKER = "vibi7x3reflect"
_REFLECT_PAYLOADS = [
    f"<{_REFLECT_MARKER}>",        # raw HTML tag reflected
    f"\"{_REFLECT_MARKER}\"",      # attribute injection
    f"javascript:{_REFLECT_MARKER}",  # JS proto
]
_MAX_REFLECT_ENDPOINTS = 8

# Patterns for dangerous DOM sinks in inline scripts
_DOM_SINK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("innerHTML assignment", re.compile(r'\.innerHTML\s*[+]?=')),
    ("document.write usage", re.compile(r'document\.write\s*\(')),
    ("eval() usage", re.compile(r'\beval\s*\(')),
    ("setTimeout with string", re.compile(r'setTimeout\s*\(\s*["\']')),
    ("setInterval with string", re.compile(r'setInterval\s*\(\s*["\']')),
    ("location.hash in sink", re.compile(r'location\.hash')),
    ("document.referrer in sink", re.compile(r'document\.referrer')),
]

# Security headers that should be present
_REQUIRED_HEADERS = {
    "x-content-type-options": ("X-Content-Type-Options missing", "nosniff"),
    "x-frame-options": ("X-Frame-Options missing", None),
}

# Weak CSP patterns
_WEAK_CSP_PATTERNS = [
    ("unsafe-inline in script-src", re.compile(r"script-src[^;]*'unsafe-inline'")),
    ("unsafe-eval in script-src", re.compile(r"script-src[^;]*'unsafe-eval'")),
    ("wildcard in default-src", re.compile(r"default-src\s+\*")),
    ("wildcard in script-src", re.compile(r"script-src\s+\*")),
]

# JS evaluation snippet to detect DOM sinks on the live page
_DOM_SINK_JS = """
(function() {
  try {
    var scripts = Array.from(document.querySelectorAll('script'))
      .map(function(s) { return s.textContent || ''; })
      .join('\\n');
    var inlineHandlers = document.body ? document.body.innerHTML : '';
    var text = scripts + inlineHandlers;
    var found = [];
    var patterns = [
      ['innerHTML assignment', /\\.innerHTML\\s*[+]?=/],
      ['document.write', /document\\.write\\s*\\(/],
      ['eval usage', /\\beval\\s*\\(/],
      ['setTimeout string', /setTimeout\\s*\\(\\s*["\\x27]/],
      ['location.hash sink', /location\\.hash/],
      ['document.referrer sink', /document\\.referrer/],
    ];
    patterns.forEach(function(p) {
      if (p[1].test(text)) found.push(p[0]);
    });
    return JSON.stringify(found);
  } catch(e) {
    return '[]';
  }
})()
"""


class Scanner(BaseScanner):
    """Tests for XSS vulnerabilities via passive header analysis and DOM inspection."""

    name = "xss_check"
    category = "Injection"
    stages = ["pre-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target

        self._check_response_headers(network, target, stack, findings)
        self._check_csp_headers(network, target, stack, findings)
        self._check_dom_sinks(session, config, stack, findings)
        self._check_reflected_xss(network, target, stack, findings)
        return findings

    # ------------------------------------------------------------------ #
    # Security headers (passive)                                          #
    # ------------------------------------------------------------------ #

    def _check_response_headers(
        self, network: Any, target: str, stack: str, findings: list[Finding],
    ) -> None:
        seen_fps: set[str] = set()

        for req in network.get_requests():
            if req.response_headers is None:
                continue
            if not req.url.startswith(target):
                continue
            lowered = {k.lower(): v for k, v in req.response_headers.items()}

            for header_key, (issue_label, expected_value) in _REQUIRED_HEADERS.items():
                actual = lowered.get(header_key)
                if actual is not None:
                    continue

                fp = self.make_fingerprint(self.name, issue_label, target)
                if fp in seen_fps:
                    continue
                seen_fps.add(fp)

                desc = (
                    f"The `{header_key}` security header is missing from responses. "
                    "This header helps prevent MIME-type sniffing and clickjacking attacks. "
                    "Modern browsers rely on these headers as an additional defence layer against XSS."
                )
                hint = f"Expected: `{header_key}: {expected_value}`" if expected_value else f"Expected: `{header_key}` header to be present"
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.LOW,
                    title=f"Missing security header: {header_key}",
                    description=desc,
                    evidence={
                        "request": {"method": req.method, "url": req.url},
                        "response": {"status": getattr(req, "status_code", "?"), "headers": dict(req.response_headers)},
                        "payload_type": "missing_header",
                        "injection_point": f"response_header:{header_key}",
                        "payload_used": hint,
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Missing security header: {header_key}",
                        severity=Severity.LOW, scanner=self.name, page=req.url,
                        category=self.category, description=desc,
                        evidence_summary=f"Header `{header_key}` absent on: {req.url}\n{hint}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** Add the `{header_key}` header to all responses.\n\n"
                        f"**How to fix:** In your server middleware or Next.js `next.config.js` headers, "
                        f"add: `{header_key}: {expected_value or 'DENY'}`. "
                        "For Express: `res.setHeader('X-Content-Type-Options', 'nosniff')`.\n\n"
                        "**Verify the fix:** Re-run xss_check and check browser DevTools → Network → Response Headers."
                    ),
                    category=self.category, page=req.url,
                ))

    # ------------------------------------------------------------------ #
    # CSP evaluation (passive)                                            #
    # ------------------------------------------------------------------ #

    def _check_csp_headers(
        self, network: Any, target: str, stack: str, findings: list[Finding],
    ) -> None:
        seen_fps: set[str] = set()
        csp_seen = False

        for req in network.get_requests():
            if req.response_headers is None:
                continue
            if not req.url.startswith(target):
                continue
            lowered = {k.lower(): v for k, v in req.response_headers.items()}
            csp = lowered.get("content-security-policy", "")

            if csp:
                csp_seen = True
                for pattern_label, pattern in _WEAK_CSP_PATTERNS:
                    if pattern.search(csp):
                        fp = self.make_fingerprint(self.name, f"Weak CSP: {pattern_label}", target)
                        if fp in seen_fps:
                            continue
                        seen_fps.add(fp)
                        desc = (
                            f"The Content Security Policy contains `{pattern_label}`. "
                            "This weakens CSP protection against XSS because the browser will "
                            "execute scripts from untrusted sources or allow inline scripts. "
                            "An attacker who can inject HTML can bypass CSP and execute JavaScript."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.MEDIUM,
                            title=f"Weak Content Security Policy: {pattern_label}",
                            description=desc,
                            evidence={
                                "request": {"method": req.method, "url": req.url},
                                "response": {"status": getattr(req, "status_code", "?"), "headers": {"content-security-policy": csp[:300]}},
                                "payload_type": "weak_csp",
                                "payload_used": pattern_label,
                                "injection_point": "response_header:content-security-policy",
                            },
                            llm_prompt=self.build_llm_prompt(
                                title=f"Weak CSP: {pattern_label}",
                                severity=Severity.MEDIUM, scanner=self.name, page=req.url,
                                category=self.category, description=desc,
                                evidence_summary=f"CSP: {csp[:200]}",
                                stack=stack,
                            ),
                            remediation=(
                                "**What to fix:** The CSP policy is too permissive.\n\n"
                                "**How to fix:** Remove `'unsafe-inline'` and `'unsafe-eval'` from "
                                "`script-src`. Use nonces (`'nonce-{random}'`) or hashes instead. "
                                "Avoid wildcard sources (`*`) in any directive.\n\n"
                                "**Verify the fix:** Re-run xss_check. Test with `report-uri` to catch violations."
                            ),
                            category=self.category, page=req.url,
                        ))

        if not csp_seen:
            fp = self.make_fingerprint(self.name, "Content Security Policy not set", target)
            if fp not in seen_fps:
                seen_fps.add(fp)
                desc = (
                    "No Content Security Policy header was found in any response. "
                    "Without a CSP, the browser has no directives to restrict which scripts "
                    "can execute. This significantly increases the impact of any XSS vulnerability."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Content Security Policy header not set",
                    description=desc,
                    evidence={
                        "payload_type": "missing_csp",
                        "payload_used": "No Content-Security-Policy header found in any response",
                        "injection_point": "response_header:content-security-policy",
                    },
                    llm_prompt=self.build_llm_prompt(
                        title="Content Security Policy header not set",
                        severity=Severity.MEDIUM, scanner=self.name, page=target,
                        category=self.category, description=desc,
                        evidence_summary="No Content-Security-Policy header observed in captured responses.",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Add a Content Security Policy to all HTML responses.\n\n"
                        "**How to fix:** Start with a strict policy: "
                        "`Content-Security-Policy: default-src 'self'; script-src 'self'; "
                        "object-src 'none'; base-uri 'self'`. "
                        "For Next.js, add it in `next.config.js` headers or middleware.\n\n"
                        "**Verify the fix:** Use https://csp-evaluator.withgoogle.com to test your policy."
                    ),
                    category=self.category, page=target,
                ))

    # ------------------------------------------------------------------ #
    # DOM sink detection (active via session.evaluate)                    #
    # ------------------------------------------------------------------ #

    def _check_dom_sinks(
        self, session: Any, config: Any, stack: str, findings: list[Finding],
    ) -> None:
        if session is None:
            return
        try:
            raw = session.evaluate(_DOM_SINK_JS)
            if not raw:
                return
            import json
            sinks = json.loads(raw) if isinstance(raw, str) else []
        except Exception:
            return

        if not sinks:
            return

        page = config.target
        try:
            page = session.current_url() or config.target
        except Exception:
            pass

        desc = (
            f"Dangerous DOM sink patterns were detected in the page's JavaScript: "
            f"{', '.join(sinks)}. "
            "If any of these sinks consume user-controllable input (URL params, hash, referrer), "
            "an attacker could inject executable JavaScript without a server-side vulnerability. "
            "DOM-based XSS is harder to detect with static analysis and often overlooked."
        )
        findings.append(self.new_finding(
            scanner=self.name, severity=Severity.MEDIUM,
            title=f"DOM XSS: dangerous sink patterns detected ({len(sinks)} found)",
            description=desc,
            evidence={
                "payload_type": "dom_xss",
                "payload_used": f"DOM analysis found: {', '.join(sinks)}",
                "injection_point": "dom:inline_script",
                "request": {"method": "GET", "url": page},
                "response": {"status": "200", "body_excerpt": f"Sinks found: {', '.join(sinks)}"},
            },
            llm_prompt=self.build_llm_prompt(
                title="DOM XSS: dangerous sink patterns detected",
                severity=Severity.MEDIUM, scanner=self.name, page=page,
                category=self.category, description=desc,
                evidence_summary=f"Dangerous sinks on {page}:\n- " + "\n- ".join(sinks),
                stack=stack,
            ),
            remediation=(
                "**What to fix:** Dangerous DOM sinks may be consuming untrusted input.\n\n"
                "**How to fix:** Audit every instance of `innerHTML`, `document.write`, and `eval` — "
                "ensure they never receive user-controllable data. "
                "Replace `innerHTML` with `textContent` where HTML is not needed. "
                "Use a trusted sanitizer like DOMPurify for rich content.\n\n"
                "**Verify the fix:** Re-run xss_check DOM sink check and manually test "
                "with `#<img src=x onerror=alert(1)>` in the URL hash."
            ),
            category=self.category, page=page,
        ))

    # ------------------------------------------------------------------ #
    # Reflected XSS — active URL parameter injection                      #
    # ------------------------------------------------------------------ #

    def _check_reflected_xss(
        self, network: Any, target: str, stack: str, findings: list[Finding],
    ) -> None:
        seen_fps: set[str] = set()
        tested: set[str] = set()
        ctx = ssl._create_unverified_context()

        for req in network.get_requests():
            if not req.url.startswith(target):
                continue
            parsed = urllib.parse.urlparse(req.url)
            if not parsed.query:
                continue  # only test URLs that already have query params

            endpoint_key = f"{parsed.netloc}{parsed.path}"
            if endpoint_key in tested or len(tested) >= _MAX_REFLECT_ENDPOINTS:
                break
            tested.add(endpoint_key)

            # Try each existing param with each payload
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param_name in list(params.keys())[:3]:  # limit to 3 params per endpoint
                for payload in _REFLECT_PAYLOADS:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                    try:
                        http_req = urllib.request.Request(
                            test_url,
                            headers={"User-Agent": "vibe-iterator/xss-reflect"},
                        )
                        with urllib.request.urlopen(http_req, timeout=4, context=ctx) as resp:
                            body = resp.read(8192).decode("utf-8", errors="replace")
                        ct = resp.headers.get("Content-Type", "")
                    except Exception:
                        continue

                    if "text/html" not in ct:
                        continue
                    if _REFLECT_MARKER not in body:
                        continue

                    fp = self.make_fingerprint(self.name, "Reflected XSS marker in response", test_url)
                    if fp in seen_fps:
                        continue
                    seen_fps.add(fp)

                    desc = (
                        f"A marker injected into the `{param_name}` URL parameter "
                        f"(`{urllib.parse.quote(payload)}`) was reflected verbatim in the HTML response. "
                        "If the server does not encode output, an attacker can inject arbitrary HTML/JS "
                        "that executes in the victim's browser."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title=f"Reflected XSS: parameter `{param_name}` reflects input",
                        description=desc,
                        evidence={
                            "endpoint": test_url,
                            "test_performed": "reflected_marker_injection",
                            "injection_point": f"query_param:{param_name}",
                            "payload_used": payload,
                            "request": {"method": "GET", "url": test_url},
                            "response": {
                                "status": "200",
                                "body_excerpt": _excerpt(body, _REFLECT_MARKER),
                            },
                            "expected_response": f"Marker `{_REFLECT_MARKER}` should be HTML-encoded",
                            "actual_response": f"Marker reflected verbatim: `{payload}`",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title=f"Reflected XSS: parameter `{param_name}` reflects input",
                            severity=Severity.HIGH, scanner=self.name, page=req.url,
                            category=self.category, description=desc,
                            evidence_summary=(
                                f"URL: {test_url}\n"
                                f"Param: {param_name}\n"
                                f"Payload: {payload}\n"
                                f"Marker found in HTML response body."
                            ),
                            stack=stack,
                        ),
                        remediation=(
                            f"**What to fix:** The `{param_name}` parameter is reflected in the HTML "
                            "response without HTML-encoding.\n\n"
                            "**How to fix:** HTML-encode all user-supplied values before inserting them "
                            "into HTML. In React/Next.js this happens automatically via JSX — avoid "
                            "`dangerouslySetInnerHTML`. For server-side rendering: use your template engine's "
                            "built-in auto-escaping. Never concatenate user input into HTML strings.\n\n"
                            "**Verify the fix:** Re-run xss_check — the marker should no longer appear "
                            "unencoded in the response."
                        ),
                        category=self.category, page=req.url,
                    ))


def _excerpt(body: str, marker: str, context: int = 80) -> str:
    """Return a short excerpt around the first occurrence of *marker* in *body*."""
    idx = body.find(marker)
    if idx < 0:
        return ""
    start = max(0, idx - context)
    end = min(len(body), idx + len(marker) + context)
    return body[start:end]
