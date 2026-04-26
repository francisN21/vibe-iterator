"""Auth check scanner — comprehensive authentication and session security audit."""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import find_jwts, truncate

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")


class Scanner(BaseScanner):
    """Six-group authentication and session security audit."""

    name = "auth_check"
    category = "Authentication"
    stages = ["dev", "pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = True

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        storage = listeners["storage"]

        self._group1_token_security(session, storage, network, config, findings, stack)
        self._group2_session_management(session, config, findings, stack, network)
        self._group3_login_security(session, config, findings, stack, network)
        self._group4_password_account(session, config, findings, stack, network)
        self._group5_auth_bypass(session, config, findings, stack, network)
        self._group6_oauth(session, config, findings, stack, network)

        return findings

    # ------------------------------------------------------------------ #
    # Group 1 — Token Security                                           #
    # ------------------------------------------------------------------ #

    def _group1_token_security(
        self, session: Any, storage: Any, network: Any, config: Any,
        findings: list[Finding], stack: str
    ) -> None:
        latest = storage.get_latest()
        if not latest:
            return
        page = latest.url

        # 1a — JWT in localStorage
        for key, val in latest.local_storage.items():
            if _JWT_PATTERN.search(str(val)):
                desc = (
                    f"An authentication JWT was found stored in localStorage under key `{key}`. "
                    "localStorage is accessible to all JavaScript on the page, making the token "
                    "vulnerable to XSS theft. "
                    "Tokens should be stored in HttpOnly cookies that cannot be accessed by JS."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title="JWT stored in localStorage (XSS-accessible)",
                    description=desc,
                    evidence={
                        "check_group": "Token Security",
                        "check_name": "JWT storage location",
                        "evidence_type": "storage_inspection",
                        "observed_value": f"localStorage['{key}'] contains JWT: {truncate(str(val), 60)}...",
                        "expected_behavior": "Token should be in an HttpOnly cookie, not accessible to JavaScript",
                        "request": None, "response": None,
                    },
                    llm_prompt=self.build_llm_prompt(
                        title="JWT stored in localStorage (XSS-accessible)",
                        severity=Severity.HIGH, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"localStorage['{key}'] = JWT token\nMakes token stealable via any XSS vulnerability.",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** JWT stored in localStorage is accessible to JavaScript and therefore to XSS attacks.\n\n"
                        "**How to fix:** For Supabase, configure your client to use cookies: "
                        "`createBrowserClient(url, key, { auth: { storage: cookieStorage, storageKey: 'sb-session' } })`. "
                        "Or use `supabase-js` v2 with SSR helpers that set HttpOnly cookies automatically.\n\n"
                        "**Verify the fix:** Re-run auth_check — localStorage should contain no JWT."
                    ),
                    category=self.category, page=page,
                ))
                break  # one finding for localStorage JWT

        # 1b — JWT with `alg: none` accepted
        token = _get_session_token(session)
        if token:
            tampered = _make_alg_none_token(token)
            if tampered:
                response_code = _replay_with_token(tampered, config.target)
                if response_code not in (401, 403, None):
                    desc = (
                        "The server accepted a JWT with the algorithm set to `none`, which means the "
                        "signature is not verified. An attacker can forge arbitrary JWT claims "
                        "(e.g., change their user_id or role) without knowing the signing secret."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.CRITICAL,
                        title="JWT algorithm confusion: `alg: none` accepted by server",
                        description=desc,
                        evidence={
                            "check_group": "Token Security",
                            "check_name": "JWT signature bypass",
                            "evidence_type": "request_replay",
                            "observed_value": f"Server returned HTTP {response_code} for token with alg:none",
                            "expected_behavior": "Server must reject tokens with alg:none with 401 Unauthorized",
                            "request": {"method": "GET", "url": config.target, "headers": {"Authorization": f"Bearer {truncate(tampered, 60)}..."}, "body": None},
                            "response": {"status": response_code},
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="JWT algorithm confusion: `alg: none` accepted",
                            severity=Severity.CRITICAL, scanner=self.name,
                            page=config.target, category=self.category, description=desc,
                            evidence_summary=f"Sent JWT with alg:none — server returned HTTP {response_code} (not 401).",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** The JWT verification library does not reject the `alg: none` attack.\n\n"
                            "**How to fix:** Ensure your JWT library specifies the expected algorithm explicitly: "
                            "`jwt.verify(token, secret, { algorithms: ['HS256'] })`. "
                            "Never allow `none` in the algorithms list. For Supabase, this is handled server-side — "
                            "if you're verifying JWTs yourself, use `jsonwebtoken` with explicit algorithm config.\n\n"
                            "**Verify the fix:** Re-run auth_check — alg:none token must return 401."
                        ),
                        category=self.category, page=config.target,
                    ))

            # 1c — JWT in URL (check network traffic)
            for req in network.get_requests():
                if "eyJ" in req.url and ("token=" in req.url or "access_token=" in req.url):
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title="Session token passed in URL query string",
                        description=(
                            "An authentication token was found in a URL query parameter during the session. "
                            "URLs are stored in browser history and server logs. "
                            "Anyone with access to these logs can steal the token."
                        ),
                        evidence={
                            "check_group": "Token Security",
                            "check_name": "Token in URL",
                            "evidence_type": "request_replay",
                            "observed_value": f"Token in URL: {truncate(req.url, 100)}",
                            "expected_behavior": "Tokens must only be in Authorization header or HttpOnly cookies",
                            "request": {"method": req.method, "url": truncate(req.url), "headers": {}, "body": None},
                            "response": None,
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="Session token passed in URL query string",
                            severity=Severity.HIGH, scanner=self.name,
                            page=req.url, category=self.category,
                            description="Authentication token found in URL — exposed in browser history and server logs.",
                            evidence_summary=f"URL with token: {truncate(req.url, 150)}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** Never put tokens in URL parameters.\n\n"
                            "**How to fix:** Check your OAuth/SSO callback handlers. Tokens returned in URL fragments "
                            "(`#access_token=`) should be immediately moved to memory or cookies and the URL cleaned. "
                            "Do not redirect with tokens as query params.\n\n"
                            "**Verify the fix:** Re-run auth_check."
                        ),
                        category=self.category, page=req.url,
                    ))
                    break

    # ------------------------------------------------------------------ #
    # Group 2 — Session Management                                       #
    # ------------------------------------------------------------------ #

    def _group2_session_management(
        self, session: Any, config: Any, findings: list[Finding], stack: str, network: Any
    ) -> None:
        # 2a — Logout invalidation: replay token after logout
        token_before = _get_session_token(session)
        if not token_before:
            return

        try:
            # Trigger logout via JS
            session.evaluate("""
            (async () => {
                const client = window.supabase || window._supabase;
                if (client) await client.auth.signOut();
            })()
            """)
            time.sleep(1)

            # Try to use the old token on an authenticated endpoint
            code = _replay_with_token(token_before, config.target)
            if code not in (401, 403, None):
                desc = (
                    "After signing out, the old session token was replayed against the server and received "
                    f"a {code} response instead of 401. "
                    "This means logout does not invalidate the JWT server-side. "
                    "Anyone who steals a token (from XSS, logs, etc.) can continue using it even after the victim logs out."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title="Logout does not invalidate session token server-side",
                    description=desc,
                    evidence={
                        "check_group": "Session Management",
                        "check_name": "Logout token invalidation",
                        "evidence_type": "request_replay",
                        "observed_value": f"POST-logout token replay returned HTTP {code}",
                        "expected_behavior": "Server must return 401 for tokens issued before logout",
                        "request": {"method": "GET", "url": config.target, "headers": {"Authorization": "Bearer [old-token]"}, "body": None},
                        "response": {"status": code},
                    },
                    llm_prompt=self.build_llm_prompt(
                        title="Logout does not invalidate session token server-side",
                        severity=Severity.HIGH, scanner=self.name,
                        page=config.target, category=self.category, description=desc,
                        evidence_summary=f"Signed out, replayed old token — server returned {code} (not 401).",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Server accepts JWT tokens that were issued before logout.\n\n"
                        "**How to fix:** For Supabase, ensure `supabase.auth.signOut()` is called with `{ scope: 'global' }` "
                        "to invalidate all sessions. If you maintain a token blocklist, add the token's `jti` claim. "
                        "Short-lived tokens (15 min) with refresh token rotation reduce the window.\n\n"
                        "**Verify the fix:** Re-run auth_check — replayed token must return 401."
                    ),
                    category=self.category, page=config.target,
                ))
        except Exception:
            pass
        finally:
            # Re-authenticate for remaining checks
            try:
                from vibe_iterator.crawler.auth import login as auth_login
                auth_login(session, config, account=1)
            except Exception:
                pass

        # 2b — Session cookie flags
        from vibe_iterator.listeners.storage import StorageListener
        try:
            cookies = session.driver.get_cookies()
            for cookie in cookies:
                name = cookie.get("name", "")
                if any(kw in name.lower() for kw in ["auth", "session", "token", "sb-"]):
                    issues = []
                    if not cookie.get("httpOnly"):
                        issues.append("missing HttpOnly flag (JS-accessible)")
                    if not cookie.get("secure"):
                        issues.append("missing Secure flag (sent over HTTP)")
                    if not cookie.get("sameSite") or cookie.get("sameSite") == "None" and not cookie.get("secure"):
                        issues.append("SameSite not set or insecure")
                    if issues:
                        desc = (
                            f"The `{name}` session cookie is missing security flags: {', '.join(issues)}. "
                            "A cookie without HttpOnly can be stolen by JavaScript (XSS). "
                            "A cookie without Secure can be transmitted over unencrypted HTTP connections."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.MEDIUM,
                            title=f"Session cookie `{name}` missing security flags",
                            description=desc,
                            evidence={
                                "check_group": "Session Management",
                                "check_name": "Session cookie flags",
                                "evidence_type": "storage_inspection",
                                "observed_value": f"Cookie `{name}`: httpOnly={cookie.get('httpOnly')}, secure={cookie.get('secure')}, sameSite={cookie.get('sameSite')}",
                                "expected_behavior": "Auth cookies should have HttpOnly=true, Secure=true, SameSite=Strict or Lax",
                                "request": None, "response": None,
                            },
                            llm_prompt=self.build_llm_prompt(
                                title=f"Session cookie `{name}` missing security flags",
                                severity=Severity.MEDIUM, scanner=self.name,
                                page=config.target, category=self.category, description=desc,
                                evidence_summary=f"Cookie {name}: httpOnly={cookie.get('httpOnly')}, secure={cookie.get('secure')}, sameSite={cookie.get('sameSite')}",
                                stack=stack,
                            ),
                            remediation=(
                                f"**What to fix:** The `{name}` cookie is missing: {', '.join(issues)}.\n\n"
                                "**How to fix:** Set `HttpOnly`, `Secure`, and `SameSite=Strict` when issuing the cookie: "
                                "`Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict`. "
                                "For Next.js/Remix, configure cookie options in your auth helper.\n\n"
                                "**Verify the fix:** Re-run auth_check — cookie flags should be correct."
                            ),
                            category=self.category, page=config.target,
                        ))
                        break
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Group 3 — Login Security                                           #
    # ------------------------------------------------------------------ #

    def _group3_login_security(
        self, session: Any, config: Any, findings: list[Finding], stack: str, network: Any
    ) -> None:
        login_url = config.target.rstrip("/") + "/login"

        # 3a — Brute force protection: send 10 rapid failed login attempts
        blocked = False
        for i in range(10):
            try:
                req = urllib.request.Request(
                    config.target.rstrip("/") + "/api/auth/login",
                    data=json.dumps({"email": config.test_email, "password": "wrong_password_attempt"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 429:
                        blocked = True
                        break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    blocked = True
                    break
            except Exception:
                break

        if not blocked:
            # Also check Supabase auth endpoint
            supabase_url = (config.supabase_url or "").rstrip("/")
            if supabase_url:
                supabase_blocked = False
                for i in range(6):
                    try:
                        req = urllib.request.Request(
                            f"{supabase_url}/auth/v1/token?grant_type=password",
                            data=json.dumps({"email": config.test_email, "password": f"wrong{i}"}).encode(),
                            headers={
                                "Content-Type": "application/json",
                                "apikey": config.supabase_anon_key or "",
                            },
                            method="POST",
                        )
                        with urllib.request.urlopen(req, timeout=3) as resp:
                            pass
                    except urllib.error.HTTPError as e:
                        if e.code == 429:
                            supabase_blocked = True
                            break
                    except Exception:
                        break
                blocked = supabase_blocked

        if not blocked:
            desc = (
                "10 consecutive failed login attempts did not trigger rate limiting or account lockout. "
                "Without brute force protection, an attacker can systematically try passwords until "
                "they find the correct one — especially for accounts with weak or common passwords."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.MEDIUM,
                title="No rate limiting on login endpoint",
                description=desc,
                evidence={
                    "check_group": "Login Security",
                    "check_name": "Brute force protection",
                    "evidence_type": "request_replay",
                    "observed_value": "10 rapid failed logins — no 429 response or lockout",
                    "expected_behavior": "Login should return 429 or lock the account after ~5 failures",
                    "request": {"method": "POST", "url": login_url, "headers": {}, "body": "{\"email\": \"...\", \"password\": \"wrong\"}"},
                    "response": {"status": 401, "body_excerpt": "repeated 401 responses, no rate limit"},
                },
                llm_prompt=self.build_llm_prompt(
                    title="No rate limiting on login endpoint",
                    severity=Severity.MEDIUM, scanner=self.name,
                    page=login_url, category=self.category, description=desc,
                    evidence_summary="10 failed login attempts returned 401 each time — no 429 or lockout.",
                    stack=stack,
                ),
                remediation=(
                    "**What to fix:** The login endpoint has no brute force protection.\n\n"
                    "**How to fix:** Enable rate limiting on your auth endpoint. "
                    "For Supabase: configure Auth → Rate Limits in your Supabase project settings. "
                    "Add application-level rate limiting with a library like `express-rate-limit` or "
                    "Cloudflare WAF rules for `/api/auth/*`.\n\n"
                    "**Verify the fix:** Re-run auth_check — 6th attempt should return 429."
                ),
                category=self.category, page=login_url,
            ))

        # 3b — Username enumeration
        error_valid = _get_login_error_message(config.target, config.test_email, "definitely_wrong_password_xyz_123")
        error_invalid = _get_login_error_message(config.target, "nonexistent_99999@example.com", "wrong_password_xyz")
        if error_valid and error_invalid and error_valid != error_invalid:
            desc = (
                "The login endpoint returns different error messages for valid vs invalid email addresses. "
                f"Valid email: '{truncate(error_valid, 80)}'. "
                f"Invalid email: '{truncate(error_invalid, 80)}'. "
                "Attackers can use this to enumerate valid user accounts."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.LOW,
                title="Login endpoint leaks valid email addresses via different error messages",
                description=desc,
                evidence={
                    "check_group": "Login Security",
                    "check_name": "Username enumeration",
                    "evidence_type": "response_analysis",
                    "observed_value": f"Valid email error: '{truncate(error_valid, 80)}' | Invalid email error: '{truncate(error_invalid, 80)}'",
                    "expected_behavior": "Both valid and invalid emails should return the same generic error: 'Invalid email or password'",
                    "request": None, "response": None,
                },
                llm_prompt=self.build_llm_prompt(
                    title="Login endpoint leaks valid email addresses",
                    severity=Severity.LOW, scanner=self.name,
                    page=login_url, category=self.category, description=desc,
                    evidence_summary=f"Valid email → '{truncate(error_valid, 80)}'\nInvalid email → '{truncate(error_invalid, 80)}'",
                    stack=stack,
                ),
                remediation=(
                    "**What to fix:** Login errors reveal whether an email address exists.\n\n"
                    "**How to fix:** Return the same generic message for both cases: "
                    "`'Invalid email or password'`. Never return 'user not found' or 'email not registered'. "
                    "For Supabase: configure the custom email error message in Auth → Email templates.\n\n"
                    "**Verify the fix:** Re-run auth_check."
                ),
                category=self.category, page=login_url,
            ))

    # ------------------------------------------------------------------ #
    # Group 4 — Password & Account Security                              #
    # ------------------------------------------------------------------ #

    def _group4_password_account(
        self, session: Any, config: Any, findings: list[Finding], stack: str, network: Any
    ) -> None:
        # Check if any captured response includes password hashes or plaintext
        for req in network.get_requests():
            body = req.response_body or ""
            if re.search(r'"password"\s*:\s*"[^"]{6,}"', body, re.I):
                desc = (
                    "A network response contains a `password` field. "
                    "Even if hashed, returning password data to the client is unnecessary and dangerous. "
                    "If the password is in plaintext, this is a critical vulnerability."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title="Password field returned in API response",
                    description=desc,
                    evidence={
                        "check_group": "Password & Account Security",
                        "check_name": "Password in response",
                        "evidence_type": "response_analysis",
                        "observed_value": f"'password' field in response body of {req.method} {req.url}",
                        "expected_behavior": "Password fields must never appear in API responses",
                        "request": {"method": req.method, "url": req.url, "headers": {}, "body": None},
                        "response": {"status": req.status_code, "body_excerpt": truncate(body, 300)},
                    },
                    llm_prompt=self.build_llm_prompt(
                        title="Password field returned in API response",
                        severity=Severity.HIGH, scanner=self.name,
                        page=req.url, category=self.category, description=desc,
                        evidence_summary=f"'password' key found in {req.method} {req.url} response.",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Remove password fields from all API responses.\n\n"
                        "**How to fix:** In your API serializer or RLS select policies, exclude the password column. "
                        "For Supabase: `CREATE POLICY ... USING (...) WITH CHECK (...)` — and in your select: "
                        "`supabase.from('users').select('id, email, name')` (omit password). "
                        "Never select `*` on tables that contain password fields.\n\n"
                        "**Verify the fix:** Re-run auth_check."
                    ),
                    category=self.category, page=req.url,
                ))
                break

    # ------------------------------------------------------------------ #
    # Group 5 — Auth Bypass Vectors                                      #
    # ------------------------------------------------------------------ #

    def _group5_auth_bypass(
        self, session: Any, config: Any, findings: list[Finding], stack: str, network: Any
    ) -> None:
        # 5a — Unprotected routes: navigate without auth
        protected_pages = [p for p in config.pages if p not in ("/", "/login", "/signup", "/register")]

        for path in protected_pages[:3]:
            url = config.target.rstrip("/") + path
            try:
                # Clear session
                session.evaluate("(function(){ localStorage.clear(); sessionStorage.clear(); })()")
                try:
                    session.driver.delete_all_cookies()
                except Exception:
                    pass

                session.navigate(url)
                time.sleep(0.8)

                current = session.current_url()
                page_source = session.driver.page_source.lower()
                login_keywords = ["login", "sign in", "authenticate", "unauthorized", "401", "403"]

                if not any(kw in current.lower() for kw in ["login", "signin", "auth"]) and \
                        not any(kw in page_source for kw in login_keywords):
                    desc = (
                        f"The page at `{path}` loaded successfully without authentication. "
                        "No redirect to login or 401/403 response was detected. "
                        "If this page displays user data, it may be accessible to unauthenticated visitors."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title=f"Protected route `{path}` accessible without authentication",
                        description=desc,
                        evidence={
                            "check_group": "Auth Bypass Vectors",
                            "check_name": "Unprotected route",
                            "evidence_type": "response_analysis",
                            "observed_value": f"Navigated to {url} without auth — no redirect to login",
                            "expected_behavior": "Unauthenticated access should redirect to /login or return 401",
                            "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                            "response": {"status": 200, "body_excerpt": "Page loaded without auth redirect"},
                        },
                        llm_prompt=self.build_llm_prompt(
                            title=f"Protected route `{path}` accessible without authentication",
                            severity=Severity.HIGH, scanner=self.name,
                            page=url, category=self.category, description=desc,
                            evidence_summary=f"Cleared all auth tokens and navigated to {url} — page loaded without redirect.",
                            stack=stack,
                        ),
                        remediation=(
                            f"**What to fix:** Route `{path}` does not require authentication.\n\n"
                            "**How to fix:** Add auth middleware to all protected routes. "
                            "For Next.js: use `getServerSideProps` with `supabase.auth.getSession()` and redirect if null. "
                            "For Remix: use a `loader` that checks the session. "
                            "For Supabase SSR: use `@supabase/auth-helpers-nextjs` `createServerComponentClient`.\n\n"
                            "**Verify the fix:** Re-run auth_check — unauthenticated access must redirect to login."
                        ),
                        category=self.category, page=url,
                    ))
            except Exception:
                pass
            finally:
                # Re-authenticate
                try:
                    from vibe_iterator.crawler.auth import login as auth_login
                    auth_login(session, config, account=1)
                except Exception:
                    pass

        # 5b — API calls without auth header
        api_calls = [r for r in network.get_requests() if "/api/" in r.url and r.method in ("GET", "POST")]
        for req in api_calls[:3]:
            if not req.response_body or req.status_code in (401, 403):
                continue
            code = _replay_without_auth(req.url, req.method, req.post_data)
            if code not in (401, 403, None):
                desc = (
                    f"The API endpoint `{req.method} {req.url}` returned HTTP {code} when called "
                    "without an Authorization header. "
                    "This endpoint may be accessible to unauthenticated users, "
                    "potentially exposing sensitive data or functionality."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title=f"API endpoint accessible without authentication: {req.method} {truncate(req.url, 60)}",
                    description=desc,
                    evidence={
                        "check_group": "Auth Bypass Vectors",
                        "check_name": "API endpoint auth",
                        "evidence_type": "request_replay",
                        "observed_value": f"{req.method} {req.url} returned {code} without auth header",
                        "expected_behavior": "Must return 401 Unauthorized when no valid auth header is present",
                        "request": {"method": req.method, "url": req.url, "headers": {}, "body": req.post_data},
                        "response": {"status": code},
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"API endpoint accessible without authentication",
                        severity=Severity.HIGH, scanner=self.name,
                        page=req.url, category=self.category, description=desc,
                        evidence_summary=f"{req.method} {req.url}\nNo Authorization header → HTTP {code} (not 401).",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** This API endpoint does not require authentication.\n\n"
                        "**How to fix:** Add auth verification to this endpoint. "
                        "For Supabase: check `supabase.auth.getUser(token)` server-side. "
                        "For Next.js API routes: use `createRouteHandlerClient` and check the session. "
                        "Return 401 if no valid session is present.\n\n"
                        "**Verify the fix:** Re-run auth_check."
                    ),
                    category=self.category, page=req.url,
                ))
                break

    # ------------------------------------------------------------------ #
    # Group 6 — OAuth / Third-Party Auth                                #
    # ------------------------------------------------------------------ #

    def _group6_oauth(
        self, session: Any, config: Any, findings: list[Finding], stack: str, network: Any
    ) -> None:
        # Detect OAuth flows from network traffic
        for req in network.get_requests():
            if "oauth" in req.url.lower() or "callback" in req.url.lower():
                # Check for state parameter in OAuth requests
                if "state=" not in req.url:
                    desc = (
                        "An OAuth authorization request was captured without a `state` parameter. "
                        "The `state` parameter is required to prevent CSRF attacks against the OAuth flow. "
                        "Without it, an attacker can trick a user into completing an OAuth flow that logs "
                        "them into the attacker's account."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="OAuth flow missing CSRF state parameter",
                        description=desc,
                        evidence={
                            "check_group": "OAuth / Third-Party Auth",
                            "check_name": "OAuth state parameter",
                            "evidence_type": "request_replay",
                            "observed_value": f"OAuth URL without state: {truncate(req.url, 120)}",
                            "expected_behavior": "OAuth requests must include a random, unguessable `state` parameter",
                            "request": {"method": req.method, "url": truncate(req.url), "headers": {}, "body": None},
                            "response": None,
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="OAuth flow missing CSRF state parameter",
                            severity=Severity.MEDIUM, scanner=self.name,
                            page=req.url, category=self.category, description=desc,
                            evidence_summary=f"OAuth URL without state param: {truncate(req.url, 150)}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** OAuth authorization URL is missing the `state` parameter.\n\n"
                            "**How to fix:** Generate a cryptographically random `state` value, store it in the session, "
                            "and include it in the OAuth redirect URL. Verify it matches when the callback returns. "
                            "For Supabase OAuth: use `supabase.auth.signInWithOAuth({ provider: 'github', options: { scopes: '...' } })` "
                            "which handles state automatically.\n\n"
                            "**Verify the fix:** Re-run auth_check."
                        ),
                        category=self.category, page=req.url,
                    ))
                    break


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _get_session_token(session: Any) -> str | None:
    """Extract JWT from the current browser session."""
    try:
        from vibe_iterator.utils.supabase_helpers import extract_session_token
        return session.evaluate(extract_session_token())
    except Exception:
        return None


def _make_alg_none_token(token: str) -> str | None:
    """Create a JWT variant with alg:none and no signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def _replay_with_token(token: str, target: str) -> int | None:
    """Replay a GET request to the target with the given Bearer token."""
    try:
        req = urllib.request.Request(
            target, headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _replay_without_auth(url: str, method: str, body: str | None) -> int | None:
    """Replay an API request without Authorization header."""
    try:
        data = body.encode() if body else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _get_login_error_message(target: str, email: str, password: str) -> str | None:
    """Attempt login and return the error message text."""
    try:
        for path in ["/api/auth/login", "/api/login", "/auth/login"]:
            url = target.rstrip("/") + path
            data = json.dumps({"email": email, "password": password}).encode()
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=4) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    return _extract_error_text(body)
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                msg = _extract_error_text(body)
                if msg:
                    return msg
    except Exception:
        pass
    return None


def _extract_error_text(body: str) -> str | None:
    """Extract a human-readable error message from a JSON response body."""
    try:
        data = json.loads(body)
        for key in ("error", "message", "msg", "detail", "error_description"):
            if key in data and isinstance(data[key], str):
                return data[key]
    except Exception:
        pass
    return None
