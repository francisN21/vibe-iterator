# SCANNERS.md — Scanner Interface & Descriptions

## Scanner Interface Contract

Every scanner MUST follow this pattern:

```python
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import uuid

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Screenshot:
    label: str       # e.g., "Before tampering", "Payload injected", "Server response"
    data: str        # base64-encoded PNG: "data:image/png;base64,..."

@dataclass
class Finding:
    id: str                     # uuid4 — unique per scan run, do NOT use for cross-scan identity
    fingerprint: str            # sha256(scanner + title + page)[:16] — stable across scans, used for comparison
    scanner: str                # e.g., "tier_escalation"
    severity: Severity
    title: str                  # e.g., "Subscription tier accepted client-side value"
    description: str            # Plain-English explanation (2–4 sentences, no jargon)
    evidence: dict              # Category-specific structure — see Evidence Structure section
    screenshots: list[Screenshot]  # Ordered list: before/during/after. Empty list if not captured
    llm_prompt: str             # Copy-paste prompt — see LLM Prompt Template section
    remediation: str            # Structured fix block — see Remediation Guidance Template section
    category: str               # Must match a category in the scanner registry
    page: str                   # Full URL where finding was discovered
    timestamp: str              # ISO 8601
    mark_status: str            # "none" | "resolved" | "accepted_risk" | "false_positive" — default "none"
    mark_note: str | None       # Justification note for accepted_risk or false_positive

class BaseScanner:
    name: str
    category: str
    stages: list[str]           # Which stages this scanner runs in
    requires_stack: list[str]   # e.g., ["supabase"] — engine skips if stack not in list. Use ["any"] for stack-agnostic
    requires_second_account: bool  # True if scanner uses auth.login(account=2)

    def run(self, browser, listeners, config) -> list[Finding]:
        """Execute the scan. Return findings list (empty = passed)."""
        raise NotImplementedError

    def emit(self, runner, message: str, level: str = "info"):
        """Send a progress message to the dashboard terminal feed."""
        runner.on_event(ScanEvent(
            type="scanner_progress",
            timestamp=datetime.now().isoformat(),
            data={"scanner_name": self.name, "message": message, "level": level}
        ))

    @staticmethod
    def make_fingerprint(scanner: str, title: str, page: str) -> str:
        """Stable cross-scan identity. Call this when creating each Finding."""
        import hashlib
        raw = f"{scanner}::{title}::{page}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

## Scanner Rules

- Each scanner is an independent module in `vibe_iterator/scanners/`
- Scanners MUST NOT depend on each other's results
- Every Finding MUST include raw evidence (not just a description)
- Every Finding MUST include a ready-to-paste LLM prompt
- If a scanner errors, it logs the error and returns an empty list — never crashes the scan
- Scanners declare which stages they run in via the `stages` attribute
- Scanners use `self.emit()` to send progress messages to the dashboard terminal feed
- Scanners that modify client state (localStorage, cookies, navigation) **MUST restore original state in a `try/finally` block** before returning — the browser is shared across all scanners
- Scanners that need the second test account call `auth.login(account=2)` themselves and call `auth.login(account=1)` to restore primary session before returning

---

## Shared Utilities (`utils/supabase_helpers.py`)

Not a scanner — a module of helper functions used by `rls_bypass`, `tier_escalation`, and `bucket_limits`. Do not add Supabase-specific logic directly into scanners; put it here so it can be reused and tested independently.

| Function | Used By | What It Does |
|----------|---------|-------------|
| `build_table_query_snippet(table, filters, select)` | `rls_bypass` | Generates a CDP `Runtime.evaluate` script that calls `supabase.from(table).select(...)` using the page's live auth session |
| `build_rpc_snippet(fn_name, args)` | `rls_bypass`, `tier_escalation` | Generates a CDP snippet for calling a Supabase RPC function with the current session token |
| `parse_postgrest_url(url)` → `(table, filters, select, order)` | `rls_bypass`, `sql_injection` | Extracts components from a PostgREST REST URL for manipulation |
| `extract_session_token()` | `rls_bypass`, `auth_check` | CDP snippet that calls `supabase.auth.getSession()` from the page context and returns the current JWT |
| `is_postgrest_error(response_body)` → `bool` | all Supabase scanners | Returns `True` if the response body is a PostgREST error object (`{"code", "details", "hint", "message"}`) |
| `detect_supabase_url(network_events)` → `str \| None` | `config.py` auto-detect | Scans captured network events for `*.supabase.co` hostnames and returns the project URL |

---

## Scanner Registry

| Scanner | Category | Stages | `requires_stack` | `requires_second_account` | Phase |
|---------|----------|--------|-----------------|--------------------------|-------|
| `data_leakage` | Data Leakage | dev, pre-deploy, post-deploy | `["any"]` | `False` | 2 |
| `rls_bypass` | Access Control | pre-deploy, post-deploy | `["supabase"]` | `True` (cross-user checks; skipped if absent, not the whole scanner) | 2 |
| `tier_escalation` | Access Control | pre-deploy, post-deploy | `["supabase"]` | `False` | 2 |
| `bucket_limits` | Access Control | pre-deploy, post-deploy | `["supabase"]` | `False` | 2 |
| `auth_check` | Authentication | dev, pre-deploy, post-deploy | `["any"]` | `True` (concurrent session checks only) | 2 |
| `client_tampering` | Client-Side Tampering | dev, pre-deploy | `["any"]` | `False` | 2 |
| `sql_injection` | Injection | pre-deploy, post-deploy | `["any"]` | `False` | 2 |
| `cors_check` | Misconfiguration | post-deploy | `["any"]` | `False` | 4 |
| `xss_check` | Injection | pre-deploy only* | `["any"]` | `False` | 4 |
| `api_exposure` | API Security | pre-deploy, post-deploy | `["any"]` | `False` | 4 |

*`xss_check` is intentionally excluded from `post-deploy` — see `xss_check` Stage Coverage Note section.

**`requires_second_account` nuance for `rls_bypass` and `auth_check`:** These scanners run in full even without a second account — only the specific cross-user/concurrent-session checks are skipped. The scanner emits a `scanner_progress` info message when skipping those sub-checks.

---

## Core Scanners (Phase 2 — Supabase Focus)

### `data_leakage.py`
- **Category:** Data Leakage
- **Stages:** dev, pre-deploy, post-deploy
- **What it does:** Scans network responses and console output for sensitive data that shouldn't be client-visible
- **Checks:** Exposed Supabase anon/service keys, JWTs in URLs or response bodies, UUIDs that shouldn't be client-visible, PII in API responses beyond what the UI displays, sensitive data in console.log statements
- **How:** Uses CDP Network listener to inspect all response bodies and CDP Console listener for logged data

### `rls_bypass.py`
- **Category:** Access Control
- **Stages:** pre-deploy, post-deploy
- **What it does:** Attempts to query Supabase tables that RLS should block for the authenticated user
- **Checks:** Direct table access bypassing RLS, cross-user data access (if second test account configured), `USING (true)` overly permissive policies, missing `WITH CHECK` clauses
- **How:** Uses `utils/supabase_helpers.py` to inject Supabase JS client calls via CDP `Runtime.evaluate`. For cross-user checks, calls `auth.login(account=2)`, runs queries, then restores primary session via `auth.login(account=1)`
- **Second account:** Cross-user IDOR checks are silently skipped if `VIBE_ITERATOR_TEST_EMAIL_2` is not configured

### `tier_escalation.py`
- **Category:** Access Control
- **Stages:** pre-deploy, post-deploy
- **What it does:** Reads the user's subscription tier from the client, modifies it, and checks if the server accepts the spoofed tier
- **Checks:** Client-side tier stored in localStorage/cookies, tier value accepted without server-side validation, tier-gated features accessible after client-side modification
- **How:** Reads tier value, modifies via CDP, attempts tier-gated actions, checks server responses

### `bucket_limits.py`
- **Category:** Access Control
- **Stages:** pre-deploy, post-deploy
- **What it does:** Tests whether storage bucket upload limits are enforced server-side
- **Checks:** Upload count limits per plan, file size limits per plan, file type restrictions, bucket policy enforcement
- **How:** Attempts uploads that exceed the plan's allowance, verifies server-side rejection

### `auth_check.py` — EXTENSIVE
- **Category:** Authentication
- **Stages:** dev, pre-deploy, post-deploy
- **What it does:** Comprehensive authentication and session security audit covering the full auth lifecycle — from login to logout, including token handling, session management, password policies, and auth bypass vectors

**Check Group 1 — Token Security:**
- JWT storage location: flags localStorage/sessionStorage (insecure), expects httpOnly cookies
- JWT validation: sends requests with tampered JWT payloads (modified `sub`, `role`, `exp` claims) — server must reject
- JWT signature bypass: sends token with `alg: none` header — server must reject
- JWT secret strength: checks if tokens can be decoded without verification (`jwt.decode()` without `verify=True`)
- Token in URL: flags any JWT or session token appearing in URL parameters or query strings
- Token exposure in error responses: checks if error messages leak token details

**Check Group 2 — Session Management:**
- Session fixation: checks if session ID changes after authentication
- Session expiry: verifies tokens actually expire (waits or fast-forwards `exp` claim)
- Concurrent sessions: logs in from two contexts using `auth.login(account=2)`, checks if both sessions remain valid (configurable flag — some apps intentionally allow this). Restores primary session before returning
- Logout invalidation: after logout, replays the old token — server must reject
- Session cookie flags: checks `Secure`, `HttpOnly`, `SameSite` attributes on auth cookies

**Check Group 3 — Login Security:**
- Brute force protection: sends 10+ rapid failed login attempts — expects rate limiting or account lockout
- Username enumeration: checks if different error messages reveal whether an account exists ("user not found" vs "wrong password")
- Timing attack: measures response time for valid vs. invalid usernames — significant differences indicate enumeration
- Default/weak credentials: attempts common defaults (admin/admin, test/test) if not the configured test account
- Login over HTTPS: flags if login form submits credentials over HTTP

**Check Group 4 — Password & Account Security:**
- Password in response: checks if any API response includes password hashes or plaintext passwords
- Password reset flow: if a reset endpoint exists, checks for token predictability, expiry, and reuse
- Account takeover via email change: attempts to change email without re-authentication
- Missing re-authentication for sensitive actions: checks if password change, email change, or account deletion require current password

**Check Group 5 — Auth Bypass Vectors:**
- Unprotected routes: navigates to all configured pages without authentication — checks which ones allow access
- API endpoint auth: replays captured API requests without the auth header — expects 401/403
- HTTP method override: tries accessing protected endpoints with different HTTP methods (GET vs POST vs PUT)
- Path traversal in auth: tests if `/admin/../user/profile` or similar patterns bypass route-level auth checks
- GraphQL introspection: if GraphQL is detected, checks if introspection is enabled without auth

**Check Group 6 — OAuth / Third-Party Auth (if detected):**
- OAuth state parameter: checks if the `state` param is present and validated (CSRF protection)
- Redirect URI validation: tests if the OAuth callback accepts arbitrary redirect URLs
- Token exchange: verifies the auth code exchange happens server-side, not client-side

### `client_tampering.py`
- **Category:** Client-Side Tampering
- **Stages:** dev, pre-deploy
- **What it does:** Modifies client-side state and checks if the server blindly trusts it
- **Checks:** User role/permissions in localStorage or cookies, feature flags stored client-side, any client-side value that controls server behavior
- **How:** Reads client-side state, modifies values via CDP, performs actions, checks if server accepted tampered values

### `sql_injection.py` — EXTENSIVE
- **Category:** Injection
- **Stages:** pre-deploy, post-deploy
- **What it does:** Comprehensive SQL injection testing covering classic injection, Supabase/PostgREST-specific vectors, ORM bypass patterns, and blind injection techniques. This is a dedicated deep scanner — not a surface-level form check.

**Check Group 1 — Supabase / PostgREST Specific:**
- Filter operator manipulation: injects malicious values into `.eq()`, `.neq()`, `.gt()`, `.lt()`, `.like()`, `.ilike()`, `.in()`, `.or()` filter params in Supabase REST URLs
- PostgREST query string injection: manipulates `?select=`, `?order=`, `?limit=`, `?offset=` parameters to extract unauthorized data or cause errors that leak schema info
- RPC function injection: tests Supabase `rpc()` calls with SQL payloads in function arguments
- Supabase realtime subscription manipulation: checks if channel/topic names are sanitized
- `text search` injection: tests full-text search endpoints (`.textSearch()`, `.fts()`) with SQL metacharacters
- Horizontal filter bypass: attempts to add `.or()` conditions to existing filters via URL manipulation to access other users' data

**Check Group 2 — Classic SQL Injection:**
- Error-based injection: sends payloads that trigger SQL errors to confirm injection and extract database type/version (`' OR 1=1--`, `' UNION SELECT NULL--`, `'; SELECT version()--`)
- Union-based injection: attempts `UNION SELECT` payloads to extract data from other tables
- Stacked queries: tests if multiple statements are accepted (`; DROP TABLE test--` with a safe test table)
- Comment injection: tests `--`, `/* */`, and `#` comment patterns to truncate queries
- String termination variants: single quote, double quote, backtick, parenthesis — tests which characters break the query

**Check Group 3 — Blind SQL Injection:**
- Boolean-based blind: sends true/false conditions (`' AND 1=1--` vs `' AND 1=2--`) and compares response differences (content length, status code, response time)
- Time-based blind: sends `'; SELECT pg_sleep(3)--` and measures response delay (PostgreSQL-specific for Supabase)
- Out-of-band detection: for PostgreSQL, tests `COPY ... TO PROGRAM` and `dblink` if detectable through timing differences

**Check Group 4 — ORM & Query Builder Bypass:**
- Prisma `$queryRawUnsafe` detection: scans for raw SQL usage patterns in API responses or error messages
- Prisma operator injection: tests `{ contains: }`, `{ startsWith: }`, `{ gt: }` with SQL metacharacters to check if operators are sanitized
- Sequelize literal injection: if Sequelize patterns detected, tests `Sequelize.literal()` and `Sequelize.where()` with injection payloads
- Knex raw query detection: tests `.whereRaw()`, `.raw()` patterns with SQL payloads
- TypeORM injection: tests query builder methods with unsanitized inputs

**Check Group 5 — Input Vector Discovery:**
- Form input scanning: identifies all `<input>`, `<textarea>`, `<select>` elements and tests each with injection payloads
- URL parameter injection: tests every URL parameter captured by the network listener with SQL payloads
- JSON body injection: replays captured POST/PUT/PATCH requests with SQL payloads in each JSON field
- HTTP header injection: tests `X-Forwarded-For`, `Referer`, `User-Agent` headers with SQL payloads (some backends log these unsafely)
- Cookie value injection: tests cookie values with SQL payloads

**Check Group 6 — Post-Exploitation Indicators:**
- Schema leakage: checks if error responses reveal table names, column names, or database structure
- Database version disclosure: checks if errors or headers reveal PostgreSQL version
- Verbose error messages: flags any response containing SQL syntax errors, query plans, or stack traces that include SQL
- Information schema access: tests if `information_schema.tables` or `pg_catalog` are accessible through injection

**Detection Strategy:**
The scanner uses a layered approach:
1. **Passive analysis** — scan all captured network traffic for SQL-related error messages, schema leaks, and suspicious patterns (no active injection needed)
2. **Safe active testing** — send payloads that detect injection without modifying data (error-based, boolean-based, time-based)
3. **Invasive testing** (opt-in via config flag `allow_invasive: true`) — tests that could modify data (stacked queries, UNION-based extraction). Disabled by default. When enabled, uses only the test account and test data.

---

## Extended Scanners (Phase 4)

### `cors_check.py`
- **Category:** Misconfiguration
- **Stages:** post-deploy
- **What it does:** Tests CORS configuration for overly permissive settings
- **Checks:** `Access-Control-Allow-Origin: *`, credentials allowed with wildcard origin, sensitive endpoints accessible cross-origin, reflected Origin header without validation, null origin acceptance
- **How:** Sends cross-origin requests with various Origin headers, inspects CORS response headers

### `xss_check.py`
- **Category:** Injection
- **Stages:** pre-deploy
- **What it does:** Tests for cross-site scripting vulnerabilities across all input surfaces
- **Checks:**
  - Reflected XSS: payloads in URL params, form inputs, and headers reflected in response HTML
  - Stored XSS: payloads submitted via forms that persist and execute on subsequent page loads
  - DOM-based XSS: checks for dangerous sinks (`innerHTML`, `document.write`, `eval`) consuming user-controllable sources (`location.hash`, `location.search`, `document.referrer`)
  - Template injection: tests `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` patterns for server-side template injection
  - SVG/event handler injection: tests `<svg onload=...>`, `<img onerror=...>` patterns
  - Content-Type sniffing: checks for missing `X-Content-Type-Options: nosniff` header
  - CSP evaluation: checks if Content Security Policy headers are present and restrictive enough to mitigate XSS
- **How:** Injects payloads into all discovered input surfaces, checks DOM and network responses for execution or reflection

### `api_exposure.py`
- **Category:** API Security
- **Stages:** pre-deploy, post-deploy
- **What it does:** Discovers and tests API endpoints for authentication and authorization gaps
- **Checks:** Unauthenticated access to protected endpoints, mass assignment (sending extra fields the API shouldn't accept), rate limiting on sensitive endpoints (auth, AI, email), HTTP verb tampering, response header security (`X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`)
- **How:** Captures API endpoints from network traffic, replays without auth, tests with extra fields, checks response headers

---

## LLM Prompt Template

Every `Finding.llm_prompt` must follow this structure. Consistency across all scanners is mandatory — this is the primary deliverable for the developer.

```
You are a security expert helping me fix a vulnerability in my web application.

VULNERABILITY: {title}
SEVERITY: {severity}
SCANNER: {scanner_name}
PAGE: {page_url}
CATEGORY: {category}

WHAT WAS FOUND:
{plain_english_description — 2–4 sentences explaining what the issue is and what an attacker could do}

EVIDENCE:
{evidence_summary — the actual request/response, tampered value, leaked data, or payload that proves the issue. Include specific values, not generic descriptions}

YOUR TASK:
Fix the vulnerability described above in my codebase. 

1. Explain what the root cause is
2. Show me the specific code change needed (with before/after if possible)
3. If this involves {stack}-specific config (RLS policies, storage rules, auth settings), show me the exact config change
4. Confirm what I should test after applying the fix to verify it's resolved

My stack: {detected_stack}
```

**Rules for prompt content:**
- `evidence_summary` must include actual values from the scan (real JWT snippet, real endpoint URL, real tampered localStorage key) — never generic placeholders
- Keep the prompt under 800 tokens so it fits in any AI assistant context
- For Supabase findings, include the relevant Supabase dashboard section or SQL migration snippet
- `COPY FIX PROMPT` in the dashboard copies this exact string — what the developer pastes is what they see in the expanded `<details>` block

---

## Evidence Structure by Category

The `Finding.evidence` dict structure varies by scanner category. All scanners MUST conform to their category's structure — this drives the dashboard evidence panel rendering.

**Screenshots** are stored separately in `Finding.screenshots: list[Screenshot]` — not inside the `evidence` dict. Populate them using: `finding.screenshots.append(Screenshot(label="Before tampering", data=collector.capture()))`. The deep dive page renders them as a labeled carousel.

**Network timeline** (shown on deep dive Page 4) comes from `listeners/network.py` — all CDP network events captured during the scanner's run, ordered by timestamp. The scanner should pass the relevant network event window to `evidence/collector.py` so it can be attached to the finding. Add `network_events: list[dict]` to the evidence dict for findings where the full sequence matters (sql_injection, auth_check, api_exposure).

### Injection (`sql_injection`, `xss_check`)
```python
{
    "request": {
        "method": "GET",
        "url": "https://app.com/api/users?id=1' OR 1=1--",
        "headers": { "Authorization": "Bearer eyJ..." },
        "body": None
    },
    "response": {
        "status": 200,
        "headers": { "Content-Type": "application/json" },
        "body_excerpt": "[{\"id\":1,...},{\"id\":2,...}]",  # first 500 chars
        "body_truncated": True
    },
    "payload_used": "1' OR 1=1--",
    "payload_type": "error_based",   # or: union, boolean, time_based, reflected_xss, dom_xss
    "injection_point": "url_param:id",  # or: json_field:name, cookie:session, header:User-Agent
    # screenshots captured in Finding.screenshots — not inline in evidence dict
}
```

### Access Control (`rls_bypass`, `tier_escalation`, `bucket_limits`)
```python
{
    "action_attempted": "SELECT * FROM profiles WHERE id != current_user_id",
    "auth_context": "authenticated as user_id: abc123",
    "request": { "method": "GET", "url": "...", "headers": {...}, "body": None },
    "response": { "status": 200, "body_excerpt": "[{\"id\":\"xyz789\"...}]" },
    "expected_response": "403 Forbidden or empty array",
    "actual_response": "200 OK with other user's data",
    "second_account_used": True,    # True if cross-user check
    # screenshots captured in Finding.screenshots — not inline in evidence dict
}
```

### Authentication (`auth_check`)
```python
{
    "check_group": "Token Security",   # which of the 6 groups triggered this
    "check_name": "JWT stored in localStorage",
    "evidence_type": "storage_inspection",  # or: request_replay, timing_measurement, response_analysis
    "observed_value": "localStorage['sb-auth-token'] = 'eyJhbGci...'",
    "expected_behavior": "Token should be in httpOnly cookie, not accessible to JS",
    "request": { ... },   # if a request was replayed
    "response": { ... },  # if applicable
    # screenshots captured in Finding.screenshots — not inline in evidence dict
}
```

### Client-Side Tampering (`client_tampering`)
```python
{
    "storage_key": "user_role",
    "original_value": "free",
    "tampered_value": "admin",
    "storage_type": "localStorage",   # or: sessionStorage, cookie
    "action_performed": "POST /api/admin/users",
    "request": { "method": "POST", "url": "...", "headers": {...}, "body": "{...}" },
    "response": { "status": 200, "body_excerpt": "..." },
    "expected_response": "403 Forbidden",
    # screenshots captured in Finding.screenshots — not inline in evidence dict
}
```

### Data Leakage (`data_leakage`)
```python
{
    "leak_type": "supabase_service_key",  # or: jwt, uuid, pii_email, pii_phone, api_key
    "leak_location": "network_response",  # or: console_log, url_param, response_header
    "url": "https://app.com/api/init",
    "leaked_value_excerpt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...[truncated]",
    "context": "Found in response body of GET /api/init. Key starts with 'service_role'",
    "response_excerpt": "{ \"config\": { \"supabaseKey\": \"eyJ...\" } }"
}
```

### CORS (`cors_check`)
```python
{
    "test_origin_sent": "https://evil.com",
    "request": { "method": "GET", "url": "...", "headers": { "Origin": "https://evil.com" } },
    "response_headers": {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    },
    "issue": "credentials_with_wildcard"  # or: reflected_origin, null_origin_accepted
}
```

### Misconfiguration / API Security (`cors_check`, `api_exposure`)
```python
{
    "endpoint": "POST /api/admin/delete-user",
    "test_performed": "replay_without_auth",   # or: mass_assignment, verb_tamper, rate_limit
    "request": { "method": "POST", "url": "...", "headers": {}, "body": "{\"user_id\":\"abc\"}" },
    "response": { "status": 200, "body_excerpt": "{\"deleted\": true}" },
    "expected_response": "401 Unauthorized"
}
```

---

## Remediation Guidance Template

Every `Finding.remediation` must follow this structure:

```
**What to fix:** {one sentence naming the exact thing that needs to change}

**How to fix:** {1–2 sentences of concrete action. If Supabase/Firebase: name the exact policy, rule, or config setting. If code: describe the code pattern to change}

{optional} **Code / config example:**
{short snippet — SQL policy, Supabase dashboard setting, or before/after code block}

{optional} **Verify the fix:** {one sentence describing what to test after applying the fix}
```

**Examples:**

For `rls_bypass`:
> **What to fix:** The `profiles` table RLS policy allows any authenticated user to read all rows.
> **How to fix:** Update the SELECT policy to restrict reads to the authenticated user's own row using `auth.uid() = user_id`.
> ```sql
> CREATE POLICY "Users can only read own profile"
> ON profiles FOR SELECT
> USING (auth.uid() = user_id);
> ```
> **Verify the fix:** Re-run `rls_bypass` scanner — it should return 0 findings.

For `client_tampering`:
> **What to fix:** The server accepts the `user_role` value from localStorage without server-side validation.
> **How to fix:** Remove all role/permission checks from client-side storage. Derive the user's role exclusively from the authenticated JWT claims or a server-side database lookup on each request.
> **Verify the fix:** Re-run `client_tampering` scanner after the change — the tampered request should return 403.

---

## `xss_check` Stage Coverage Note

`xss_check` runs in `pre-deploy` only — not `post-deploy`. This is intentional: stored XSS tests submit persistent payloads that would pollute a live production database with test strings. Running XSS tests against a live production app requires manual cleanup or a sanitisation step that is out of scope for v1.

**Post-deploy XSS coverage gap:** The `post-deploy` stage has no XSS scanner. Developers who want post-deploy XSS coverage should either:
1. Use the `all` stage against a staging environment that mirrors production
2. Run `xss_check` standalone via `--stage all` on a staging URL before each release

This gap is explicitly documented here so it is not mistaken for an oversight.

---

## Adding New Scanners

To add a new scanner:

1. Create a new file in `vibe_iterator/scanners/` (e.g., `my_scanner.py`)
2. Extend `BaseScanner` and implement `run()`
3. Set `name`, `category`, and `stages`
4. Return a list of `Finding` objects (empty list = all checks passed)
5. Populate `Finding.evidence` using the structure for your category (see Evidence Structure section above)
6. Populate `Finding.llm_prompt` using the LLM Prompt Template above
7. Populate `Finding.remediation` using the Remediation Guidance Template above
8. Use `self.emit()` to send progress messages during the scan
9. Register the scanner name in the stage config (`vibe-iterator.config.yaml`)
10. Add a test file to `tests/test_scanners/`

The scanner will automatically be available in the dashboard and CLI.
