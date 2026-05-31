# Rate Limit Check Scanner — Implementation Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a standalone `rate_limit_check` scanner that detects missing rate limiting, account lockout (DoS vector), and missing `Retry-After` headers across all auth-sensitive endpoints, with an opt-in deep scan mode for discovered routes.

**Architecture:** Two-pass probe per endpoint — Phase 1 sends a 10-attempt burst and classifies the response pattern into one of four outcomes (protected, lockout, unprotected, absent). Phase 2 runs only when a 429 was seen and verifies the `Retry-After` header. Deep scan applies the same two passes to POST endpoints captured by the network listener during crawl.

**Tech Stack:** Python stdlib (`urllib.request`), existing `BaseScanner`/`Finding` pattern, `vibe-iterator.config.yaml` for the deep scan flag, `routes.py` `_SCANNER_META` for dashboard wiring.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `vibe_iterator/scanners/rate_limit_check.py` | Create | Scanner — probe logic, finding emission |
| `vibe_iterator/config.py` | Modify | Add `rate_limit_deep_scan: bool` field |
| `vibe_iterator/server/routes.py` | Modify | Add `rate_limit_check` to `_SCANNER_META` |
| `tests/test_scanners/test_rate_limit_check.py` | Create | Unit tests — all HTTP mocked |
| `tests/test_scanners/test_rate_limit_check_proof.py` | Create | Proof tests — real HTTP against fixture |
| `tests/fixtures/vulnerable_app/app.py` | Modify | Add login, signup, forgot-password endpoints + a rate-limited endpoint |
| `.env.example` / `vibe-iterator.config.yaml` | Modify | Document `rate_limit_deep_scan` field |

---

## Scanner Metadata

```python
name = "rate_limit_check"
category = "Rate Limiting"
stages = ["dev", "pre-deploy", "post-deploy"]
requires_stack = ["any"]
requires_second_account = False
```

---

## Standard Endpoint Coverage

Probed unconditionally on every run. For each label, path variants are tried in order; the first that does not return 404/405/501 is the active endpoint. If all variants return 404/405/501, the label is skipped silently.

| Label | Path variants (tried in order) | Method |
|---|---|---|
| Login | `/api/auth/login`, `/api/login`, `/auth/login` | POST |
| Password Reset | `/api/auth/forgot-password`, `/api/auth/reset-password`, `/api/reset-password` | POST |
| Signup | `/api/auth/signup`, `/api/auth/register`, `/api/register` | POST |
| OTP / Magic Link | `/api/auth/otp`, `/api/auth/magic-link` | POST |
| Email Verification | `/api/auth/verify`, `/api/auth/resend` | POST |
| Supabase Auth | `/auth/v1/token?grant_type=password` | POST |

---

## Deep Scan Mode

Controlled by `rate_limit_deep_scan: false` in `vibe-iterator.config.yaml` (new field, default `false`).

When enabled:
1. Collect all POST endpoints from the network listener (`network.get_requests()` filtered to `method == "POST"`).
2. Deduplicate against the standard endpoint list (path-prefix match).
3. Cap at 20 additional endpoints to keep runtime bounded.
4. Run the identical two-pass probe on each. Findings carry the full endpoint URL as `page`.

---

## Probe Request Format

```
POST {base_url}{path}
Content-Type: application/json

{"email": "probe@vibe-iterator-test.invalid", "password": "VI_PROBE_xXx"}
```

Timeout per request: 3 seconds. The probe email domain (`vibe-iterator-test.invalid`) is an RFC 2606 reserved domain — guaranteed not to match any real account.

---

## Phase 1 — Burst Probe (10 attempts)

Send up to 10 requests in sequence, inspecting each response immediately:

| Response condition | Classification | Action |
|---|---|---|
| Any attempt returns `429` | Protected | Record `Retry-After` header presence, go to Phase 2 |
| Response code shifts mid-burst (e.g. `401`→`403`/`423`) | Lockout | Emit Finding B, stop this endpoint |
| Body at any attempt contains `"locked"`, `"suspended"`, `"too many attempts"` | Lockout | Emit Finding B, stop this endpoint |
| All 10 return `401`/`400`/`422` with no shift | Unprotected | Emit Finding A |
| All 10 return `404`/`405`/`501` | Absent | Skip silently |

"Code shift" is defined as: the response code on attempt N differs from the mode of attempts 1–(N-1), where the new code is not `429`.

---

## Phase 2 — Retry-After Verification

Only runs when Phase 1 classified the endpoint as Protected (saw a 429).

- If the 429 response includes `Retry-After` header with a positive integer value → clean pass, no finding.
- If `Retry-After` is absent or zero → emit Finding C (INFO).

---

## Findings

### Finding A — Missing Rate Limiting

```
scanner:   rate_limit_check
severity:  MEDIUM
category:  Rate Limiting
title:     "No rate limiting on {label} endpoint ({path})"
page:      {base_url}{path}
```

**Evidence dict:**
```python
{
    "check_group": "Rate Limiting",
    "check_name": "Burst probe",
    "evidence_type": "request_replay",
    "endpoint": "{base_url}{path}",
    "label": "{label}",
    "attempts_sent": 10,
    "response_codes_seen": [401, 401, 401, ...],   # list of ints, length = attempts sent
    "expected_behavior": "Endpoint should return 429 by attempt 6 with a Retry-After header",
}
```

**Remediation:**
```
**What to fix:** {label} endpoint has no rate limiting — an attacker can
make unlimited attempts without being slowed down.

**How to fix (Next.js + Upstash):**
Install: npm install @upstash/ratelimit @upstash/redis

import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, "60 s"),
  analytics: true,
});

export async function POST(req) {
  const ip = req.headers.get("x-forwarded-for") ?? "anonymous";
  const email = (await req.json()).email ?? "";
  const key = `rl:login:${ip}:${email}`;
  const { success, reset } = await ratelimit.limit(key);
  if (!success) {
    return Response.json(
      { error: "Too many attempts. Try again later." },
      { status: 429, headers: { "Retry-After": String(Math.ceil((reset - Date.now()) / 1000)) } }
    );
  }
  // ... rest of handler
}

**Alternative (rate-limiter-flexible, no external service):**
Install: npm install rate-limiter-flexible

import { RateLimiterMemory } from "rate-limiter-flexible";
const limiter = new RateLimiterMemory({ points: 10, duration: 60 });

const key = `${ip}_${email}`;
try { await limiter.consume(key); }
catch { return Response.json({ error: "Too many attempts." }, { status: 429,
        headers: { "Retry-After": "60" } }); }

**For Supabase:** Enable Auth → Rate Limits in your Supabase project
dashboard. Set "Email logins per hour" to a value ≤ 10.

**Verify the fix:** Re-run rate_limit_check — the 6th attempt must return 429.
```

---

### Finding B — Account Lockout (DoS Vector)

```
scanner:   rate_limit_check
severity:  LOW
category:  Rate Limiting
title:     "Account lockout on {label} endpoint — DoS risk ({path})"
page:      {base_url}{path}
```

**Evidence dict:**
```python
{
    "check_group": "Rate Limiting",
    "check_name": "Lockout detection",
    "evidence_type": "request_replay",
    "endpoint": "{base_url}{path}",
    "label": "{label}",
    "lockout_detected_at_attempt": N,
    "code_before": 401,
    "code_after": 403,
    "body_excerpt": "...",   # first 200 chars of the lockout response body
    "expected_behavior": "Endpoint should return 429 + Retry-After, not lock the account",
}
```

**Remediation:**
```
**What to fix:** {label} endpoint locks accounts after failed attempts.
A locked account requires manual recovery (e.g. opening an IT ticket or
waiting for a timed reset). An attacker can deliberately trigger this to
lock out any user whose email they know — no password needed.

**How to fix:** Replace lockout with 429 + Retry-After progressive throttling:
- Attempts 1–5:  allow (normal 401)
- Attempts 6–20: return 429, Retry-After: 60
- Attempts 21–50: return 429, Retry-After: 300
- Attempts 51+:  return 429, Retry-After: 3600

Key on (IP + target email) together — not email alone (locks out the real
user) and not IP alone (trivially bypassed with proxies).

Never lock the account. The account owner is the victim of lockout, not
the attacker.

**Verify the fix:** Re-run rate_limit_check — lockout finding must be gone,
and a 429 must appear by attempt 6.
```

---

### Finding C — Missing Retry-After Header

```
scanner:   rate_limit_check
severity:  INFO
category:  Rate Limiting
title:     "429 response missing Retry-After header on {label} endpoint ({path})"
page:      {base_url}{path}
```

**Evidence dict:**
```python
{
    "check_group": "Rate Limiting",
    "check_name": "Retry-After header",
    "evidence_type": "response_analysis",
    "endpoint": "{base_url}{path}",
    "label": "{label}",
    "response_code": 429,
    "headers_received": ["Content-Type: application/json", ...],  # list of non-auth headers
    "expected_behavior": "429 response must include Retry-After: <seconds>",
}
```

**Remediation:**
```
**What to fix:** The 429 response does not include a Retry-After header.
HTTP clients, mobile apps, and retry libraries use this header to know
when to try again. Without it they either hammer immediately (defeating
the rate limit) or back off arbitrarily.

**How to fix:** Add the header to every 429 response:
  Retry-After: 60   (seconds until the window resets)

In Next.js:
  return Response.json({ error: "Too many attempts." },
    { status: 429, headers: { "Retry-After": "60" } });

**Verify the fix:** Re-run rate_limit_check — INFO finding must be gone.
```

---

## Config Changes

### `vibe_iterator/config.py`
Add field:
```python
rate_limit_deep_scan: bool = False
```
Loaded from `vibe-iterator.config.yaml` key `rate_limit_deep_scan`.

### `vibe-iterator.config.yaml` (example / docs)
```yaml
# Set to true to probe all POST endpoints discovered during crawl (capped at 20)
rate_limit_deep_scan: false
```

---

## Dashboard Wiring

### `vibe_iterator/server/routes.py` — `_SCANNER_META`
```python
"rate_limit_check": {
    "requires_stack": ["any"],
    "requires_second_account": False,
    "category": "Rate Limiting",
    "est_seconds": 45,
},
```

### Stage membership
Add `rate_limit_check` to:
- `pre-deploy` stage scanner list
- `post-deploy` stage scanner list
- NOT `dev` (dev stage is quick; rate limit probing requires 10 attempts × N endpoints)

---

## Fixture App Additions

`tests/fixtures/vulnerable_app/app.py` needs four new `POST` endpoints:

| Path | Behavior | Purpose |
|---|---|---|
| `/api/auth/login` | Always `401 {"error": "Invalid credentials"}` | Triggers Finding A |
| `/api/auth/signup` | Always `200 {"message": "registered"}` | Triggers Finding A |
| `/api/auth/forgot-password` | Attempts 1–4 → `401`, attempt 5+ → `403 {"error": "account locked"}` | Triggers Finding B |
| `/api/auth/rate-limited-login` | Attempt 2+ → `429` with `Retry-After: 30` | Negative control (no finding) |

The fixture tracks attempt counts per endpoint path in a module-level dict (reset on each `VulnerableApp.__enter__`).

---

## Unit Tests — `tests/test_scanners/test_rate_limit_check.py`

All HTTP calls patched via `unittest.mock.patch("urllib.request.urlopen")`.

| Test | What it verifies |
|---|---|
| `test_no_rate_limit_login_detected` | 10 × 401 → Finding A, MEDIUM, title contains "Login" |
| `test_no_rate_limit_password_reset_detected` | Login path 404s, reset path returns 10 × 200 → Finding A for Password Reset |
| `test_lockout_detected_code_shift` | Attempts 1–4 return 401, attempt 5 returns 403 → Finding B, LOW |
| `test_lockout_detected_body_signal` | All 401 but body contains "account locked" at attempt 6 → Finding B |
| `test_rate_limited_with_retry_after_no_finding` | Attempt 6 returns 429 with `Retry-After: 60` header → no findings |
| `test_rate_limited_missing_retry_after_finding_c` | 429 present but no `Retry-After` header → Finding C, INFO |
| `test_all_endpoints_404_no_findings` | All path variants return 404 → empty findings list |
| `test_deep_scan_probes_network_endpoints` | Network listener returns 3 POST endpoints → all three probed |
| `test_deep_scan_skips_already_covered_endpoints` | Network endpoint overlaps standard list → not double-probed |
| `test_deep_scan_caps_at_20_endpoints` | Network listener returns 25 endpoints → only 20 additional probed |

---

## Proof Tests — `tests/test_scanners/test_rate_limit_check_proof.py`

Real HTTP against `VulnerableApp` fixture (no Selenium).

| Test | What it verifies |
|---|---|
| `test_proof_no_rate_limit_on_login` | Scanner → Finding A for Login endpoint |
| `test_proof_lockout_on_forgot_password` | Scanner → Finding B for Password Reset endpoint |
| `test_proof_signup_no_rate_limit` | Scanner → Finding A for Signup endpoint |
| `test_proof_negative_rate_limited_endpoint` | `/api/auth/rate-limited-login` returns 429 + Retry-After → no findings for that endpoint |

---

## Spec Self-Review

**Placeholder scan:** No TBD or TODO in this document.

**Internal consistency:** Phase 1/2 logic matches the three findings exactly. Evidence dict keys match what the deep-dive modal renders (generic JSON in `<pre>`). `routes.py` wiring matches the stage membership section. Fixture endpoints match the proof test expectations.

**Scope check:** Single scanner, single file, two supporting test files, three minor edits (config, routes, fixture). Fits one implementation plan.

**Ambiguity check:**
- "Code shift" is explicitly defined (mode of prior attempts, new code ≠ 429).
- "20 additional endpoints" is capped after deduplication against the standard list.
- Probe email domain is RFC 2606 reserved — no ambiguity about whether it matches real accounts.
- `dev` stage exclusion is explicit and justified (10 attempts × N endpoints is too slow for a quick scan).
