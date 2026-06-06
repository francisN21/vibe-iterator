# False Positive Hardening Design

## Goal

Reduce scary false positives from live production scans by requiring stronger proof before reporting vulnerabilities, and by labeling weak signals as explicit sanity checks with verification steps instead of confirmed exploitable issues.

## Problem Signals From Prod Scan

The latest live scan produced three useful calibration lessons:

- Passive SQL error detection can misread public security/privacy copy or JavaScript bundles as database leakage when the text only mentions SQL as a topic.
- Security header findings can be stale or edge-specific unless the scanner revalidates the deployed URL directly.
- Rate-limit findings can be noisy when they come from missing headers, authenticated GET routes, phantom endpoint names, or a burst that is below the app's configured threshold.

## Design

### SQL Proof Gate

Passive SQL findings should require a database-error signature in a dynamic same-app response. The scanner should skip static assets, Next.js bundles, and normal public document pages. A response that merely contains security-policy terms such as "SQL injection" must not produce a finding.

Confirmed passive findings must include:

- `proof_quality: passive_database_error_signature`
- `confidence: confirmed`
- the matched error signature
- response metadata showing the response was a dynamic document/API candidate

### Header Revalidation

Security header checks should prefer direct revalidation over passive-only observations. Before reporting a missing header, the scanner should request the canonical target or endpoint URL and check the live response headers.

Confirmed header findings must include:

- `proof_quality: direct_header_revalidation_missing`
- `confidence: confirmed`
- `passive_observation_url`
- `revalidation_url`
- `headers_seen`

If revalidation cannot run or is inconclusive, the scanner may emit a lower-severity sanity-check finding only when the signal is still useful. It must not use exploit language.

### Rate Limit Calibration

Rate-limit findings should come from active probes against confirmed auth-sensitive POST endpoints, not from header absence alone. Authenticated GET profile routes and non-existent endpoint variants must be skipped.

Confirmed missing-rate-limit findings must include:

- `proof_quality: repeated_auth_post_without_429`
- `confidence: confirmed`
- attempts sent
- response codes seen
- endpoint discovery source

If the scanner cannot exceed a likely production threshold, it should emit either no finding or an INFO sanity check with exact manual verification guidance.

### Sanity-Check Messaging

Weak signals should be clearly distinguished from vulnerabilities:

- Title starts with `Sanity check:`
- Severity is `INFO` unless there is stronger evidence
- Evidence contains `confidence: needs_review`
- Remediation starts with manual verification commands or steps
- LLM prompt says "verify before changing code"

This keeps the scanner helpful without making users chase phantom vulnerabilities.

## Non-Goals

- Do not hide real confirmed findings to make scores look better.
- Do not remove active proof probes that already require runtime evidence.
- Do not redesign the report UI in this slice.
- Do not clean unrelated mojibake or generated artifacts.

## Verification

- Add false-positive regression tests for SQL mentions in static/public content.
- Add header tests proving direct revalidation suppresses stale passive observations.
- Add rate-limit tests proving phantom endpoints and authenticated GET routes do not report vulnerabilities.
- Add tests proving weak signals use sanity-check messaging and `confidence: needs_review`.
- Run targeted scanner tests, full pytest, and coverage.
