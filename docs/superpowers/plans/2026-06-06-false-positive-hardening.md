# False Positive Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce Vibe Iterator false positives from live production scans by hardening proof gates and adding sanity-check messaging for weak signals.

**Architecture:** Keep scanner interfaces stable. Add small proof helpers inside the affected scanners, require confirmed proof for vulnerability findings, and reserve INFO sanity-check wording for weak or inconclusive signals.

**Tech Stack:** Python 3.11, pytest, existing scanner dataclasses, urllib-based probes.

---

### Task 1: Commit Spec And Plan

**Files:**
- Create: `docs/superpowers/specs/2026-06-06-false-positive-hardening-design.md`
- Create: `docs/superpowers/plans/2026-06-06-false-positive-hardening.md`

- [ ] Run `git diff --check`.
- [ ] Commit with `docs: plan false positive hardening`.

### Task 2: Harden SQL Passive Proof

**Files:**
- Modify: `vibe_iterator/scanners/sql_injection.py`
- Modify: `tests/test_scanners/test_core_runtime_scanners.py`
- Modify: `tests/test_scanners/test_sql_injection_proof.py`

- [ ] Add failing tests that static security-copy text containing "SQL injection" creates no passive finding.
- [ ] Add failing tests that `.js`, `.css`, and Next.js bundle responses are skipped by passive SQL detection.
- [ ] Add failing tests that a real database error response still reports and includes `proof_quality: passive_database_error_signature` and `confidence: confirmed`.
- [ ] Implement response-candidate filtering and richer SQL error signature metadata.
- [ ] Run `python -m pytest tests/test_scanners/test_core_runtime_scanners.py tests/test_scanners/test_sql_injection_proof.py -q`.
- [ ] Commit with `fix: harden passive sql proof gate`.

### Task 3: Harden Header Revalidation

**Files:**
- Modify: `vibe_iterator/scanners/api_exposure.py`
- Modify: `vibe_iterator/scanners/xss_check.py`
- Modify: `tests/test_scanners/test_api_exposure.py`
- Modify: `tests/test_scanners/test_api_exposure_proof.py`
- Modify: `tests/test_scanners/test_xss_check.py`
- Modify: `tests/test_scanners/test_xss_proof.py`

- [ ] Add failing tests where passive captured headers are missing but direct revalidation has the header, producing no finding.
- [ ] Add failing tests where direct revalidation confirms a missing header and evidence includes `proof_quality: direct_header_revalidation_missing`.
- [ ] Implement direct header revalidation helper with safe timeout and same-origin/canonical URL handling.
- [ ] Add sanity-check messaging only for inconclusive direct validation if needed by existing behavior.
- [ ] Run `python -m pytest tests/test_scanners/test_api_exposure.py tests/test_scanners/test_api_exposure_proof.py tests/test_scanners/test_xss_check.py tests/test_scanners/test_xss_proof.py -q`.
- [ ] Commit with `fix: revalidate security header findings`.

### Task 4: Harden Rate-Limit Endpoint Discovery

**Files:**
- Modify: `vibe_iterator/scanners/api_exposure.py`
- Modify: `vibe_iterator/scanners/rate_limit_check.py`
- Modify: `tests/test_scanners/test_api_exposure.py`
- Modify: `tests/test_scanners/test_rate_limit_check.py`
- Modify: `tests/test_scanners/test_rate_limit_check_proof.py`

- [ ] Add failing tests that missing rate-limit headers alone do not create vulnerability findings.
- [ ] Add failing tests that authenticated GET routes like `/api/auth/me` are not treated as brute-force endpoints.
- [ ] Add failing tests that endpoint variants returning 401 for catch-all middleware are skipped unless they are known existing auth POST routes.
- [ ] Add or update confirmed findings to include `proof_quality: repeated_auth_post_without_429` and `confidence: confirmed`.
- [ ] Implement INFO sanity-check messaging only for weak live-threshold uncertainty if retained.
- [ ] Run `python -m pytest tests/test_scanners/test_api_exposure.py tests/test_scanners/test_rate_limit_check.py tests/test_scanners/test_rate_limit_check_proof.py -q`.
- [ ] Commit with `fix: reduce rate limit false positives`.

### Task 5: Final Verification

**Files:**
- Modify docs only if behavior docs need alignment.

- [ ] Run `python -m pytest -q`.
- [ ] Run `python -m pytest --cov=vibe_iterator --cov-report=term-missing -q`.
- [ ] Run `python scripts/check_scanner_exposure.py`.
- [ ] Commit final docs if changed.
