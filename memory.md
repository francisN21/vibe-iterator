# Vibe Iterator Handoff Memory

Last updated: 2026-05-31

## Current State

The repo is now in a much stronger Phase 6-ready state. The latest local Phase 6 pass focused on making the proof harness real, keeping verification fast, and making test results independent of this machine's local `.env`.

Current verification baseline:

- `.\.venv\Scripts\python.exe -m pytest`
  - `417 passed, 2 skipped`
  - runtime: about 32 seconds
- `.\.venv\Scripts\python.exe -m pytest --cov=vibe_iterator --cov-report=term-missing`
  - `417 passed, 2 skipped`
  - total coverage: `80%`
- Opt-in real browser smoke:
  - `$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; .\.venv\Scripts\python.exe -m pytest -q tests\e2e`
  - `2 passed`
- Packaging verified:
  - `py -m pip wheel . --no-deps -w tests\.tmp-wheelhouse`
  - fresh venv install from the wheel passed
  - installed CLI works: `vibe-iterator, version 0.1.0`

Known untracked local files historically seen in this workspace:

- `.claude/`
- `AGENTS.md`
- `icon.svg`
- `logo.svg`

Do not assume these should be committed without checking with Francisco.

## New Phase 6 Work Introduced

Exploit proof harness:

- The generic vulnerable fixture app now includes a `/login` form so the real scan runner can authenticate.
- The fixture dashboard now emits API traffic to:
  - `/api/user`
  - `/api/login`
  - `/api/protected` with an `Authorization` header
- Added fixture smoke coverage for the login/dashboard scan-target behavior.
- Added an opt-in Selenium/CDP e2e scan runner test against the vulnerable fixture:
  - `tests/e2e/test_real_browser_smoke.py`
  - verifies real Chrome launch, CDP network capture, `ScanRunner`, scanner execution, and actual findings for unauthenticated API access, reflected CORS, and sensitive path exposure.

Runtime/test reliability:

- `info_disclosure` no longer serially waits through every sensitive path when a local target is down.
- It now performs a fast local TCP reachability check and aborts after repeated network-level probe failures.
- Scanner proof test runtime dropped from about 9.5 minutes to about 22 seconds.
- Firebase Auth and Storage scanners now use a shared `is_closed_local_url()` helper to skip REST calls to closed local fixture endpoints.
- Closed local Firebase endpoint checks are cached briefly to avoid repeated socket waits inside one run.
- `ScanRunner` now detaches listeners before quitting Chrome, avoiding Selenium teardown retry noise.
- Config tests now pass an explicit empty env file where required, preventing a developer's real `.env` from leaking into test expectations.

## Remaining Before A Very Robust Phase 6+

The product is now Phase 6-ready to continue, but the next high-leverage items are:

1. Dashboard CSP hardening:
   - remove remaining inline scripts/styles/handlers where practical
   - remove `script-src 'unsafe-inline'` from dashboard CSP
   - add route/header tests for the stricter CSP

2. Deeper exploit proofs:
   - XSS: prove reflected or DOM execution, not only dangerous sinks and reflected marker checks
   - SQL injection: add JSON body and time-based vulnerable fixture proof cases
   - Auth: add live proof for logout invalidation, brute-force/rate-limit behavior, and bypass vectors

3. Firebase proof polish:
   - Firestore and Functions negative tests are still the slowest scanner cases, though acceptable
   - consider applying the shared closed-local helper there where the target URL is local

4. Release workflow:
   - add CI matrix for Windows/Linux and Python 3.11+
   - separate normal tests from opt-in Selenium smoke tests
   - add packaging verification job that builds, installs, checks CLI, and confirms package data

## Commands Claude Should Run First

```powershell
git status --short
git log -5 --oneline
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pytest --cov=vibe_iterator --cov-report=term-missing
```

Optional real browser smoke:

```powershell
$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"
.\.venv\Scripts\python.exe -m pytest -q tests\e2e
Remove-Item Env:\VIBE_ITERATOR_RUN_E2E_SMOKE
```

Packaging verification:

```powershell
Remove-Item -LiteralPath tests\.tmp-wheelhouse -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath tests\.tmp-install-venv -Recurse -Force -ErrorAction SilentlyContinue
py -m pip wheel . --no-deps -w tests\.tmp-wheelhouse
py -m venv tests\.tmp-install-venv
tests\.tmp-install-venv\Scripts\python.exe -m pip install tests\.tmp-wheelhouse\vibe_iterator-0.1.0-py3-none-any.whl
tests\.tmp-install-venv\Scripts\vibe-iterator.exe --version
Remove-Item -LiteralPath tests\.tmp-wheelhouse -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath tests\.tmp-install-venv -Recurse -Force -ErrorAction SilentlyContinue
```
