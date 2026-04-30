# Vibe Iterator Handoff Memory

Last updated: 2026-04-29

## Current State

All original build phases are implemented, and the latest Codex hardening pass moved the repo much closer to true Phase 6 readiness.

Latest committed work:

- `da27323 test: harden phase 6 readiness gates`

Current verification baseline:

- `.\.venv\Scripts\python.exe -m pytest`
  - `219 passed, 1 skipped`
- `.\.venv\Scripts\python.exe -m pytest --cov=vibe_iterator --cov-report=term-missing`
  - `219 passed, 1 skipped`
  - total coverage: `81%`
- Packaging verified:
  - wheel build passed with `py -m pip wheel . --no-deps -w tests\.tmp-wheelhouse`
  - fresh venv install passed
  - installed CLI works: `vibe-iterator --version`
  - installed package includes dashboard static files and report templates

Only known untracked local files after the commit:

- `.claude/`
- `AGENTS.md`
- `icon.svg`
- `logo.svg`

Do not assume these should be committed without checking with Francisco.

## New Hardening And Features Introduced

Configuration and CLI:

- `scanner_timeout_seconds` from `vibe-iterator.config.yaml` is now loaded and validated.
- Config priority docs/code were aligned around CLI > env > YAML > defaults.
- CLI help text now reflects that `--verbose` and `--output` are implemented.

Dashboard/API lifecycle:

- `POST /api/scan/start` now returns a stable `scan_id` immediately.
- Invalid or empty `scanner_overrides` now return HTTP 400 before background scan startup.
- A running background task now blocks double-start races.
- Report export now only allows completed scans.
- Dashboard app now sets baseline security headers:
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - CSP with current inline allowances

Engine/browser:

- `ScanRunner` accepts a caller-provided `scan_id`.
- Cancellation now reaches the active scanner task.
- Chrome debug port defaults to `0` so Chrome chooses a free port.
- `--disable-web-security` is now opt-in with `VIBE_ITERATOR_DISABLE_WEB_SECURITY=1`.
- `.env.example` documents the new Chrome controls.

Frontend safety:

- Removed the dangerous inline `copyToClipboard(JSON.stringify(...))` path from finding cards.
- Result-card copy/detail/category handlers are attached with JS listeners instead of the most risky inline string interpolation.
- WebSocket client now chooses `ws:` or `wss:` based on page protocol.

Testing:

- Pytest cache provider is disabled in `pyproject.toml` because locked cache dirs caused Windows permission failures in this workspace.
- Workspace-local temp path fixture was added in `tests/conftest.py`.
- New coverage added for:
  - auth scanner core checks
  - SQL injection scanner core checks
  - RLS scanner unauth/cross-user paths
  - bucket cleanup/type checks
  - crawler/browser helpers
  - evidence collector
  - Supabase helpers
  - CLI GUI/report-error behavior
  - docs/UI mojibake guard
- Opt-in real Selenium/CDP smoke test added:
  - `tests/e2e/test_real_browser_smoke.py`
  - skipped by default
  - run manually with:
    - PowerShell: `$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; .\.venv\Scripts\python.exe -m pytest tests\e2e`

## Important Caveats

The project is Phase 6-ready for the next iteration, but not "done done."

Known remaining product gaps:

- `auth_check` and `sql_injection` now have much better tests, but several checks are still heuristic and need live vulnerable-app proof cases.
- `xss_check` is still mostly passive/header/DOM-sink analysis. It does not yet prove reflected or stored XSS execution.
- `cors_check` does not yet perform full OPTIONS preflight and credentialed browser-behavior tests.
- `api_exposure` rate limiting is still header-based, not an active bounded repeated-request probe.
- Dashboard CSP still allows inline scripts/styles because the existing UI uses inline handlers/styles in several places. Next hardening should remove `unsafe-inline`.
- `NetworkListener` still relies on Selenium `add_cdp_listener`; the opt-in e2e smoke should confirm this on any release machine.
- Locked local dirs may exist from old pytest cache behavior:
  - `tests/pytest-cache-files-*`
  - they are ignored and excluded from pytest recursion.

## Recommended Next Claude Task

Start Phase 6 with an "exploit proof harness" milestone.

Recommended order:

1. Build a tiny intentionally vulnerable local demo app under `tests/fixtures/vulnerable_app/`.
   - Include endpoints/pages for auth leak, SQL error, unprotected API, weak CORS, and simple reflected XSS.
   - Keep it local-only and deterministic.

2. Extend `tests/e2e/test_real_browser_smoke.py` or add new e2e tests to run real scans against that fixture.
   - Keep them opt-in at first with `VIBE_ITERATOR_RUN_E2E_SMOKE=1`.
   - Prove Selenium launch, CDP listener capture, page crawl, scanner result creation, and report export.

3. Turn the most important scanners from heuristic to proof-oriented:
   - `xss_check`: add controlled payload injection and execution detection.
   - `cors_check`: add OPTIONS preflight and credentialed checks.
   - `api_exposure`: add bounded active rate-limit probe and better API endpoint classification.
   - `auth_check`: add live-app proof coverage for logout invalidation, brute-force rate limiting, and auth bypass.
   - `sql_injection`: add vulnerable fixture proof for URL params, JSON body, and time-based behavior.

4. Finish dashboard CSP hardening.
   - Remove remaining inline `onclick` and inline style usage where practical.
   - Change CSP to remove `script-src 'unsafe-inline'`.
   - Add tests that key dashboard pages include the stricter CSP.

5. Add release workflow polish.
   - CI matrix for Windows/Linux with Python 3.11+.
   - Separate normal unit tests from opt-in Selenium smoke tests.
   - Packaging verification job that builds the wheel, installs it into a fresh venv, checks CLI entry point, and checks package data.

## Commands Claude Should Run First

```powershell
git status --short
git log -3 --oneline
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pytest --cov=vibe_iterator --cov-report=term-missing
```

Optional real browser smoke:

```powershell
$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"
.\.venv\Scripts\python.exe -m pytest tests\e2e
Remove-Item Env:\VIBE_ITERATOR_RUN_E2E_SMOKE
```

Packaging verification, if needed:

```powershell
py -m pip wheel . --no-deps -w tests\.tmp-wheelhouse
py -m venv tests\.tmp-install-venv
tests\.tmp-install-venv\Scripts\python.exe -m pip install tests\.tmp-wheelhouse\vibe_iterator-0.1.0-py3-none-any.whl
tests\.tmp-install-venv\Scripts\vibe-iterator.exe --version
```

Clean temp packaging dirs after verification:

```powershell
Remove-Item -LiteralPath tests\.tmp-wheelhouse -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath tests\.tmp-install-venv -Recurse -Force -ErrorAction SilentlyContinue
```

