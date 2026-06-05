# Phase 7B Verification Depth Design Spec

- **Date:** 2026-06-03 (revised 2026-06-04)
- **Status:** Approved
- **Author:** Codex using Superpowers brainstorming + writing-plans workflow; revised by claude-sonnet-4-6
- **Scope:** Add deeper runtime verification, Firebase helper coverage, real-world edge fixtures, and final docs alignment after Phase 6 scanner hardening.
- **Related docs:** `README.md`, `docs/SCANNERS.md`, `docs/PHASES.md`, `docs/superpowers/plans/2026-05-30-security-enhancement-phase-7a.md`, `docs/superpowers/specs/2026-05-29-firebase-scanner-design.md`

---

## 1. Summary

Phase 6 made Vibe Iterator much stricter about proof quality. The remaining high-value work is not another wave of broad scanner features; it is verification depth. We need more evidence that the existing scanners behave correctly when they run in a real browser against a live vulnerable app, more coverage over Firebase helper branches, more realistic edge fixtures for tier/storage/auth scenarios, and docs that match the final behavior once these checks settle.

This spec treats the next tranche as **Phase 7B: readiness verification and fixtures**. It should be implemented as a test-first hardening pass. Scanner behavior should only change when a new fixture or e2e test exposes a real false positive, false negative, cleanup issue, or unsafe probe.

---

## 2. Current Findings

The current merged `main` state is strong:

- Full suite: `438 passed, 2 skipped`
- Coverage: `~81%`
- Fresh wheel build/install smoke: passed
- Phase 6 proof gates are merged into `main`

Remaining practical gaps:

- `tests/e2e/test_real_browser_smoke.py` has two opt-in Selenium/CDP tests, but the real scan runner path only exercises `xss_check`, `cors_check`, `api_exposure`, and `info_disclosure`.
- Firebase helper coverage is one of the weaker areas. The last coverage report showed `vibe_iterator/utils/firebase_helpers.py` at 58%.
- Firebase helper tests cover many happy paths, but thin branches remain around local reachability caching, REST delete/upload/download error handling, Firestore typed conversions beyond simple scalar values, and request construction for auth/local-host edge cases.
- The vulnerable app fixture has useful generic API vulnerabilities, but it does not yet model enough real-world tier, storage, and auth edge cases to prove the stricter Phase 6 gates across varied response shapes.
- README and docs are partially updated but `docs/SCANNERS.md`, `docs/PHASES.md`, `docs/CONFIG.md`, and `docs/ADDING_SCANNERS.md` need a final alignment pass.

---

## 3. Goals

1. Add opt-in Selenium/CDP e2e coverage that runs the real scan engine against local fixture apps and validates scanner findings from browser-captured traffic.
2. Raise Firebase helper confidence with focused branch tests and, where needed, small helper improvements.
3. Expand local fixture apps with realistic tier, storage, and auth edge cases, including negative controls that must not produce findings.
4. Preserve the fast default test suite. Real browser tests stay opt-in unless CI explicitly enables them.
5. Keep all fixture tests hermetic: local `127.0.0.1` only, no real Firebase, Supabase, Stripe, or third-party calls.
6. Keep dangerous probe behavior safe: probe writes must use `vibe_iterator_probe_` or an equivalent test-only namespace and clean up when a scanner supports cleanup.
7. Update docs only after behavior is verified, so the docs describe actual scanner semantics instead of desired scanner semantics.
8. Establish an e2e stability tracker (JSON log) that records milestone-based runs, enabling data-driven graduation from Option C (manual `workflow_dispatch`) to Option A (every-push CI) after 6 consecutive clean runs.

---

## 4. Non-Goals

1. Do not add new scanners in this tranche.
2. Do not loosen Phase 6 proof-quality gates to increase finding counts.
3. Do not make Selenium/CDP e2e mandatory for normal `python -m pytest`.
4. Do not depend on a developer having a real Firebase or Supabase project to run tests.
5. Do not redesign the dashboard, report format, scoring model, or scanner registry.
6. Do not introduce new runtime dependencies unless a test reveals an unavoidable need.

---

## 5. Approach Options

### Option A: One Big Live Demo App

Build one large fixture app that exercises every scanner in a browser and assert all expected findings from one full scan.

**Pros:** Most realistic single-path validation.

**Cons:** Flaky, slow, harder to debug, and likely to fail for unrelated reasons when one scanner changes. This is not the recommended path.

### Option B: Unit-Only Coverage Push

Add mocked unit tests until coverage rises, with no extra Selenium/CDP scans.

**Pros:** Fast and stable.

**Cons:** Misses the exact risk we care about: browser listeners, network capture, scanner orchestration, and live HTTP proof. This is useful but incomplete.

### Option C: Hybrid Proof Matrix (Recommended)

Use focused unit/proof tests for most branch depth, plus a small set of opt-in Selenium/CDP e2e scans against local fixtures.

**Pros:** Best balance of confidence, speed, and debuggability. The default suite stays fast, while real browser paths can be run before releases.

**Cons:** Requires careful fixture design and a small amount of e2e orchestration.

**Recommendation:** Use Option C.

---

## 6. Architecture

The work should be split into four independent tracks. Each track is testable on its own and can be committed independently.

### Track 1: Selenium/CDP E2E Proof Matrix

#### CI Strategy: Option C → Option A Graduation

E2e tests run via **manual `workflow_dispatch`** in GitHub Actions — headless Chrome on Ubuntu runners, triggered from the Actions tab. This does not block PRs or the default `pytest` run.

**Graduation to Option A (every-push CI):** After **6 consecutive clean runs**, each triggered following a major scanner batch merge (any merge to `main` touching `vibe_iterator/scanners/*.py`), a PR is opened to add a push trigger and graduate e2e to CI.

**Definition of "clean":** all e2e tests pass with zero retries on that run. A single flake or failure resets the counter to 0.

**Stability log:** `tests/e2e/e2e-stability-log.json` — committed to the repo and updated manually after each `workflow_dispatch` run. See Section 6A for the full schema.

Extend `tests/e2e/test_real_browser_smoke.py` with additional opt-in tests gated by `VIBE_ITERATOR_RUN_E2E_SMOKE=1`.

Target scan groups:

| E2E group | Fixture | Scanners | Expected proof |
| --------- | ------- | -------- | -------------- |
| Browser listener smoke | `_SmokeApp` | Network listener only | Browser navigation captures root and API requests through CDP. |
| Generic runtime proof | `VulnerableApp` | `auth_check`, `api_exposure`, `cors_check`, `info_disclosure`, `sql_injection`, `xss_check`, `mass_assignment`, `idor_check`, `http_method_tampering`, `rate_limit_check` | Scan completes, captures requests, and finds representative issues from each selected scanner. |
| Negative-control runtime proof | Hardened fixture mode in `VulnerableApp` or a new `HardenedApp` | `auth_check`, `api_exposure`, `info_disclosure`, `tier_escalation`, `client_tampering` | Public pages, SPA fallback text, dry-run echoes, and unrelated plan copy do not produce findings. |
| Firebase runtime proof | `FirebaseVulnerableApp` | `firebase_auth`, `firebase_firestore`, `firebase_rtdb`, `firebase_storage`, `firebase_functions` | Local Firebase-shaped endpoints produce expected findings without external Firebase calls. |

Acceptance criteria:

- Default `python -m pytest` still skips Selenium/CDP e2e tests unless `VIBE_ITERATOR_RUN_E2E_SMOKE=1`.
- Opt-in e2e run finishes reliably on a developer machine with Chrome installed.
- Each e2e test asserts scanner names, representative finding titles, and at least one `proof_quality` or evidence field where the scanner emits it.
- E2E tests assert the scan runner returns a completed result with at least one request captured.
- `tests/e2e/e2e-stability-log.json` exists and records run #1 before Phase 7B is considered done.

#### Section 6A: E2E Stability Log Schema

File: `tests/e2e/e2e-stability-log.json`

```json
{
  "graduation_status": "option-c",
  "graduation_target": "option-a",
  "consecutive_clean_runs_required": 6,
  "consecutive_clean_runs_achieved": 0,
  "runs": [
    {
      "id": 1,
      "date": "YYYY-MM-DD",
      "commit": "abc1234",
      "trigger": "phase-7b-merge",
      "result": "pass",
      "flaky": false,
      "scanners_covered": ["auth_check", "api_exposure", "cors_check"],
      "notes": ""
    }
  ]
}
```

**Update process:** after each `workflow_dispatch` run, the person who triggered it commits an update to `runs[]` and increments `consecutive_clean_runs_achieved` if clean (resets to 0 on any flake or failure). When the counter reaches 6, `graduation_status` flips to `"option-a-ready"` and a PR is opened to add the push trigger.

**`trigger` values:** use `"phase-7b-merge"`, `"codex-batch-N"`, `"pre-release"`, or `"manual"` to describe what prompted the run.

### Track 2: Firebase Helper Coverage

Extend `tests/test_utils/test_firebase_helpers.py` around uncovered branches and real-world Firebase data shapes. All 8 areas receive equal depth coverage — no triage or deprioritisation.

Target functions and behaviors:

| Helper area | Tests to add |
| ----------- | ------------ |
| `is_closed_local_url` | Open localhost returns `False`, closed localhost returns `True`, cached closed endpoint returns without a second socket attempt, invalid port returns `False`, non-local URL returns `False`. |
| RTDB REST | `rest_rtdb_delete` success, HTTPError, unknown exception, auth query parameter construction, root path handling. |
| Firestore REST | `rest_firestore_get`, `rest_firestore_write`, and `rest_firestore_delete` success/error branches with request URL, method, auth header, and JSON body assertions. |
| Storage REST | `rest_storage_download`, `rest_storage_upload`, and `rest_storage_delete` success/error branches, encoded object names, upload prefix refusal, and auth header construction. |
| Functions REST | Request URL construction for callable function names, bearer token header, JSON body encoding, unknown exception path. |
| Firestore typed values | Scalars, nested maps, arrays, timestamps represented as strings, nulls, and unknown typed values. |
| Firebase detection | `firebaseio.com`, `firebasedatabase.app`, `identitytoolkit.googleapis.com`, `firebasestorage.googleapis.com`, `firebaseapp.com`, duplicate events, and no-signal negative control. |
| Token discovery | Multiple JWTs in one body, invalid JWT-like fragments ignored if helper is tightened. |

Implementation guidance:

- Prefer mocked `urllib.request.urlopen` for REST helper tests.
- Use local fixture HTTP only when it proves URL routing or scanner integration better than mocks.
- If helper behavior changes, keep function names stable so Firebase scanners do not need broad rewrites.

Acceptance criteria:

- `vibe_iterator/utils/firebase_helpers.py` coverage rises from 58% to at least 75%.
- Overall coverage remains at or above 81%.
- No Firebase helper test performs real network egress.

### Track 3: Real-World Tier, Storage, and Auth Edge Fixtures

Extend `tests/fixtures/vulnerable_app/app.py` and `tests/fixtures/vulnerable_app/firebase_app.py` with compact, explicit edge routes.

**All Firebase fixture additions use local HTTP simulation only.** The `firebase_app.py` fixture server returns shaped HTTP responses that match real Firebase REST API response formats. No in-memory state, no real SDK, no real Firebase project required. For write scenarios (e.g., "probe-prefixed document writes succeed"), the fixture responds with a correctly-shaped success response to the probe request — it does not store the write or return it on read. Tests assert the correct request was made and a success response received.

Generic fixture additions:

| Edge area | Fixture behavior |
| --------- | ---------------- |
| Tier structured positive | API response returns `{"subscription": {"tier": "premium"}}` after a simulated tampered request. |
| Tier text negative | API response contains unrelated text such as `"Premium support is available"` without structured tier fields. |
| Tier error negative | RPC-like response contains `"error": "Premium tier function unavailable"` and no matching `data` value. |
| Storage positive | Supabase-shaped storage object routes for `object/public`, `object/sign`, `object/list`, and direct `object/{bucket}` paths. |
| Storage negative | Storage dry-run, preview, and 403 denial routes that must not produce accepted-upload findings. |
| Auth positive | Protected API returns 200 without auth for `/api/protected` and `/api/admin`. |
| Auth negative | Public `/pricing` and `/application` routes, SPA fallback text, and `/api/protected-401` returning 401. |
| Rate-limit control | One endpoint without limits, one endpoint with 429 and `Retry-After`, one endpoint that locks out with 403 after repeated attempts. |

Firebase fixture additions:

| Edge area | Fixture behavior |
| --------- | ---------------- |
| Firestore denied control | `/secured/...` returns `PERMISSION_DENIED` consistently for read/write/delete. |
| Firestore positive write | Probe-prefixed document write receives a correctly-shaped success response. |
| RTDB denied control | `/secured.json` blocks unauthenticated read/write/delete. |
| Storage denied control | `private/` object download rejects without authorization. |
| Storage positive write | Probe-prefixed upload receives a correctly-shaped success response. |
| Auth negative | Anonymous signup disabled response is modeled alongside anonymous signup enabled response. |
| Functions CORS | Reflected credentialed CORS and unauthenticated function execution are modeled separately. |

Acceptance criteria:

- Every new positive fixture route has at least one test proving a scanner reports it.
- Every new negative fixture route has at least one test proving the scanner suppresses it.
- Fixture route names and comments clearly mark intentional vulnerabilities so contributors do not "fix" the fixture.

### Track 4: Docs and README Alignment

Perform docs alignment after Tracks 1–3 pass. Update exactly these sections — no broader rewrites.

| File | What to update |
| ---- | -------------- |
| `README.md` | Update test count to the final Phase 7B verification number. |
| `docs/PHASES.md` | Add Phase 6 entry (false positive hardening, split-origin support, proof quality gates, CI/CD). Add Phase 7B entry once complete. |
| `docs/SCANNERS.md` | Add `proof_quality` vocabulary section: explain what the field means, which values are used, and which scanners emit it. |
| `docs/CONFIG.md` | Add `VIBE_ITERATOR_BACKEND_URL` to the variable table (currently missing). |
| `.env.example` | Verify it matches the final config schema — already updated, confirm no drift. |
| `docs/ADDING_SCANNERS.md` | Add note on proof-quality gates: new scanners must include `proof_quality` in evidence, or document explicitly why it does not apply. |

Acceptance criteria:

- Docs do not promise scanner behavior that tests do not prove.
- README test count matches the final verification run output.
- `docs/SCANNERS.md` describes proof gates for Phase 6/7B hardened scanners.
- `docs/CONFIG.md` is complete for all current env vars.

---

## 7. File Map

Likely modified files:

- `tests/e2e/test_real_browser_smoke.py` — additional opt-in real browser scan tests.
- `tests/e2e/e2e-stability-log.json` — new file; stability tracker for e2e graduation.
- `tests/fixtures/vulnerable_app/app.py` — generic vulnerable and negative-control routes.
- `tests/fixtures/vulnerable_app/firebase_app.py` — Firebase-shaped vulnerable and negative-control routes.
- `tests/test_utils/test_firebase_helpers.py` — helper branch coverage.
- `tests/test_scanners/test_core_runtime_scanners.py` — tier/auth/client tampering edge tests if helper-level tests are not enough.
- `tests/test_scanners/test_bucket_limits.py` — storage route parsing and upload-proof edge tests.
- `tests/test_scanners/test_auth_check_proof.py` — auth route positive/negative proof tests.
- `tests/test_scanners/test_firebase_*_proof.py` — Firebase fixture proof tests.
- `vibe_iterator/utils/firebase_helpers.py` — only if tests expose missing real-world helper behavior.
- `vibe_iterator/scanners/*.py` — only if new tests expose false positives, false negatives, or unsafe cleanup.
- `README.md`, `docs/SCANNERS.md`, `docs/PHASES.md`, `docs/CONFIG.md`, `docs/ADDING_SCANNERS.md`, `.env.example` — final docs alignment.

No new production modules are expected.

---

## 8. Execution Strategy

Recommended implementation order:

1. Create a feature branch from `main`.
2. Add Track 2 Firebase helper tests first because they are fast and low-risk.
3. Add Track 3 fixture edge routes with paired scanner proof tests.
4. Add Track 1 opt-in Selenium/CDP e2e tests once fixture behavior is stable.
5. Create `tests/e2e/e2e-stability-log.json` and record run #1 after e2e passes locally.
6. Run full unit/proof suite and coverage.
7. Run opt-in e2e locally with `VIBE_ITERATOR_RUN_E2E_SMOKE=1`.
8. Run wheel build/install smoke.
9. Update docs using the actual final verification output.

Commit rhythm:

- Commit Firebase helper coverage separately.
- Commit fixture edge routes and scanner proof tests separately by domain.
- Commit e2e tests and stability log separately.
- Commit docs alignment last.

---

## 9. Verification Plan

Required commands before merge:

```bash
python -m pytest -q
python -m pytest --cov=vibe_iterator --cov-report=term-missing
```

Baseline to beat: **438 passed, 2 skipped, coverage ≥ 81%** (`main` at `3b531ac`).

Required opt-in e2e command before release:

```bash
$env:VIBE_ITERATOR_RUN_E2E_SMOKE="1"; python -m pytest tests/e2e -q
```

Required package smoke:

```bash
uv build --wheel --out-dir <temp-dist>
python -m venv <temp-venv>
<temp-venv>/Scripts/python.exe -m pip install <wheel>
<temp-venv>/Scripts/vibe-iterator.exe --help
```

Expected final bar:

- Default suite passes with 0 failures.
- `firebase_helpers.py` coverage ≥ 75%; overall coverage ≥ 81%.
- Opt-in Selenium/CDP e2e passes on a machine with Chrome installed.
- Wheel/install smoke passes from a clean virtual environment.
- `tests/e2e/e2e-stability-log.json` exists and records run #1.

---

## 10. Phase-Done Gate

Phase 7B is complete when **all** of the following are true:

```
[ ] Default suite: python -m pytest -q passes with 0 failures
[ ] Coverage: vibe_iterator/utils/firebase_helpers.py >= 75%
[ ] Coverage: overall >= 81% (no regression from 3b531ac baseline)
[ ] E2E opt-in: VIBE_ITERATOR_RUN_E2E_SMOKE=1 pytest tests/e2e passes cleanly
[ ] Stability log: tests/e2e/e2e-stability-log.json exists and records run #1
[ ] Wheel smoke: fresh venv install + vibe-iterator --help passes
[ ] Docs: README, PHASES.md, SCANNERS.md, CONFIG.md, ADDING_SCANNERS.md all updated
[ ] No scanner proof-quality gates loosened from Phase 6 baseline
```

The stability log only needs **run #1** at phase-done time. The full 6-run graduation to Option A (every-push CI) happens over subsequent Codex batch merges after Phase 7B lands on `main`.

---

## 11. Risks and Controls

| Risk | Control |
| ---- | ------- |
| E2E tests become flaky | Keep them opt-in, local-only, short, and focused on representative findings rather than exhaustive ordering. |
| Fixture routes accidentally call external services | Use `127.0.0.1` fixtures and mocked `urlopen`; assert no real Firebase/Supabase host is reached in tests that should be hermetic. |
| Coverage-driven tests become shallow | Require branch tests to assert request method, URL, headers, body, status, and evidence shape, not only line execution. |
| More realistic fixtures reveal scanner bugs | Treat that as success. Fix scanners with targeted tests and preserve Phase 6 proof gates. |
| Docs drift again | Docs alignment is last and must use the final verification output. |
| E2E graduation never happens (Option C becomes Option B) | Stability log tracks consecutive clean runs — counter is visible in the repo and blocks graduation until 6 clean runs are recorded. |

---

## 12. Approval Gate

This spec is approved. Next step: create a detailed implementation plan at:

`docs/superpowers/plans/YYYY-MM-DD-phase-7b-verification-depth.md`

The implementation plan must use checkbox tasks, exact files, failing tests first, verification commands, and frequent commits following the execution strategy in Section 8.
