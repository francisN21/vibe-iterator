# Phase 8 Scanner Family Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add robust runtime scanners for the Phase 8 missing web-app exploit families, one family at a time, with fixture proof tests, registry/config/UI exposure, docs alignment, and frequent commits.

**Architecture:** Each exploit family is implemented as a focused scanner module using the existing `BaseScanner` contract. The vulnerable fixture app provides deterministic local proof routes, while config/server metadata make every scanner visible and selectable through the existing dynamic dashboard stage UI.

**Tech Stack:** Python 3.11, pytest, FastAPI route metadata, Selenium/CDP listener inputs, local `ThreadingHTTPServer` vulnerable fixtures.

**Status:** Implemented on `codex/firebase-stage-config-alignment`. Final verification snapshot: `python -m pytest -q` reports 613 passed, 4 skipped; `python -m pytest --cov=vibe_iterator --cov-report=term-missing` reports 613 passed, 4 skipped, 84% total coverage; scanner exposure matrix reports 30 registered scanners, 30 preset-visible scanners, and no missing mappings/metadata.

---

### Task 1: Open Redirect Scanner

**Files:**
- Create: `vibe_iterator/scanners/open_redirect_check.py`
- Create: `tests/test_scanners/test_open_redirect_check.py`
- Modify: `tests/fixtures/vulnerable_app/app.py`
- Modify: `vibe_iterator/engine/runner.py`
- Modify: `vibe_iterator/config.py`
- Modify: `vibe_iterator/server/routes.py`
- Modify: `docs/SCANNERS.md`, `docs/CONFIG.md`, `README.md`

- [ ] Write failing tests for open redirect detection on `/api/redirect?next=https://evil.example/phish`.
- [ ] Write negative tests for same-origin relative redirects and non-redirect 200 responses.
- [ ] Add fixture route with vulnerable external redirect and safe same-origin redirect.
- [ ] Implement bounded scanner that discovers redirect parameters from captured requests and probes absolute external URLs.
- [ ] Register scanner in runner/config/server metadata.
- [ ] Run targeted tests and scanner exposure matrix.
- [ ] Commit: `feat: add open redirect scanner`

### Task 2: Path Traversal Scanner

**Files:**
- Create: `vibe_iterator/scanners/path_traversal_check.py`
- Create: `tests/test_scanners/test_path_traversal_check.py`
- Modify: `tests/fixtures/vulnerable_app/app.py`
- Modify registry/config/server/docs files.

- [ ] Write failing tests for `/api/file?path=../../.env` returning environment-style secrets.
- [ ] Write negative tests for static assets, safe file ids, and 404/403.
- [ ] Add fixture route with sensitive file response and safe control.
- [ ] Implement scanner with bounded traversal payloads and sensitive-file signature proof.
- [ ] Register, expose, document, verify, and commit.

### Task 3: SSRF Scanner

**Files:**
- Create: `vibe_iterator/scanners/ssrf_check.py`
- Create: `tests/test_scanners/test_ssrf_check.py`
- Modify fixture, registry/config/server/docs files.

- [ ] Write failing tests for URL-bearing endpoint accepting loopback/private URL probes.
- [ ] Write negative tests for blocked private targets and non-URL parameters.
- [ ] Add fixture route returning structured server-side fetch evidence.
- [ ] Implement scanner using local/private URL payloads only; no external callbacks.
- [ ] Register, expose, document, verify, and commit.

### Task 4: CSRF Scanner

**Files:**
- Create: `vibe_iterator/scanners/csrf_check.py`
- Create: `tests/test_scanners/test_csrf_check.py`
- Modify fixture, registry/config/server/docs files.

- [ ] Write failing tests for state-changing endpoint accepting cross-site request without CSRF token.
- [ ] Write negative tests for endpoints requiring CSRF token, rejecting bad origin, or returning 401/403.
- [ ] Add fixture route `/api/csrf-transfer`.
- [ ] Implement scanner over captured POST/PATCH/PUT/DELETE requests using untrusted `Origin`.
- [ ] Register, expose, document, verify, and commit.

### Task 5: GraphQL Scanner

**Files:**
- Create: `vibe_iterator/scanners/graphql_check.py`
- Create: `tests/test_scanners/test_graphql_check.py`
- Modify fixture, registry/config/server/docs files.

- [ ] Write failing tests for unauthenticated introspection and unauthenticated data query.
- [ ] Write bounded depth-abuse test with small, deterministic payload.
- [ ] Add fixture `/graphql`.
- [ ] Implement scanner that discovers `/graphql` requests and probes introspection/data/depth safely.
- [ ] Register, expose, document, verify, and commit.

### Task 6: Webhook Scanner

**Files:**
- Create: `vibe_iterator/scanners/webhook_check.py`
- Create: `tests/test_scanners/test_webhook_check.py`
- Modify fixture, registry/config/server/docs files.

- [ ] Write failing tests for unsigned webhook accepted.
- [ ] Write negative tests for 401/403 on missing or invalid signature.
- [ ] Add fixture `/api/webhooks/stripe`.
- [ ] Implement scanner for webhook-like paths with invalid signature payloads.
- [ ] Register, expose, document, verify, and commit.

### Task 7: WebSocket Scanner

**Files:**
- Create: `vibe_iterator/scanners/websocket_check.py`
- Create: `tests/test_scanners/test_websocket_check.py`
- Modify fixture or create a minimal local WebSocket fixture if standard library HTTP fixture cannot support upgrade cleanly.
- Modify registry/config/server/docs files.

- [ ] Write failing tests for unauthenticated or untrusted-origin WebSocket acceptance.
- [ ] Write negative tests for auth/origin rejection.
- [ ] Implement scanner with optional dependency fallback behavior if WebSocket client library is unavailable.
- [ ] Register, expose, document, verify, and commit.

### Task 8: Unsafe Payload Scanner

**Files:**
- Create: `vibe_iterator/scanners/unsafe_payload_check.py`
- Create: `tests/test_scanners/test_unsafe_payload_check.py`
- Modify fixture, registry/config/server/docs files.

- [ ] Write failing tests for SSTI marker evaluation such as `{{7*7}} -> 49`.
- [ ] Write tests for unsafe deserialization/parser error signatures without dangerous payloads.
- [ ] Add fixture `/api/render`.
- [ ] Implement harmless marker probes and parser-error proof classification.
- [ ] Register, expose, document, verify, and commit.

### Task 9: Generic File Upload Scanner

**Files:**
- Create: `vibe_iterator/scanners/file_upload_check.py`
- Create: `tests/test_scanners/test_file_upload_check.py`
- Modify fixture, registry/config/server/docs files.

- [ ] Write failing tests for accepted executable extension, dangerous MIME, polyglot SVG/HTML, and EICAR-style harmless malware test string.
- [ ] Write negative tests for blocked uploads and dry-run/preview echoes.
- [ ] Add fixture `/api/upload`.
- [ ] Implement bounded upload probes and cleanup/no-persistence expectations.
- [ ] Register, expose, document, verify, and commit.

### Task 10: Final Phase 8 Verification

**Files:**
- Modify: `README.md`, `docs/SCANNERS.md`, `docs/CONFIG.md`, `MEMORY.md` or baton-pass notes if present.

- [x] Run `python -m pytest -q`.
- [x] Run `python -m pytest --cov=vibe_iterator --cov-report=term-missing`.
- [x] Run scanner exposure matrix script.
- [x] Refresh graphify after code changes.
- [x] Commit final docs/coverage alignment.
