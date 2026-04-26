# PHASES.md — Build Phases

## Phase 1 — Foundation (Crawl Before You Run)

**Goal:** Selenium launches localhost, authenticates, and can visit pages. CDP listeners capture network traffic and console output. Basic FastAPI server serves a placeholder dashboard.

Build in this order:
1. `pyproject.toml` — project metadata, dependencies, CLI entry point (see `STACK.md` for full content spec)
2. `.env.example` — document all expected env vars with inline comments explaining each
3. `.gitignore` — exclude `.env`, `__pycache__/`, `.pytest_cache/`, `*.pyc`, `*.egg-info/`, `dist/`, `.vibe-iterator/`, `vibe-iterator-report-*.html`, `screenshots/`
4. `__init__.py` files — create empty `__init__.py` in every package: `vibe_iterator/`, `vibe_iterator/server/`, `vibe_iterator/crawler/`, `vibe_iterator/scanners/`, `vibe_iterator/listeners/`, `vibe_iterator/engine/`, `vibe_iterator/evidence/`, `vibe_iterator/report/`, `vibe_iterator/utils/`
5. `config.py` — load `.env` and YAML config, validate required fields, expose typed `Config` dataclass to all modules
6. `cli.py` — dual-mode: `vibe-iterator` launches GUI server, `vibe-iterator scan --headless` runs CLI-only. Define all final flags now (`--target`, `--stage`, `--port`, `--verbose`, `--output`, `--no-browser`) but stub non-essential ones as no-op — they are fully wired in Phase 5
7. `server/app.py` — FastAPI app that serves static HTML on `localhost:3001`, placeholder pages. **Bind to `127.0.0.1` only — never `0.0.0.0`**
8. `crawler/browser.py` — launch Chrome with CDP enabled, return a session object. One browser instance is created per scan run and **shared across all scanners** — never restarted mid-scan
9. `crawler/auth.py` — implement `login(account: int = 1)` supporting both primary account (`VIBE_ITERATOR_TEST_EMAIL`) and optional second account (`VIBE_ITERATOR_TEST_EMAIL_2`). Second account silently skipped if not configured. Authentication happens once at scan start, not per-scanner
10. `crawler/navigator.py` — visit a list of URLs from config, wait for page load, return page metadata
11. `listeners/network.py` — attach CDP Network listener, log all request/response pairs including headers and bodies
12. `listeners/console.py` — attach CDP Console listener, capture all console output with level (log/warn/error)
13. `listeners/storage.py` — read localStorage, sessionStorage, cookies after each page visit

**Done when:** `vibe-iterator` opens a browser to `localhost:3001` showing a placeholder dashboard, AND Selenium can launch, authenticate (primary + second account), crawl pages, and dump captured network/console/storage data as JSON.

**Tests (Phase 1):** `tests/conftest.py` with shared fixtures (mock config, mock browser session). `tests/test_listeners/` with unit tests for network, console, and storage listeners using mock CDP events.

---

## Phase 2 — Scan Engine + Core Scanners

**Goal:** Build the scan orchestrator and implement the Supabase-focused scanners. Each scanner extends `BaseScanner` and returns structured findings. Engine emits events via callbacks.

Build in this order:
1. `scanners/base.py` — define `BaseScanner` with `run(browser, listeners, config) → list[Finding]` interface and `Finding` dataclass. Scanners are **synchronous** — the engine bridges to async via `asyncio.to_thread()` (see `ENGINE.md`)
2. `engine/runner.py` — `ScanRunner` class: stores live `ScanResult` on `self._result` (in-memory, returned via `get_result()`), loads scanners by stage, runs each via `asyncio.to_thread()` to keep WebSocket alive, emits `ScanEvent` objects via callback. Only one scan can run at a time
3. `utils/supabase_helpers.py` — shared utilities used by Supabase-specific scanners: CDP `Runtime.evaluate` snippet builders for Supabase JS client calls, PostgREST URL parser, session token extractor, PostgREST error response detector (see `SCANNERS.md` for full function list)
4. `scanners/data_leakage.py` — scan network responses and console for exposed keys, JWTs, UUIDs, PII
5. `scanners/rls_bypass.py` — attempt unauthorized Supabase table queries via CDP `Runtime.evaluate`. Uses `utils/supabase_helpers.py`. Uses second test account (if configured) for cross-user data access checks
6. `scanners/tier_escalation.py` — read/modify subscription tier client-side, attempt tier-gated actions. Uses `utils/supabase_helpers.py`
7. `scanners/bucket_limits.py` — attempt uploads exceeding plan allowance, verify server-side rejection. Uses `utils/supabase_helpers.py`
8. `scanners/auth_check.py` — EXTENSIVE: 6 check groups covering token security, session management, login security, password/account security, auth bypass vectors, and OAuth (see `SCANNERS.md` for full breakdown). Uses second test account for concurrent session and cross-user tests if configured
9. `scanners/client_tampering.py` — modify localStorage/cookie values for role/permissions, check server trust. **Must restore all original values in a `try/finally` block before returning**
10. `scanners/sql_injection.py` — EXTENSIVE: 6 check groups covering Supabase/PostgREST-specific injection, classic SQLi, blind injection, ORM bypass, input vector discovery, and post-exploitation indicators (see `SCANNERS.md` for full breakdown)
11. `evidence/collector.py` — capture screenshots, request/response pairs, tampered-vs-original value diffs, and console log snapshots
12. `report/prompt_builder.py` — generate structured, copy-pasteable LLM prompts per Finding with full context and evidence embedded

**Done when:** Running `vibe-iterator scan --headless --stage dev` executes scanners, prints events to stdout, and each scanner produces structured `Finding` objects with severity, evidence, and LLM prompts. All state-modifying scanners leave the browser in original state after running.

**Tests (Phase 2):** `tests/test_scanners/test_base.py` (Finding dataclass validation, BaseScanner contract), `tests/test_scanners/test_data_leakage.py` (mock network responses with injected secrets), `tests/test_scanners/test_client_tampering.py` (verify state restore), `tests/test_engine/test_runner.py` (event emission, error recovery, result storage).

---

## Phase 3 — Live Dashboard GUI

**Goal:** Build the full hacker-themed dashboard with real-time scan progress and results display. This is the "wow factor" phase. See `docs/DASHBOARD.md` for full UI specification.

Build in this order:
1. `server/websocket.py` — WebSocket connection manager, broadcast scan events to all connected clients
2. `server/routes.py` — REST API: `POST /api/scan/start` (accepts `{ stage, scanner_overrides? }`), `DELETE /api/scan/active` (cancel running scan), `GET /api/scan/results`, `GET /api/scan/results/{finding_id}`, `GET /api/report/export`, `GET /api/config`
3. Wire `ScanRunner` to WebSocket — on_event callback pushes `ScanEvent` JSON to all WebSocket clients
4. `server/static/css/dashboard.css` — full hacker-themed dark UI (see DASHBOARD.md Visual Language section)
5. `server/static/js/websocket.js` — WebSocket client that receives events and dispatches to UI update functions
6. `server/static/index.html` — Dashboard Home: stage selector cards, config summary, START SCAN button
7. `server/static/js/app.js` — Dashboard interaction: stage selection, scan launch (POST to API), page navigation
8. `server/static/scan.html` — Live Scan Progress: split-panel terminal feed + live findings feed
9. `server/static/results.html` — Results Dashboard: executive summary, findings by category, COPY FIX PROMPT buttons
10. `server/static/js/clipboard.js` — copy-to-clipboard for LLM prompts with toast notifications
11. Wire `POST /api/scan/start` to return `409 Conflict` if a scan is already in progress — prevents concurrent scans from corrupting in-memory results
12. Note: `GET /api/scan/results/{finding_id}` route is built here (data layer ready) but the frontend deep-dive page is deferred to Phase 5

**Done when:** Running `vibe-iterator` opens the browser to `localhost:3001`, user selects a stage, clicks START SCAN, watches real-time terminal output and findings appear live, then transitions to a full results dashboard where they can explore findings and copy LLM fix prompts.

**Tests (Phase 3):** `tests/test_server/test_routes.py` (start scan, get results, 409 on double-start, config endpoint), `tests/test_server/test_websocket.py` (event broadcast to connected clients, reconnect behavior).

---

## Phase 4 — Exportable Report + Extended Scanners

**Goal:** Add the standalone HTML export and broader web security scanners.

Build in this order:
1. `report/templates/report.html.j2` — self-contained HTML with all CSS/JS inlined (no external CDN, no WebSocket). Structure: executive summary block (score/grade, severity bar, key stats), findings by category (collapsible sections, same card layout as dashboard), passed checks section. `report/generator.py` inlines all `<style>` and `<script>` content at render time using Jinja2 so the output is a single portable `.html` file
2. `report/generator.py` — render Jinja2 template with `ScanResult`, read CSS/JS from `server/static/` and inline them, write output to `vibe-iterator-report-{timestamp}.html`. Must produce a valid self-contained file with no broken references
3. Wire export to dashboard — "EXPORT REPORT" button triggers download via `/api/report/export`. Button is disabled until a scan has completed
4. `scanners/cors_check.py` — test CORS headers with cross-origin requests, null origin, reflected origin, credentials with wildcard
5. `scanners/xss_check.py` — reflected, stored, and DOM-based XSS, template injection, SVG/event handler injection, CSP header evaluation
6. `scanners/api_exposure.py` — discover and test API endpoints for missing auth, mass assignment, rate limiting on sensitive routes, HTTP verb tampering, security response headers

**Done when:** Users can export a polished standalone HTML report from the dashboard that opens correctly with no internet connection, and the tool covers the full security methodology.

**Tests (Phase 4):** `tests/test_scanners/test_cors_check.py`, `tests/test_scanners/test_xss_check.py`, `tests/test_scanners/test_api_exposure.py`, `tests/test_report/test_generator.py` (verify report renders with all finding types, verify output is self-contained — no external URLs in the generated HTML).

---

## Phase 5 — Polish & Open Source Release

**Goal:** Final polish, stage profiles, packaging, and open-source readiness.

Build in this order:
1. Stage profiles in config — verify dev/pre-deploy/post-deploy/all each select the correct scanners; test each profile end-to-end
2. `vibe-iterator.config.yaml` — full config schema with technology auto-detection (see `CONFIG.md` for auto-detection logic)
3. Finding deep dive page (`server/static/results/{finding_id}.html` or JS-rendered at `results.html#finding_id`) — full evidence view (request/response chain, screenshot carousel, storage state diff), network timeline, related findings, variant LLM prompts for Claude/ChatGPT/Copilot. The API route (`GET /api/scan/results/{finding_id}`) was built in Phase 3 — this step is the frontend only
4. CLI polish — fully implement flags stubbed in Phase 1: `--verbose` streams events to stdout even in GUI mode, `--output <path>` saves report to specified file, `--port <n>` overrides default 3001, `--no-browser` suppresses auto-open of dashboard on launch
5. Error handling — graceful degradation: target unreachable at startup (clear error, no scan starts), scanner timeout (configurable, default 60s per scanner), CDP disconnect mid-scan (emit `scan_error`, attempt cleanup, exit cleanly), missing optional config (warn, skip affected scanners)
6. Scanner state safety audit — verify every scanner that touches localStorage/cookies/navigation restores state correctly; add integration test that runs all scanners sequentially and asserts browser state is identical before and after
7. README.md — setup instructions (Chrome requirement, `pip install`, `.env` creation), demo GIF or screenshot, quick start (5 commands to first scan), architecture diagram, FAQ
8. `docs/ADDING_SCANNERS.md` — step-by-step contributor guide: extend BaseScanner, implement run(), declare stages, write tests, register in config
9. PyPI packaging — verify `pip install vibe-iterator` works cleanly in a fresh virtualenv, `vibe-iterator --version` works, all entry points resolve
10. LICENSE (MIT)
11. Final test suite pass — run full test suite, target ≥80% coverage on scanner and engine modules

**Done when:** A vibe coder can `pip install vibe-iterator`, create a `.env`, run `vibe-iterator`, and get a stunning hacker-themed dashboard where they select a stage, watch the scan live, explore findings with full evidence, copy fix prompts, and export a self-contained report — all in under 5 minutes from install.
