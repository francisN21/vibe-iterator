# STANDARDS.md — Coding Standards, Design Decisions & Guardrails

## Coding Standards

- **Python 3.11+** — use modern syntax (match/case, type hints, dataclasses)
- **Type hints everywhere** — all function signatures must have type annotations
- **Docstrings** — every public class and method gets a one-liner at minimum
- **No hardcoded values** — everything configurable via `.env` or YAML
- **Each scanner is independent** — scanners must not depend on each other's results
- **Evidence is mandatory** — every Finding must include raw evidence (not just a description)
- **LLM prompts are first-class** — every Finding must include a ready-to-paste prompt
- **Fail gracefully** — if a scanner errors, log it and continue to the next. Never crash the whole scan
- **No external services required** — the tool runs 100% locally (no cloud APIs, no accounts needed beyond the target app)
- **GUI is optional** — the scan engine must work identically in headless CLI mode. The GUI is a presentation layer, not a dependency
- **No Node.js / no build step** — the dashboard frontend is vanilla HTML/CSS/JS served by FastAPI. No npm, no webpack, no React. This keeps installation to `pip install vibe-iterator` only

---

## Design Decisions

### 1. CDP over proxy
We use Chrome DevTools Protocol directly via Selenium 4's CDP support instead of setting up a proxy (mitmproxy). This is simpler to configure, doesn't require cert installation, and gives us everything we need (network inspection, console capture, JS execution, storage access).

### 2. FastAPI + vanilla frontend over Electron/React
No build step. No Node.js. The dashboard is vanilla HTML/CSS/JS served by a lightweight FastAPI server. This means `pip install vibe-iterator` is the ONLY install step. The hacker aesthetic is achieved through CSS, not a framework.

### 3. WebSocket for real-time updates
The scan engine emits events via a callback. In GUI mode, that callback pushes events through WebSocket to the browser. In CLI mode, it prints to stdout. Same engine, two interfaces.

### 4. Dual-mode CLI
`vibe-iterator` (no flags) launches the GUI dashboard. `vibe-iterator scan --headless` runs the scan without a GUI and outputs the report file. Power users get CLI, vibe coders get the pretty dashboard.

### 5. Scanner plugin architecture
Each scanner is a standalone module extending `BaseScanner`. This makes it trivial for contributors to add new scanners without touching core code. The scanner just needs to implement `run()` and return `Finding` objects.

### 6. LLM-prompt-first reporting
The primary output isn't just "you have a vulnerability" — it's "here's exactly what to paste into your AI to fix it." This is the key differentiator for the vibe-coder audience.

### 7. Supabase-first, stack-agnostic architecture
We start with Supabase-specific scanners (RLS, buckets, tiers) but the base architecture supports any backend. Firebase, custom APIs, etc. can be added as scanner modules without changing the core.

### 8. Manual crawl over automatic spidering
For v1, the user defines which pages to visit in the config. This is intentional — it keeps the tool predictable and avoids crawling into destructive actions. Automatic spidering is a future enhancement.

### 9. Exportable report as secondary output
The primary experience is the live dashboard. The exportable single-file HTML report is a portable snapshot of the same data — for sharing, archiving, or environments where you can't run the GUI.

---

## Guardrails

### What this tool MUST do
- Run entirely locally — no data leaves the user's machine
- Work against localhost targets during development
- Work against live URLs for post-deployment scanning
- Produce actionable, copy-pasteable fix prompts for every finding
- Fail gracefully — one scanner crash never takes down the whole scan
- Be installable with a single `pip install` command

### What this tool MUST NOT do
- Modify the target application's data in any destructive way (read-only where possible, use test accounts for writes)
- Store or transmit user credentials anywhere beyond the local `.env` file
- Require external API keys or cloud services to function
- Auto-update or phone home
- Run scanners that aren't included in the selected stage profile
- Produce findings without evidence — no guessing, no "this might be vulnerable"

### Security of the tool itself
- The `.env` file must be in `.gitignore` by default
- The `.env.example` must never contain real credentials
- The dashboard on `localhost:3001` must only bind to `127.0.0.1` (not `0.0.0.0`) to prevent network exposure
- The WebSocket endpoint (`/ws`) has no token auth — this is acceptable because of the `127.0.0.1` binding. Never relax the bind address
- Test credentials should be for dedicated test accounts, never production accounts
- The exported HTML report may contain sensitive evidence (request bodies, tokens, screenshots) — the tool must display a warning before export and in the report header

---

## Browser Session Rules

- One Chrome instance per scan run — never launch a new browser per scanner
- Scanners that modify client state (localStorage, cookies, URL, session) **must restore original state in a `try/finally` block** before returning
- The primary test account is authenticated once at scan start by the engine — scanners must not log out without re-authenticating before returning
- The second test account (`account=2`) is managed by the scanner that needs it — it calls `auth.login(account=2)` before cross-user tests and `auth.login(account=1)` to restore the primary session afterward
- If a scanner navigates to a different page as part of a test, it must navigate back to the original URL before returning

---

## Testing Standards

- Every scanner module must have a corresponding test file in `tests/test_scanners/`
- Tests must not require a live browser — use mock CDP responses and mock network events
- Scanner tests must verify: (a) findings are returned when vulnerability is present, (b) empty list returned when vulnerability is absent, (c) no exception raised when target is unresponsive
- Engine tests must verify: event emission sequence, error recovery (scanner throws), result storage, 409 on concurrent scan attempt
- Target coverage: ≥80% on `scanners/`, `engine/`, `listeners/` modules
