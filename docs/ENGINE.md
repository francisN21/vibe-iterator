# ENGINE.md — Scan Engine Architecture

## Overview

The scan engine (`engine/runner.py`) is the orchestrator that ties everything together. It is **decoupled from both the CLI and the GUI** — it accepts a callback function for emitting events, which the server's WebSocket handler or the CLI's stdout printer can both use.

## ScanRunner Class

```python
class ScanRunner:
    """Orchestrates the full scan lifecycle."""

    def __init__(
        self,
        config: Config,
        on_event: Callable[[ScanEvent], None],
        scanner_overrides: list[str] | None = None,
    ):
        self.config = config
        self.on_event = on_event           # GUI → WebSocket, CLI → stdout
        self.scanner_overrides = scanner_overrides  # session-only list from POST /api/scan/start
        self._cancel_requested: bool = False
        self._active_task: asyncio.Task | None = None
        self._result: ScanResult | None = None

    def cancel(self) -> None:
        """Request cancellation. Engine stops after the current scanner finishes."""
        self._cancel_requested = True
        if self._active_task:
            self._active_task.cancel()

    def get_result(self) -> ScanResult | None:
        return self._result

    async def run(self, stage: str) -> ScanResult:
        """Execute all scanners for the given stage."""
        # 1. Resolve scanner list:
        #    a. Load scanners for stage from config
        #    b. If scanner_overrides is set, intersect — validate all names are valid for stage
        #       (invalid name → 400 with valid name list, raised before scan starts)
        # 2. Emit scan_started { stage, target, scanner_count, scanner_names, pages }
        # 3. Launch browser with CDP
        # 4. Emit scanner_progress { scanner_name: "auth", message: "Authenticating as t***@...", level: "info" }
        # 5. auth.login(account=1)
        # 6. Emit scanner_progress { message: "✓ Authentication successful", level: "info" }
        # 7. Crawl all pages from config; emit page_navigated per page
        # 8. For each scanner in resolved list:
        #    a. If scanner.requires_stack not in [config.stack.backend, "any"]:
        #          emit scanner_skipped { scanner_name, reason: "Requires {stack} — not detected" }
        #          record ScannerResult(status="skipped", skip_reason=...), continue
        #    b. If scanner.requires_second_account and not config.second_account_configured:
        #          emit scanner_skipped { scanner_name, reason: "Requires second test account — not configured" }
        #          record ScannerResult(status="skipped", ...), continue
        #    c. If self._cancel_requested:
        #          emit scan_cancelled { scanner_name_at_cancel, findings_so_far }; break
        #    d. Emit scanner_started { scanner_name, category, index, total }
        #    e. start_time = time.monotonic()
        #    f. Run via asyncio.to_thread(scanner.run, ...) with timeout=config.scanner_timeout_seconds
        #       - Timeout → emit scan_error(error_type="scanner_timeout", recoverable=True)
        #                    record ScannerResult(status="timeout"), continue
        #       - Exception → emit scan_error(error_type="scanner_exception", recoverable=True)
        #                     record ScannerResult(status="error"), continue
        #    g. For each Finding: set fingerprint = sha256(scanner+title+page)[:16]; emit finding event
        #    h. duration = time.monotonic() - start_time
        #       outcome = "passed" if not findings else "findings"
        #       emit scanner_completed { scanner_name, outcome, findings_count, duration_seconds }
        #    i. Record ScannerResult(status=outcome, duration_seconds=duration, ...)
        # 9. Compute score (see Score Computation section)
        # 10. Emit scan_completed or scan_cancelled
        # 11. self._result = completed ScanResult; return it
        # [finally] browser.quit() — always, even on cancel or error
```

## Dual-Mode Design

The same engine powers both interfaces:

- **`vibe-iterator`** (GUI mode) → FastAPI starts on `localhost:3001`, serves dashboard, WebSocket broadcasts `ScanEvent` objects to connected browser clients
- **`vibe-iterator scan --headless`** (CLI mode) → `on_event` callback prints formatted events to stdout, saves report file on completion

Same engine, same scanners, same results — two presentation layers.

## WebSocket Event Protocol

The scan engine emits events that the WebSocket broadcasts to all connected dashboard clients.

```python
@dataclass
class ScanEvent:
    type: str          # Event type (see below)
    timestamp: str     # ISO 8601
    data: dict         # Event-specific payload
```

### Event Types

| Type | Payload | When |
|------|---------|------|
| `scan_started` | `{ stage, target, scanner_count, scanner_names: list[str], pages: list[str] }` | Scan begins — `scanner_names` lets frontend build progress bar segments upfront |
| `scanner_started` | `{ scanner_name, category, index, total }` | Each scanner starts |
| `scanner_progress` | `{ scanner_name, message, level }` | Scanner/auth sends status (level: `"info"` \| `"warning"` \| `"error"`) |
| `finding` | `{ finding_id, fingerprint, scanner, severity, title, description, category, page }` | Vulnerability discovered — includes `page` URL and stable `fingerprint` |
| `scanner_completed` | `{ scanner_name, outcome, findings_count, duration_seconds }` | Each scanner finishes — `outcome`: `"passed"` \| `"findings"` \| `"timeout"` \| `"error"` |
| `scanner_skipped` | `{ scanner_name, reason }` | Scanner skipped (stack mismatch, missing account, etc.) |
| `page_navigated` | `{ url, status_code }` | Crawler visits a page |
| `scan_completed` | `{ total_findings, by_severity, duration_seconds, score, score_grade, scanners_run, scanners_skipped }` | Entire scan finishes |
| `scan_cancelled` | `{ scanner_name_at_cancel, findings_so_far, duration_seconds }` | User cancelled scan |
| `scan_error` | `{ error_type, error, scanner_name?, recoverable }` | Error occurs — `error_type`: `"cdp_disconnected"` \| `"target_unreachable"` \| `"scanner_timeout"` \| `"scanner_exception"` \| `"browser_crash"` |

The dashboard JS receives these events and updates the UI in real time — appending terminal lines, adding finding cards, updating the progress bar and counters.

## Server API Routes

| Method | Route | Purpose |
|--------|-------|---------|
| `POST` | `/api/scan/start` | Body: `{ stage: str, scanner_overrides?: list[str] }`. Returns `409` if scan already running, `400` if scanner names invalid |
| `DELETE` | `/api/scan/active` | Cancel running scan. Calls `runner.cancel()`, emits `scan_cancelled`, sets status `"cancelled"`. Returns `404` if no scan running |
| `GET` | `/api/scan/results` | Full `ScanResult` including `scanner_results`, `pages_crawled`, `requests_captured`, `stack_detected`. Available after completion, cancellation, or error |
| `GET` | `/api/scan/results/{finding_id}` | Single `Finding` with full evidence dict and `screenshots` list |
| `POST` | `/api/scan/findings/mark` | Body: `{ findings: [{ finding_id: str, status: "resolved"\|"accepted_risk"\|"false_positive"\|"none", note?: str }] }`. Stores marking on `ScanResult` so report export reflects it |
| `GET` | `/api/report/export` | Download self-contained HTML report with marking state applied. Returns `404` if no completed scan (partial cancelled scans are not exportable in v1) |
| `GET` | `/api/config` | Returns full config response (see Config API Response below) |
| `WS` | `/ws` | WebSocket endpoint for live scan events |

## Error Handling

- If a scanner throws an exception, the engine catches it, emits a `scan_error` event with `recoverable: true`, and continues to the next scanner
- If the browser crashes or CDP disconnects, the engine emits `scan_error` with `recoverable: false` and stops the scan gracefully
- If the target is unreachable at scan start, the engine emits `scan_error` immediately and does not proceed
- The dashboard shows errors inline in the terminal feed (red text) and in the findings feed (error card)
- Each scanner has a configurable timeout (default: 60 seconds). If exceeded, the engine cancels the thread, emits `scan_error` with `recoverable: true`, and moves on

---

## Result Storage

`ScanRunner` stores the live result in memory on `self._result: ScanResult | None`. The FastAPI app holds a single shared `ScanRunner` instance. The `/api/scan/results` route calls `runner.get_result()`.

**Concurrency:** Only one scan can run at a time. `POST /api/scan/start` returns `409 Conflict` if `self._result` is in a running state. The result persists in memory until a new scan is started.

**Persistence:** Results are not written to disk by default in v1. If the server process is killed, results are lost. A future enhancement can write `self._result` as JSON to `.vibe-iterator/last-scan.json` after each completed scan for crash recovery.

```python
@dataclass
class ScannerResult:
    scanner_name: str
    status: str              # "passed" | "findings" | "skipped" | "timeout" | "error"
    findings_count: int
    duration_seconds: float | None
    skip_reason: str | None  # populated when status == "skipped"

@dataclass
class FindingMark:
    finding_id: str
    status: str              # "resolved" | "accepted_risk" | "false_positive" | "none"
    note: str | None

@dataclass
class ScanResult:
    scan_id: str                          # uuid4
    stage: str
    target: str
    status: str                           # "running" | "completed" | "error" | "cancelled"
    started_at: str                       # ISO 8601
    completed_at: str | None
    findings: list[Finding]
    scanner_results: list[ScannerResult]  # ordered by execution order — use list, not dict
    finding_marks: list[FindingMark]      # populated via POST /api/scan/findings/mark
    score: int | None                     # 0–100, None if cancelled or error
    score_grade: str | None               # "A"|"B"|"C"|"D"|"F", None if no score
    duration_seconds: float | None
    pages_crawled: list[dict]             # [{ "url": str, "status_code": int }]
    requests_captured: dict               # { "total": int, "GET": int, "POST": int, "PUT": int, "DELETE": int, "PATCH": int }
    stack_detected: str                   # "supabase" | "firebase" | "custom"
    stack_detection_source: str           # "auto-detected" | "manually-configured"
    second_account_used: bool
    scanner_overrides_applied: list[str] | None
```

---

## Score Computation

Computed by `ScanRunner` after all scanners complete. `None` if scan was cancelled or ended in error.

```python
SEVERITY_DEDUCTIONS = { "critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0 }

# Maximum possible deduction per stage (used for normalization)
STAGE_MAX_DEDUCTIONS = {
    "dev":        60,   # 3 scanners
    "pre-deploy": 200,  # 9 scanners
    "post-deploy": 120, # 6 scanners
    "all":        250,  # 10 scanners
}

GRADE_THRESHOLDS = [(90, "A"), (75, "B"), (60, "C"), (45, "D"), (0, "F")]

def compute_score(findings: list[Finding], stage: str) -> tuple[int, str]:
    raw_deduction = sum(SEVERITY_DEDUCTIONS[f.severity.value] for f in findings)
    stage_max = STAGE_MAX_DEDUCTIONS.get(stage, 200)
    # Normalize: apply deduction proportionally against stage baseline
    normalized_deduction = min(100, int((raw_deduction / stage_max) * 100))
    score = max(0, 100 - normalized_deduction)
    grade = next(g for threshold, g in GRADE_THRESHOLDS if score >= threshold)
    return score, grade
```

Skipped and timed-out scanners do not reduce the stage max — the max is based on the scanners that actually ran plus those that completed with findings.

---

## Config API Response

`GET /api/config` returns this structure. The `scanners` block is computed from: detected/configured stack + whether second account is configured. This enables the dashboard to dim scanner pills before a scan starts.

**Note:** For auto-detected stack, scanner availability reflects the *last known* detection state (from previous scan or from YAML if manually set). On first run with no YAML stack setting, all Supabase-specific scanners show `available: false` until a scan completes and populates detection.

```json
{
  "target": "http://localhost:3000",
  "target_reachable": true,
  "pages": ["/", "/login", "/dashboard", "/profile"],
  "stack": {
    "backend": "supabase",
    "auth": "supabase-auth",
    "storage": "supabase",
    "detection_source": "manually-configured"
  },
  "second_account_configured": true,
  "credentials": {
    "primary_set": true,
    "secondary_set": true
  },
  "scanners": {
    "data_leakage":     { "available": true,  "skip_reason": null },
    "rls_bypass":       { "available": true,  "skip_reason": null },
    "tier_escalation":  { "available": true,  "skip_reason": null },
    "bucket_limits":    { "available": true,  "skip_reason": null },
    "auth_check":       { "available": true,  "skip_reason": null },
    "client_tampering": { "available": true,  "skip_reason": null },
    "sql_injection":    { "available": true,  "skip_reason": null },
    "cors_check":       { "available": true,  "skip_reason": null },
    "xss_check":        { "available": true,  "skip_reason": null },
    "api_exposure":     { "available": true,  "skip_reason": null }
  },
  "estimated_durations": {
    "dev": 120,
    "pre-deploy": 480,
    "post-deploy": 300,
    "all": 900
  },
  "version": "0.1.0"
}
```

`skip_reason` examples: `"Requires Supabase stack — set stack.backend: supabase in config"`, `"Requires second test account — set VIBE_ITERATOR_TEST_EMAIL_2 in .env"`.

`estimated_durations` are in seconds. Initially hardcoded constants; future enhancement: rolling average of completed scans from `.vibe-iterator/scan-history.json`.

---

## Browser Session Lifecycle

One Chrome instance per scan run. Launched at the start of `ScanRunner.run()` and closed in a `finally` block regardless of outcome.

```
ScanRunner.run()
  ├── browser = BrowserSession.launch()      # Chrome starts
  ├── auth.login(account=1)                  # authenticate once
  ├── for each scanner in stage:
  │     asyncio.to_thread(scanner.run, ...)  # scanner executes synchronously
  └── finally: browser.quit()               # Chrome closes, always
```

**State rules:**
- The browser session is shared across all scanners — do not launch a new instance per scanner
- Scanners that modify client state (localStorage, cookies, URL) **must restore original state in a `try/finally` block** before returning
- Authentication happens once at scan start. If a scanner logs out as part of a test, it must call `auth.login()` again before returning
- The second test account is managed by the scanner that needs it (`rls_bypass`, `auth_check`) — they open a second browser context or tab, not a new Chrome process

---

## Async/Sync Bridge

FastAPI and the scan engine run on the asyncio event loop. Scanner `run()` methods are synchronous. Bridge using `asyncio.to_thread()`:

```python
findings = await asyncio.to_thread(scanner.run, browser, listeners, config)
```

**Why this matters:** Never call a blocking synchronous function directly with `await` or in the event loop body. Doing so freezes the event loop, stalls all WebSocket broadcasts, and causes the dashboard to hang during scans. `asyncio.to_thread()` runs the scanner in a thread pool executor, keeping the event loop free to send WebSocket events in real time.

---

## WebSocket Security

The `/ws` endpoint accepts any local connection without token authentication. This is intentional for v1 — the server binds to `127.0.0.1` only, making it inaccessible from other machines or network interfaces.

**Rules:**
- Never relax the `127.0.0.1` bind to `0.0.0.0` — doing so exposes live scan data and scan control to the local network
- Do not add CORS headers to the WebSocket endpoint
- If multi-user or remote access is needed in the future, gate the `/ws` endpoint with a one-time session token generated at server start and passed via the dashboard URL query string
