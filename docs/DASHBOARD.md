# DASHBOARD.md — GUI Specification

## Design Philosophy

The dashboard is a **hacker-themed security control center** — dark backgrounds, monospace fonts, neon accent colors (green/cyan/red), terminal-style animations, scan-line effects, and a "mission control" layout. Think: cyberpunk meets devtools. The goal is to make security testing feel exciting and trendy so vibe coders actually want to use it.

## Visual Language

- **Background:** Near-black (#0a0a0f) with subtle grid or scan-line overlay
- **Primary text:** Light gray (#c8c8d0) in monospace (JetBrains Mono or Fira Code)
- **Accent colors:** Neon green (#00ff41) for pass/safe, cyan (#00d4ff) for info/active, red (#ff0040) for critical/fail, amber (#ffb000) for warnings, purple (#b347d9) for system UI
- **Cards/panels:** Dark glass-morphism with subtle borders (#1a1a2e), slight glow on hover
- **Animations:** Typing/typewriter effects for status messages, pulse animations on active scans, smooth reveals for findings, a subtle matrix-rain or particle background (lightweight, not distracting)
- **Icons:** Minimal line icons — shields, locks, terminals, warning triangles
- **Overall feel:** Professional but edgy. Like a tool a security researcher would respect but a vibe coder would screenshot for Twitter

---

## Page 1: Dashboard Home (`localhost:3001/`)

This is the launch pad. The user lands here when they run `vibe-iterator`.

**Header area:**
- Vibe Iterator logo/wordmark with a subtle glitch or neon effect
- Target URL display (from config) with a connection status indicator (green dot = reachable, red = unreachable)
- Timestamp and version

**Stage selector (main focus):**
- Four large selectable cards (or 2×2 grid on narrow screens):
  - **DEV** — icon: code brackets, tag: "Quick scan", estimated time: ~2 min. Scanners: `data_leakage`, `auth_check`, `client_tampering`
  - **PRE-DEPLOY** — icon: rocket, tag: "Recommended", estimated time: ~8 min. All 9 core + extended scanners
  - **POST-DEPLOY** — icon: globe, tag: "Production", estimated time: ~5 min. 6 external-facing scanners. Small info icon with tooltip: "XSS not tested in this stage — stored XSS tests can pollute live data. Use PRE-DEPLOY or ALL against a staging environment for XSS coverage."
  - **ALL SCANNERS** — icon: grid/matrix, tag: "Full Audit", estimated time: ~15 min. Amber badge: "⚠ Slow — best for deep audits, not routine checks"
- Each card shows its scanners as small pill tags
- Pills for scanners that **will be skipped** are dimmed with strikethrough and a tooltip (sourced from `GET /api/config` → `scanners[name].skip_reason`). Examples: "Requires Supabase stack — not detected", "Requires second test account — not configured"
- **Caveat:** For auto-detected stack, skip status reflects the *last known* detection (from prior scan or YAML). On first-ever run with no YAML stack setting, all Supabase-specific scanner pills show as "skipped (stack unknown)" until one scan completes. A tooltip explains: "Run a scan first to auto-detect your stack, or set it manually in your config."
- Selected card gets a neon border glow
- **Stack mismatch warning:** If the selected stage includes `rls_bypass`, `tier_escalation`, or `bucket_limits` and `GET /api/config` shows those scanners unavailable, show an amber inline banner: "⚠ 3 Supabase-specific scanners will be skipped. Set `stack: backend: supabase` in your config to enable them."
- **Advanced — custom scanner overrides (collapsible):** A "⚙ Advanced" toggle reveals individual scanner checkboxes for the selected stage. Each shows category, estimated duration, and description on hover. Uncheck to skip — sent as `scanner_overrides` in `POST /api/scan/start`. Session-only, does not modify YAML

**Config validation rules (enforced before START SCAN):**
- Target reachability: checked on page load via `GET /api/config` and re-checked on focus return. Shows green dot (reachable), red dot (unreachable — "check your app is running at [URL]"), amber spinner (checking)
- If required `.env` vars are missing, show a red error card *above* the stage selector listing each missing variable and its purpose (e.g., "`VIBE_ITERATOR_TEST_EMAIL` — required for authentication")
- If `pages` list in YAML is empty: "⚠ No pages configured — add at least one page to `vibe-iterator.config.yaml`"
- If second account env vars are partially set (email but no password or vice versa): amber warning
- START SCAN is disabled (greyed, `cursor: not-allowed`) with tooltip showing the specific blocking reason until all required config is valid

**Config summary panel (collapsible):**
- Shows loaded `.env` values (credentials masked to `t***@example.com` format)
- Pages to crawl list with count
- Detected stack with source: "supabase (auto-detected from network)" or "supabase (manually configured)"
- Second test account status: "configured ✓" or "not configured — cross-user checks disabled"
- Edit button opens YAML in a syntax-highlighted code viewer (read-only in v1)

**Launch button:**
- Large, prominent "START SCAN" button with pulse animation when enabled
- Disabled state: muted color, no pulse, tooltip on hover with blocking reason
- On click: `POST /api/scan/start` with `{ stage, scanner_overrides }`, then navigate to Scan Progress page

---

## Page 2: Live Scan Progress (`localhost:3001/scan`)

The user watches the scan happen in real time. This is the "wow" page.

**Top control bar:**
- Scan title: "SCANNING — PRE-DEPLOY · target: localhost:3000"
- **Browser/CDP status indicator** — small icon left of title: green pulsing dot ("CDP connected"), amber ("connecting..."), red ("CDP disconnected — scan may stall"). Driven by `scan_error` events with `recoverable: false`
- **CANCEL SCAN** button (top-right, red outlined): sends `DELETE /api/scan/active`. Shows confirmation: "Cancel scan? All progress will be lost." On confirm — engine stops the running scanner, closes browser, emits `scan_cancelled` event. Page shows cancelled state with "← Back to Home" and "Retry" buttons

**Layout: split-panel**

**Left panel (60%) — Live terminal feed:**
- Styled like a real terminal (dark bg, monospace, green text on black)
- Cap at 1000 lines in DOM — oldest lines pruned from top when limit is reached. A "▲ Load earlier output" label appears when lines have been pruned
- Full terminal log downloadable any time via "⬇ Download log" button at panel bottom-right — saves as `vibe-iterator-scan-{timestamp}.txt`
- Streams scan events in real time via WebSocket. Example sequence:
  ```
  [10:32:01] Launching Chrome with CDP...
  [10:32:02] ✓ Chrome launched — CDP connected
  [10:32:03] Authenticating as t***@example.com...
  [10:32:05] ✓ Authentication successful
  [10:32:06] Crawling 6 pages...
  [10:32:07] Navigating to /dashboard... [200]
  [10:32:09] [data_leakage] Starting scan...
  [10:32:11] ⚠ [data_leakage] FINDING [HIGH]: JWT token exposed in network response
  [10:32:12] ✓ [data_leakage] Completed — 1 finding
  [10:32:13] [rls_bypass] Starting scan...
  [10:32:14] [rls_bypass] Switching to second test account: t2***@example.com
  [10:32:15] [rls_bypass] Running cross-user query on table: profiles...
  [10:32:16] [rls_bypass] ✓ Restoring primary session
  [10:32:17] ✓ [rls_bypass] Completed — 0 findings (passed)
  [10:32:17] [sql_injection] Starting scan...
  [10:32:77] ✗ [sql_injection] TIMEOUT after 60s — scanner skipped
  ```
- Color-coded lines: green (`✓` pass, info), red (critical/high findings, errors), amber (medium, warnings, timeouts), cyan (scanner transitions, navigation), white (progress messages)
- Auto-scrolls to bottom. Pauses when user scrolls up — "↓ Resume auto-scroll" button appears bottom-right of panel
- Each finding line (`⚠ FINDING`) is clickable — scrolls and highlights the corresponding card in the right panel

**Right panel (40%) — Live findings feed:**
- Findings appear as cards as they're discovered, animated in with slide-up + fade
- Each card: severity badge (color-coded), scanner name, title, one-line description, page URL
- Running count at top: "3 Critical · 1 High · 2 Medium · 0 Low"
- **Severity filter pills** above the feed: [All] [Critical] [High] [Medium] [Low] — tap to filter live cards without stopping the scan
- Skipped scanners appear as grey "SKIPPED" cards at the bottom with the skip reason
- Timed-out scanners appear as amber "TIMEOUT" cards

**Top progress bar:**
- Shows: "Scanner 4 of 9 — tier_escalation · 3 findings so far"
- Neon progress bar fills left to right. Each scanner's completed segment is color-coded: green (passed), red (had findings), amber (timed out), grey (skipped)
- Estimated time remaining (rolling average based on completed scanner durations)

**Bottom status bar:**
- Current page being crawled
- Elapsed time (counting up)
- Network requests captured count
- Status indicator: "SCANNING..." (pulsing) → "COMPLETE ✓" → "CANCELLED" or "ERROR ✗"

**On scan complete:**
- Terminal shows an ASCII art summary block: total by severity, duration, score preview
- "VIEW RESULTS →" button with pulse animation
- Auto-redirect to Results page after 3 seconds — cancelable with "Stay on this page" link
- On cancel or error: show appropriate terminal message in red/amber + "← Back to Home" and "Retry Scan" buttons

---

## Page 3: Results Dashboard (`localhost:3001/results`)

The main results view. This is what users will spend the most time on.

**Top section — Executive summary:**
- **Security score** (0–100) with letter grade displayed large. Scoring formula:
  - Start at 100. Deduct: Critical = −20 pts, High = −10 pts, Medium = −4 pts, Low = −1 pt. Floor at 0
  - Grade thresholds: A = 90–100, B = 75–89, C = 60–74, D = 45–59, F = 0–44
  - Score color: green (A/B), amber (C/D), red (F)
  - Score is stage-normalized — a dev-stage scan (3 scanners) is scored against the dev baseline only, not the full 10-scanner baseline
- Severity breakdown as a horizontal stacked bar: critical (red) | high (orange) | medium (amber) | low (blue) | passed (green). Each segment is clickable — filters the findings list below to that severity
- Key stats row: total findings · pages crawled · requests captured · scanners run (e.g., "7 of 9 — 2 skipped") · scan duration
- Stage badge + target URL
- **Scan metadata panel (collapsible, default collapsed):**
  - Pages crawled: list with HTTP status code per page
  - Scanner breakdown table: scanner name | status (passed / N findings / skipped / timed out) | duration
  - Requests captured: total + breakdown by method (GET/POST/PUT/DELETE/PATCH)
  - Stack detected and source
  - Second account used: yes / no + which scanners used it

**Filter & sort bar (sticky, below executive summary):**
- **Severity filter pills:** [All] [Critical] [High] [Medium] [Low] — active pill is highlighted
- **Category filter:** multi-select dropdown
- **Sort:** dropdown — Severity (critical-first, default) | Category | Scanner | Page URL
- **Search:** text input filtering by finding title keyword (case-insensitive, instant)
- **Toggles:** "Show skipped scanners" | "Show passed checks"
- Active filter count badge ("3 filters active") with "Clear all" link
- Filter state is persisted to `localStorage` — survives page refresh

**Middle section — Findings by category:**
- Category sections match the scanner registry exactly: **Access Control**, **Data Leakage**, **Authentication**, **Injection**, **API Security**, **Client-Side Tampering**, **Misconfiguration**
- Each category header: category icon, name, finding count, worst severity badge, expand/collapse toggle
- Findings within each category are sorted severity-first (critical → high → medium → low)
- Empty categories are hidden by default — shown when "Show passed checks" toggle is on

**Finding card (collapsed):**
- Severity badge (color-coded pill) | Title | Scanner name | Page URL | One-line description
- Right side: "Mark as ▾" dropdown + "↗ Deep Dive" link
- Click card body to expand

**Finding card (expanded):**
- **"What this means"** — 2–4 sentence plain-English explanation: what the vulnerability is, who is at risk, what an attacker could do. No jargon
- **Evidence panel** — structure is category-specific (full spec in `SCANNERS.md`):
  - *Injection / API Security / Authentication*: HTTP request block (method, URL, headers, body) + HTTP response block (status, headers, body excerpt). Injected payload highlighted inline
  - *Client-Side Tampering*: before/after diff of the tampered localStorage key or cookie. Server response to the tampered request shown below
  - *Data Leakage*: highlighted excerpt from the network response with the leaked value. Leak type labeled (JWT, API key, UUID, PII)
  - *XSS*: injected payload string + response/DOM excerpt showing reflection. CSP header displayed if present
  - *CORS*: test request Origin header used + full response headers received
  - Screenshot thumbnail if captured — click to expand full size. Stored inline as base64 for portability
- **Remediation** — structured fix block: "What to fix" (1 sentence) + "How to fix" (1–2 sentences with optional code snippet or doc link). See `SCANNERS.md` for template
- **"COPY FIX PROMPT"** — copies the structured LLM prompt to clipboard with green toast. Prompt is also visible in an expandable `<details>` block under the button so developers can read it before copying. See `SCANNERS.md` for prompt template
- Tags row: scanner · category · stage · page URL
- **"Mark as ▾" dropdown:**
  - ✓ **Resolved** — card greyed out, moved to "Resolved" section
  - ⚠ **Accepted Risk** — amber outline, prompts for a one-line justification note
  - ✗ **False Positive** — strikethrough title, moved to "Dismissed" section
  - On every selection: immediately calls `POST /api/scan/findings/mark` with `{ findings: [{ finding_id, status, note? }] }`. The server updates `ScanResult.finding_marks` so the export endpoint generates a report with marking state already embedded — no client-side data needed at export time

**Bottom sections:**
- **Passed checks** (collapsed by default): all scanners/check groups that produced zero findings, with green checkmarks. Extensive scanners (`auth_check`, `sql_injection`) show individual check groups (e.g., "Token Security ✓", "Session Management ✓"). Message: "These areas look good based on the tests we ran"
- **Resolved** (collapsed, shown only if items exist): findings marked resolved
- **Dismissed** (collapsed, shown only if items exist): findings marked false positive or accepted risk, with justification notes

**Action bar (sticky top-right):**
- **"EXPORT REPORT"** — downloads self-contained HTML. Report reflects marking state. Disabled until scan completes
- **"RE-SCAN"** — back to Dashboard Home with same stage pre-selected
- **"COPY PROMPTS ▾"** dropdown:
  - Copy all prompts (numbered, `---` delimited)
  - Copy Critical + High only (shows count)
  - Copy prompts for active filter/category (shows count)
- **"Compare ▾"** (appears only if a prior scan result exists in `localStorage`):
  - Opens diff modal comparing by **`fingerprint`** (stable `sha256(scanner+title+page)[:16]`), not by `finding_id` (which is a new uuid every scan)
  - Shows: 🆕 New findings (fingerprint in current, not in previous), ✅ Resolved (fingerprint in previous, not in current), ↔ Unchanged (same fingerprint, same severity), ⚠ Worsened (same fingerprint, higher severity now)
  - Useful for verifying fixes: run scan → fix vulnerability → re-run → use Compare to confirm finding moved to "Resolved"

---

## Page 4: Finding Deep Dive (`localhost:3001/results/{finding_id}`)

Advanced view for users who want to dig deeper into a specific finding.

**Full evidence view:**
- Complete request/response chain (headers, body, timing)
- Screenshot carousel (before tampering, during, after)
- Network timeline showing the exact sequence of events
- Console log entries related to this finding
- Storage state (localStorage, cookies) before and after

**Context panel:**
- Page URL where found (clickable link opens the target page)
- Scanner that detected it (with short scanner description)
- Scan timestamp, stage, and duration
- **Related findings** — shown when any of these conditions match:
  1. Same page URL → labeled "Also found on this page"
  2. Same category → labeled "Same category"
  3. Known complementary pairs: `tier_escalation` ↔ `client_tampering`, `rls_bypass` ↔ `auth_check`, `sql_injection` ↔ `api_exposure` → labeled "Often co-occur"
  - Shown as compact clickable cards (severity badge + title). Hidden entirely if no relations found

**LLM prompt section (prominent):**
- The full copy-paste prompt with syntax highlighting
- Variant prompts for different AI assistants (Claude, ChatGPT, Copilot)
- "What to tell your AI" — a plain-English script the user can follow

---

## Technical Implementation Notes

- All pages are vanilla HTML/CSS/JS — no frameworks, no build step
- Pages are served as static files by FastAPI from `server/static/`
- WebSocket connection is established on page load for `scan.html`
- All scan data is fetched via REST API (`/api/scan/results`, `/api/config`)
- Scan cancellation: `DELETE /api/scan/active` — engine stops current scanner and closes browser
- CSS uses custom properties (CSS variables) for the color system — makes theming a single-file change
- Animations are CSS-only where possible (transitions, keyframes) — JS only for WebSocket-driven updates
- **Marking state** is sent to the server via `POST /api/scan/findings/mark` immediately on each mark action — the server is the source of truth. The dashboard UI reflects `ScanResult.finding_marks` returned by `GET /api/scan/results`. `localStorage` is used only as an optimistic UI cache to avoid re-fetching after each mark
- **Scan comparison:** When a scan completes, the current result's `findings` fingerprints + severities are written to `localStorage` as `vibe_iterator_last_scan`. On the next completed scan, the Compare button diffs current fingerprints vs. stored fingerprints. `finding_id` (uuid4) is never used for comparison — `fingerprint` is the stable identity field
- The exported HTML report includes marking state annotations and is fully self-contained (all CSS/JS inlined, no WebSocket, no external CDN)
