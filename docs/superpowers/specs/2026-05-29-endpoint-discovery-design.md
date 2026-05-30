# Automatic Endpoint Discovery / Spidering — Design Spec

## Goal

Add a `discover` stage to vibe-iterator that automatically maps the full attack surface of a target web app — both page routes and API endpoints — and persists the results to a sidecar file that all future scan stages consume automatically.

## Context

The current `navigator.py` visits a static `config.pages` list (default: `/`, `/login`, `/dashboard`, `/profile`). There is no auto-discovery. This means:
- Routes the developer forgot to list are never scanned
- API endpoints are only found if a page the user listed happens to call them
- Each new project requires manual configuration of the page list

## Scope

Two discovery goals, both covered:
1. **Route/page coverage** — find every navigable page in the app
2. **API endpoint attack surface** — find every API endpoint called by the app during normal use

## Architecture

### New module: `vibe_iterator/spider/`

```
vibe_iterator/spider/
├── __init__.py
├── sitemap.py            # HTTP-only: fetch /sitemap.xml, /sitemap_index.xml, /robots.txt
├── dom_crawler.py        # BFS Selenium crawl — follow <a href>, max_pages + max_depth
├── js_extractor.py       # CDP JS: extract routes from React Router, Next.js, Vite bundles
└── endpoint_harvester.py # Collect API endpoints from NetworkListener during crawl
```

### New orchestration file

`vibe_iterator/engine/discover_runner.py` — runs all four spider components in sequence, merges and deduplicates results, writes the sidecar file.

### Sidecar output: `vibe-iterator.discovered.yaml`

Written beside the user's `vibe-iterator.config.yaml`. Format:

```yaml
pages:
  - /
  - /login
  - /dashboard
  - /admin/users
  - /settings/billing
api_endpoints:
  - GET /api/v1/users/{id}
  - POST /api/v1/auth/login
  - DELETE /api/v1/items/{id}
discovered_at: "2026-05-29T14:32:00"
```

Pages and api_endpoints are deduplicated and sorted. UUIDs and numeric IDs in API paths are normalized to `{id}`.

### Modified files

| File | Change |
|------|--------|
| `vibe_iterator/config.py` | Add `max_pages` (default 30), `max_depth` (default 3); load sidecar if present, merge into `config.pages` |
| `vibe_iterator/engine/runner.py` | Route `--stage discover` to `discover_runner.py` (early-exit before scanner pipeline); merge sidecar pages into `config.pages` before any other stage runs |
| `vibe-iterator.config.yaml.example` | Document `max_pages`, `max_depth`, `discover` stage |
| `vibe_iterator/server/static/index.html` | "Discover Endpoints" button on home page |
| `vibe_iterator/server/static/js/app.js` | `startDiscovery()` handler; "Discovered Surface" panel on results page |
| `docs/SCANNERS.md` | Document `endpoint_discovery` as a pseudo-scanner (discover stage) |
| `docs/CONFIG.md` | Document `max_pages`, `max_depth`, sidecar file, `discover` stage |

---

## Component Design

### `sitemap.py` — Pure HTTP, no browser

**What it does:**
1. GET `/sitemap.xml` — parse `<loc>` entries (XML)
2. If `<sitemapindex>` found, follow each child sitemap URL (one level deep only)
3. GET `/robots.txt` — extract `Sitemap:` directive URLs and `Disallow:` paths
4. Return flat `list[str]` of URL paths, capped at `max_pages`

**Key behavior:**
- `Disallow:` paths from robots.txt are **included** — they are often sensitive routes the developer tried to hide from crawlers
- 404 or timeout on sitemap → log DEBUG, return `[]`, continue
- External URLs filtered out (only same-origin paths kept)

**Signature:**
```python
def fetch_sitemap_routes(base_url: str, max_pages: int = 30) -> list[str]:
    ...
```

---

### `dom_crawler.py` — BFS Selenium crawl

**What it does:**
1. Start with seed set: sitemap results + `config.pages`
2. For each page in BFS queue: extract all `<a href>` that resolve to same origin
3. Add unseen paths to queue; track depth per path
4. Stop when `max_pages` reached OR queue exhausted within `max_depth`

**Filtering:**
- Skip: `mailto:`, `tel:`, external domains, fragment-only `#` links, `javascript:` hrefs
- Normalize: strip query strings and fragments from discovered paths before deduplication

**Signature:**
```python
def crawl_dom(
    session: BrowserSession,
    seeds: list[str],
    base_url: str,
    max_pages: int = 30,
    max_depth: int = 3,
) -> list[str]:
    ...
```

---

### `js_extractor.py` — CDP route extraction

**What it does:**
After each page load, executes a JS probe via `session.evaluate()` that checks for known framework fingerprints in order:

1. **Next.js**: `window.__NEXT_DATA__` → extract `page`, `buildManifest.pages[]`
2. **React Router v6**: query `window.__reactRouterContext` or DOM `<RouterProvider>` internals
3. **React Router v5**: `window.__reactRouterVersion` + history routes
4. **Vite**: `window.__vite_plugin_react_preamble_installed__` + manifest chunk analysis

**Key behavior:**
- Each fingerprint check is isolated in `try/catch` inside the JS probe — a framework not being present returns `null`, not an error
- Returns `[]` silently when no framework is detected — no false positives
- Relative paths normalized to absolute paths (e.g., `about` → `/about`)

**Signature:**
```python
def extract_js_routes(session: BrowserSession) -> list[str]:
    ...
```

---

### `endpoint_harvester.py` — API surface from network traffic

**What it does:**
Reads `NetworkListener.get_requests()` after the full crawl. For each captured request, classifies it as an API endpoint if the path:
- Starts with `/api/`, `/v1/`, `/v2/`, `/v3/`, `/graphql`, `/rest/`, `/rpc/`
- Or matches `/{word}/{uuid-or-int}` pattern (REST resource pattern)

**Normalization:**
- Strip query strings
- Replace UUID segments (`[0-9a-f-]{36}`) with `{id}`
- Replace pure-integer segments with `{id}`
- Deduplicate: `GET /api/users/123` + `GET /api/users/456` → one entry: `GET /api/users/{id}`

**Output format:** `"METHOD /normalized/path"` strings

**Signature:**
```python
def harvest_endpoints(network: NetworkListener) -> list[str]:
    ...
```

---

### `discover_runner.py` — Orchestrator

**Sequence:**
1. Open browser session
2. `sitemap.py` → seed URLs (no browser)
3. `dom_crawler.py` → BFS over seeds + `config.pages`
4. `js_extractor.py` runs on each page during DOM crawl (not a separate pass)
5. `endpoint_harvester.py` reads NetworkListener after crawl completes
6. Merge all page paths: sitemap + DOM + JS routes → deduplicate → sort
7. Write `vibe-iterator.discovered.yaml`
8. Close browser session

**Always writes sidecar** — even if some components returned empty results, so partial discovery is useful and CI can rely on the file existing.

---

## Config Changes

New optional fields in `vibe-iterator.config.yaml`:

```yaml
spider:
  max_pages: 30       # stop crawl after this many unique pages
  max_depth: 3        # stop following links deeper than this
```

Defaults apply if the `spider:` block is absent.

---

## Sidecar Merging

When `vibe-iterator.discovered.yaml` exists beside the config:
- `config.pages` = union of `config.pages` + `discovered.pages`
- The merged list is used by all scan stages transparently
- User never needs to manually copy discovered routes into their config

---

## Dashboard Integration

**Home page:** One new "Discover Endpoints" button in the scan launcher section. Posts `{ stage: "discover" }` to `/api/scan/start` and navigates to `scan.html` — identical flow to all other stages.

**Results page:** After a `discover` stage completes, the results page shows a **"Discovered Surface"** panel listing:
- Found pages (count + list)
- Found API endpoints (count + list)
- Copy-all button for pasting into notes or other tools

No new HTML pages required.

**Data flow for discovery results:** `discover_runner.py` returns a `DiscoveryResult` dataclass (`pages: list[str]`, `api_endpoints: list[str]`, `discovered_at: str`). The scan runner stores this on the scan state object. `/api/scan/results` returns it as a `discovered_surface` field alongside the normal `findings` list. `results.html` checks for `discovered_surface` in the response and renders the panel only when present — no change needed for non-discover stages.

---

## Error Handling

Each spider component is independently fault-tolerant:

| Component | On failure | Behavior |
|-----------|-----------|----------|
| `sitemap.py` | 404, timeout, malformed XML | Log DEBUG, return `[]`, continue |
| `js_extractor.py` | CDP error, framework not found | Return `[]` silently |
| `dom_crawler.py` | Individual page visit error | Skip page, log DEBUG, continue queue |
| `endpoint_harvester.py` | Pure data transform, no I/O | Cannot fail |

`discover_runner.py` always writes the sidecar even on partial results.

---

## Testing

Each component has a focused unit test using the `VulnerableApp` fixture pattern:

| Test file | What it covers |
|-----------|---------------|
| `tests/test_spider/test_sitemap.py` | Fixture serves sitemap with 3 URLs + robots.txt with Disallow — assert correct paths returned; assert 404 returns `[]` |
| `tests/test_spider/test_dom_crawler.py` | Fixture serves 3 linked pages — assert BFS finds all 3; assert `max_pages=2` stops at 2; assert external links skipped |
| `tests/test_spider/test_js_extractor.py` | Fixture injects `window.__NEXT_DATA__` — assert routes extracted; assert empty return when no framework present |
| `tests/test_spider/test_endpoint_harvester.py` | Feed mock `NetworkRequest` objects — assert `/api/users/123` → `GET /api/users/{id}`; assert non-API paths skipped |
| `tests/test_spider/test_discover_runner.py` | Full integration against `VulnerableApp` — assert sidecar written with correct shape and content |

---

## What This Enables

- **Immediate value**: every scan stage automatically covers routes that would have been missed with a manual page list
- **CI/CD ready**: run `vibe-iterator --stage discover` once on deploy, commit `vibe-iterator.discovered.yaml`, future CI runs use the saved surface without re-spidering
- **Foundation for scanner marketplace**: discovered API endpoints become the input for future API-specific scanners
