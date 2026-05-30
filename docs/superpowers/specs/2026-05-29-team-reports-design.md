# Team Reports and Scan History — Design Spec

## Goal

Auto-save every completed scan as a lightweight JSON file in a local `vibe-iterator-results/` directory. Add a "Scan History" dropdown to the dashboard results page so users can switch between past scans without re-running them.

## Context

Currently, scan results exist only in memory during the scan session, with the only persistence being the manually exported HTML report (`vibe-iterator-report-*.html`). There is no automatic save and no way to view a past scan in the dashboard without re-running it.

This feature adds automatic persistence (always-on, no configuration needed) and a history browser in the existing results UI. No database, no authentication, no team server — just JSON files on disk.

---

## Architecture

### Files created / modified

| File | Change |
|------|--------|
| `vibe_iterator/history.py` | New — JSON serializer/deserializer and file management helpers |
| `vibe_iterator/config.py` | Add `results_dir: Path` field to `Config` dataclass; set it in `load_config()` |
| `vibe_iterator/cli.py` | Auto-save after headless scan completes |
| `vibe_iterator/server/routes.py` | Replace `_result_dict()` with import of `serialize_result()`; auto-save after GUI scan completes; add 2 new API routes |
| `vibe_iterator/server/static/results.html` | Add "Scan History" panel |
| `vibe_iterator/server/static/js/app.js` | `loadHistory()`, `loadHistoricalResult()`, `renderHistoryPanel()` |

---

## Component Design

### 1. `vibe_iterator/history.py`

Three public functions and one private serialization helper.

**`save_result(result: ScanResult, results_dir: Path) -> Path`**

Serializes `result` to `result-YYYYMMDD-HHmmss.json` in `results_dir`. Creates the directory with `mkdir(parents=True, exist_ok=True)` if it doesn't exist. Returns the path of the written file.

Naming: `datetime.now(timezone.utc).strftime("result-%Y%m%d-%H%M%S.json")`. If a file with the same name already exists (two scans in the same second), appends `-2`, `-3`, etc.

**`list_results(results_dir: Path) -> list[dict]`**

Scans `results_dir` for files matching `result-*.json`. For each file:
1. Reads only the top-level fields needed for the dropdown (does NOT load findings to keep it fast)
2. Returns a metadata dict per file, sorted newest-first

Returns `[]` if `results_dir` doesn't exist (first-run case, not an error).

Corrupt/unreadable files are skipped with a warning to stderr; they never cause a failure.

Returned metadata structure per file:
```json
{
  "filename": "result-20260529-143001.json",
  "timestamp": "2026-05-29T14:30:01Z",
  "stage": "pre-deploy",
  "target": "http://localhost:3000",
  "score": 72,
  "score_grade": "C",
  "finding_count": 12,
  "status": "completed"
}
```

**`load_result(filename: str, results_dir: Path) -> dict`**

Validates that `filename` matches `^result-\d{8}-\d{6}(-\d+)?\.json$` (prevents path traversal). Reads and returns the full JSON dict. Raises `FileNotFoundError` if the file doesn't exist, `ValueError` if the filename is invalid.

**`serialize_result(result: ScanResult) -> dict`**

Public function. Produces the exact same JSON structure as the current `_result_dict()` in `routes.py` — this is the canonical serializer. `routes.py` is updated to import and use `serialize_result()` instead of its own `_result_dict()`, ensuring the saved JSON and the live API response have identical structure (so `renderResults(data)` works for both paths).

The structure mirrors `_result_dict()` precisely: top-level fields (`scan_id`, `stage`, `target`, `status`, etc.), `findings` as a list of finding dicts (with `severity` as a string value, not enum), `scanner_results`, `finding_marks`, `discovered_surface`. No `dataclasses.asdict()` — the existing `_result_dict()` logic is moved here verbatim.

---

### 2. `vibe_iterator/config.py` changes

Add one field to `Config`:

```python
# History
results_dir: Path = field(default_factory=lambda: Path.cwd() / "vibe-iterator-results")
```

In `load_config()`, set it explicitly after the YAML parsing block:

```python
results_dir = yaml_file.parent / "vibe-iterator-results"
```

Document in `docs/CONFIG.md`: the `vibe-iterator-results/` directory is created automatically on first scan. Users should add it to `.gitignore`:

```
vibe-iterator-results/
```

---

### 3. Auto-save Integration

**CLI headless mode (`vibe_iterator/cli.py` — `_run_headless()`):**

After `result = asyncio.run(runner.run(stage))` and before the findings summary print:

```python
from vibe_iterator.history import save_result
try:
    saved_path = save_result(result, config.results_dir)
    click.echo(f"[vibe-iterator] Result saved to: {saved_path}")
except Exception as exc:
    click.echo(f"[WARN] Could not save result: {exc}", err=True)
```

**GUI mode (`vibe_iterator/server/routes.py` — `_run_scan()` background task):**

After the scan completes and `_current_result` is set, call `save_result()` with the same pattern — try/except, log warning on failure, never raise.

---

### 4. History API Endpoints

Two new routes added to `vibe_iterator/server/routes.py`:

**`GET /api/history`**

```python
@router.get("/api/history")
async def get_history(config: Config = Depends(get_config)):
    from vibe_iterator.history import list_results
    return list_results(config.results_dir)
```

Returns a JSON array. Returns `[]` if no results exist.

**`GET /api/history/{filename}`**

```python
@router.get("/api/history/{filename}")
async def get_historical_result(filename: str, config: Config = Depends(get_config)):
    from vibe_iterator.history import load_result
    try:
        return load_result(filename, config.results_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Result not found")
```

Filename validation is in `load_result()` — the route itself does not need additional checks.

---

### 5. Frontend — `results.html` + `app.js`

**`results.html` addition:**

A "Scan History" panel inserted at the very top of the `<main>` content area (above the score header), hidden by default:

```html
<div id="history-panel" class="history-panel" style="display:none">
  <span class="history-label">Scan History</span>
  <select id="history-select" class="history-select" onchange="loadHistoricalResult(this.value)">
    <!-- populated by loadHistory() -->
  </select>
</div>
```

**`app.js` additions:**

```javascript
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const items = await res.json();
    if (!items.length) return;  // no history yet, keep panel hidden

    const panel = document.getElementById('history-panel');
    const select = document.getElementById('history-select');
    panel.style.display = 'flex';

    // First option: current session result
    const current = document.createElement('option');
    current.value = '';
    current.textContent = '(current scan)';
    select.appendChild(current);

    items.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.filename;
      const ts = item.timestamp ? item.timestamp.slice(0, 16).replace('T', ' ') : '';
      opt.textContent = `${ts} — ${item.stage} — score ${item.score ?? 'n/a'} (${item.finding_count} findings)`;
      select.appendChild(opt);
    });
  } catch (e) {
    console.warn('Could not load scan history:', e);
  }
}

async function loadHistoricalResult(filename) {
  if (!filename) {
    // Reload current session result
    await loadResults();
    return;
  }
  try {
    const res = await fetch(`/api/history/${encodeURIComponent(filename)}`);
    if (!res.ok) { console.warn('History load failed:', res.status); return; }
    const data = await res.json();
    renderResults(data);  // reuses existing renderResults() which takes a result dict
  } catch (e) {
    console.warn('Could not load historical result:', e);
  }
}
```

`loadHistory()` is called once on page load alongside `loadResults()`. The current scan result always appears as the first "(current scan)" option in the dropdown.

`renderResults(data)` — the existing results rendering logic is refactored from inline code to a named function that accepts a result dict. Both the current-scan load path and the historical load path call `renderResults(data)`.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `vibe-iterator-results/` doesn't exist | `save_result()` creates it; `list_results()` returns `[]` |
| JSON write fails (permissions, disk full) | `save_result()` logs warning; scan result returned normally, scan never fails |
| `GET /api/history/{filename}` — invalid filename | 400 from `load_result()` ValueError |
| `GET /api/history/{filename}` — file not found | 404 from `load_result()` FileNotFoundError |
| Corrupt JSON file in results directory | `list_results()` skips it with a stderr warning |
| First scan (no history yet) | `GET /api/history` returns `[]`; history panel hidden |
| `results_dir` not resolvable (no config YAML) | Falls back to `Path.cwd() / "vibe-iterator-results"` |

---

## Testing

**`tests/test_history.py`:**
- `test_save_result_creates_file` — saves a mock ScanResult, asserts file exists with correct name pattern
- `test_save_result_creates_directory` — verifies `results_dir` is created if it doesn't exist
- `test_list_results_sorted_newest_first` — writes 3 files with different timestamps, asserts list order
- `test_list_results_empty_directory` — `list_results()` returns `[]` for a fresh directory
- `test_list_results_missing_directory` — `list_results()` returns `[]` for a non-existent directory
- `test_list_results_skips_corrupt_file` — writes one valid JSON + one invalid, asserts list contains only 1 entry
- `test_load_result_roundtrip` — save then load, assert key fields match
- `test_load_result_invalid_filename` — asserts ValueError for `"../secrets.json"` and `"notaresult.json"`
- `test_load_result_not_found` — asserts FileNotFoundError

**`tests/test_server/test_history_routes.py`:**
- `test_get_history_empty` — 200, returns `[]`
- `test_get_history_with_results` — saves 2 files, asserts both appear in response sorted newest-first
- `test_get_historical_result_ok` — saves a result, fetches it, asserts key fields
- `test_get_historical_result_invalid_name` — 400
- `test_get_historical_result_not_found` — 404

**Auto-save integration:** verified by running `pytest tests/test_history.py -v` — no real scan needed.

---

## What This Enables

- **Zero-configuration history:** Every scan is saved automatically. No flags to enable.
- **Instant review:** Navigate back to any past scan in the dashboard without re-running.
- **Easy sharing:** Copy a `result-*.json` file to a teammate — they open it in their own dashboard via the dropdown.
- **Lightweight:** A typical JSON result is 20–100KB (compared to 200KB+ for the self-contained HTML report). The history directory stays lean.
