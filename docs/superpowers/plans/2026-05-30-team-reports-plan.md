# Team Reports and Scan History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-save every completed scan as a lightweight JSON file in `vibe-iterator-results/`, expose a two-route history API, and add a "Scan History" dropdown to the results dashboard so past scans can be browsed without re-running.

**Architecture:** New `vibe_iterator/history.py` holds the canonical serializer (`serialize_result`, `finding_dict`) and file helpers (`save_result`, `list_results`, `load_result`). `vibe_iterator/config.py` gains a `results_dir: Path` field. `routes.py` imports from `history.py` instead of defining its own serializers. Two new GET routes serve history. The results dashboard frontend adds a hidden panel that becomes visible once history exists.

**Tech Stack:** Python stdlib only — `pathlib`, `json`, `re`, `datetime`. FastAPI routes (existing pattern). Vanilla JS `fetch`. pytest + httpx for tests.

---

### Task 1: `vibe_iterator/history.py` + `tests/test_history.py`

**Files:**
- Create: `vibe_iterator/history.py`
- Create: `tests/test_history.py`

- [ ] **Step 1: Write failing tests in `tests/test_history.py`**

```python
"""Tests for history.py — JSON serializer, file management helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vibe_iterator.engine.runner import ScanResult, ScannerResult
from vibe_iterator.history import (
    finding_dict,
    list_results,
    load_result,
    save_result,
    serialize_result,
)
from vibe_iterator.scanners.base import Finding, Severity


def _make_finding() -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint="fp-1",
        scanner="test_scanner",
        severity=Severity.HIGH,
        title="Test Finding",
        description="A test vulnerability.",
        evidence={"request": {"url": "http://localhost:3000/api/test"}},
        screenshots=[],
        llm_prompt="Fix this.",
        remediation="Apply a patch.",
        category="injection",
        page="http://localhost:3000/api/test",
        timestamp=datetime.now(timezone.utc).isoformat(),
        mark_status="none",
        mark_note=None,
    )


def _make_result(stage: str = "pre-deploy", score: int = 72) -> ScanResult:
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        stage=stage,
        target="http://localhost:3000",
        status="completed",
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
        findings=[_make_finding()],
        scanner_results=[
            ScannerResult(
                scanner_name="auth_check",
                status="findings",
                findings_count=1,
                duration_seconds=2.1,
            ),
        ],
        finding_marks=[],
        score=score,
        score_grade="C",
        duration_seconds=5.3,
        pages_crawled=[{"url": "http://localhost:3000/", "status_code": 200}],
        requests_captured={"total": 10, "GET": 8, "POST": 2},
        stack_detected="custom",
        stack_detection_source="manually-configured",
        second_account_used=False,
        scanner_overrides_applied=None,
        discovered_surface=None,
    )


# ---------------------------------------------------------------------------
# finding_dict
# ---------------------------------------------------------------------------

def test_finding_dict_severity_is_string() -> None:
    f = _make_finding()
    d = finding_dict(f)
    assert d["severity"] == "high"
    assert isinstance(d["severity"], str)


def test_finding_dict_all_keys_present() -> None:
    f = _make_finding()
    d = finding_dict(f)
    for key in (
        "id", "fingerprint", "scanner", "severity", "title", "description",
        "evidence", "screenshots", "llm_prompt", "remediation", "category",
        "page", "timestamp", "mark_status", "mark_note",
    ):
        assert key in d, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# serialize_result
# ---------------------------------------------------------------------------

def test_serialize_result_structure() -> None:
    r = _make_result()
    d = serialize_result(r)
    for key in (
        "scan_id", "stage", "target", "status", "findings",
        "scanner_results", "finding_marks", "score", "score_grade",
        "discovered_surface",
    ):
        assert key in d, f"Missing top-level key: {key}"
    assert isinstance(d["findings"], list)
    assert d["findings"][0]["severity"] == "high"


def test_serialize_result_discovered_surface_none() -> None:
    r = _make_result()
    assert r.discovered_surface is None
    assert serialize_result(r)["discovered_surface"] is None


# ---------------------------------------------------------------------------
# save_result
# ---------------------------------------------------------------------------

def test_save_result_creates_file(tmp_path: Path) -> None:
    r = _make_result()
    path = save_result(r, tmp_path)
    assert path.exists()
    assert path.suffix == ".json"
    data = json.loads(path.read_text())
    assert data["scan_id"] == r.scan_id


def test_save_result_creates_directory(tmp_path: Path) -> None:
    results_dir = tmp_path / "vibe-iterator-results"
    assert not results_dir.exists()
    save_result(_make_result(), results_dir)
    assert results_dir.exists()


def test_save_result_filename_pattern(tmp_path: Path) -> None:
    import re
    path = save_result(_make_result(), tmp_path)
    assert re.match(r"result-\d{8}-\d{6}(-\d+)?\.json$", path.name)


def test_save_result_deduplication(tmp_path: Path, monkeypatch) -> None:
    # Two saves with the same mocked timestamp produce different filenames
    import vibe_iterator.history as hist_mod
    fixed_dt = datetime(2026, 5, 30, 14, 30, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(hist_mod, "_now", lambda: fixed_dt)
    r = _make_result()
    p1 = save_result(r, tmp_path)
    p2 = save_result(r, tmp_path)
    assert p1 != p2
    assert p2.stem.endswith("-2")


# ---------------------------------------------------------------------------
# list_results
# ---------------------------------------------------------------------------

def test_list_results_missing_directory(tmp_path: Path) -> None:
    assert list_results(tmp_path / "nonexistent") == []


def test_list_results_empty_directory(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    assert list_results(results_dir) == []


def test_list_results_sorted_newest_first(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    files = [
        ("result-20260530-100000.json", "2026-05-30T10:00:00Z"),
        ("result-20260530-120000.json", "2026-05-30T12:00:00Z"),
        ("result-20260530-080000.json", "2026-05-30T08:00:00Z"),
    ]
    for name, ts in files:
        (results_dir / name).write_text(json.dumps({
            "completed_at": ts,
            "stage": "dev",
            "target": "http://localhost:3000",
            "score": 80,
            "score_grade": "B",
            "findings": [],
            "status": "completed",
        }))
    items = list_results(results_dir)
    assert len(items) == 3
    assert items[0]["filename"] == "result-20260530-120000.json"
    assert items[2]["filename"] == "result-20260530-080000.json"


def test_list_results_skips_corrupt_file(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "result-20260530-100000.json").write_text(json.dumps({
        "completed_at": "2026-05-30T10:00:00Z",
        "stage": "dev",
        "target": "http://localhost:3000",
        "score": 80,
        "score_grade": "B",
        "findings": [],
        "status": "completed",
    }))
    (results_dir / "result-20260530-090000.json").write_text("NOT VALID JSON{{{{")
    items = list_results(results_dir)
    assert len(items) == 1
    assert items[0]["filename"] == "result-20260530-100000.json"


# ---------------------------------------------------------------------------
# load_result
# ---------------------------------------------------------------------------

def test_load_result_roundtrip(tmp_path: Path) -> None:
    r = _make_result()
    path = save_result(r, tmp_path)
    loaded = load_result(path.name, tmp_path)
    assert loaded["scan_id"] == r.scan_id
    assert loaded["stage"] == r.stage
    assert len(loaded["findings"]) == 1


def test_load_result_invalid_filename(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_result("../secrets.json", tmp_path)
    with pytest.raises(ValueError):
        load_result("notaresult.json", tmp_path)
    with pytest.raises(ValueError):
        load_result("result-bad.json", tmp_path)


def test_load_result_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_result("result-20260530-120000.json", tmp_path)
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/test_history.py -v
```

Expected: `ModuleNotFoundError` — `vibe_iterator.history` doesn't exist yet.

- [ ] **Step 3: Create `vibe_iterator/history.py`**

```python
"""Scan result persistence — JSON serializer, save/load helpers."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from vibe_iterator.engine.runner import ScanResult
from vibe_iterator.scanners.base import Finding


_FILENAME_RE = re.compile(r"^result-\d{8}-\d{6}(-\d+)?\.json$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "scanner": f.scanner,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "evidence": f.evidence,
        "screenshots": [{"label": s.label, "data": s.data} for s in f.screenshots],
        "llm_prompt": f.llm_prompt,
        "remediation": f.remediation,
        "category": f.category,
        "page": f.page,
        "timestamp": f.timestamp,
        "mark_status": f.mark_status,
        "mark_note": f.mark_note,
    }


def serialize_result(result: ScanResult) -> dict:
    return {
        "scan_id": result.scan_id,
        "stage": result.stage,
        "target": result.target,
        "status": result.status,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "findings": [finding_dict(f) for f in result.findings],
        "scanner_results": [
            {
                "scanner_name": sr.scanner_name,
                "status": sr.status,
                "findings_count": sr.findings_count,
                "duration_seconds": sr.duration_seconds,
                "skip_reason": sr.skip_reason,
            }
            for sr in result.scanner_results
        ],
        "finding_marks": [
            {"finding_id": m.finding_id, "status": m.status, "note": m.note}
            for m in result.finding_marks
        ],
        "score": result.score,
        "score_grade": result.score_grade,
        "duration_seconds": result.duration_seconds,
        "pages_crawled": result.pages_crawled,
        "requests_captured": result.requests_captured,
        "stack_detected": result.stack_detected,
        "stack_detection_source": result.stack_detection_source,
        "second_account_used": result.second_account_used,
        "scanner_overrides_applied": result.scanner_overrides_applied,
        "discovered_surface": {
            "pages": result.discovered_surface.pages,
            "api_endpoints": result.discovered_surface.api_endpoints,
            "discovered_at": result.discovered_surface.discovered_at,
        } if result.discovered_surface is not None else None,
    }


# ---------------------------------------------------------------------------
# File management
# ---------------------------------------------------------------------------

def save_result(result: ScanResult, results_dir: Path) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    base = _now().strftime("result-%Y%m%d-%H%M%S")
    candidate = results_dir / f"{base}.json"
    counter = 2
    while candidate.exists():
        candidate = results_dir / f"{base}-{counter}.json"
        counter += 1
    candidate.write_text(json.dumps(serialize_result(result), indent=2), encoding="utf-8")
    return candidate


def list_results(results_dir: Path) -> list[dict]:
    if not results_dir.exists():
        return []
    items: list[dict] = []
    for path in sorted(results_dir.glob("result-*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            items.append({
                "filename": path.name,
                "timestamp": data.get("completed_at") or data.get("started_at"),
                "stage": data.get("stage", ""),
                "target": data.get("target", ""),
                "score": data.get("score"),
                "score_grade": data.get("score_grade"),
                "finding_count": len(data.get("findings", [])),
                "status": data.get("status", ""),
            })
        except Exception as exc:
            print(f"[WARN] Skipping corrupt result file {path.name}: {exc}", file=sys.stderr)
    return items


def load_result(filename: str, results_dir: Path) -> dict:
    if not _FILENAME_RE.match(filename):
        raise ValueError(f"Invalid result filename: {filename!r}")
    path = results_dir / filename
    if not path.exists():
        raise FileNotFoundError(f"Result not found: {filename}")
    return json.loads(path.read_text(encoding="utf-8"))
```

- [ ] **Step 4: Run tests to confirm they pass**

```
pytest tests/test_history.py -v
```

Expected: all 13 tests pass.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/history.py tests/test_history.py
git commit -m "feat: add history module — serialize_result, save/list/load_result helpers"
```

---

### Task 2: Config `results_dir` field + routes.py serializer migration

**Files:**
- Modify: `vibe_iterator/config.py`
- Modify: `vibe_iterator/server/routes.py`

- [ ] **Step 1: Add `field` to the dataclasses import and add `results_dir` to Config**

In `vibe_iterator/config.py` line 6, change:

```python
from dataclasses import dataclass
```

to:

```python
from dataclasses import dataclass, field
```

Then in the `Config` dataclass, after the `spider_max_depth: int = 3` field (line 78), add:

```python
    # History
    results_dir: Path = field(default_factory=lambda: Path.cwd() / "vibe-iterator-results")
```

- [ ] **Step 2: Set `results_dir` from the YAML location in `load_config()`**

In `vibe_iterator/config.py`, in the `load_config()` function, add this line immediately before `return Config(...)` (after the stack block, around line 262):

```python
    results_dir = yaml_file.parent / "vibe-iterator-results"
```

Then add `results_dir=results_dir,` to the `return Config(...)` call:

```python
    return Config(
        target=target,
        test_email=test_email,
        test_password=test_password,
        test_email_2=test_email_2,
        test_password_2=test_password_2,
        supabase_url=supabase_url,
        supabase_anon_key=supabase_anon_key,
        pages=pages,
        stages=stages,
        stack=stack,
        port=port,
        scanner_timeout_seconds=scanner_timeout_seconds,
        spider_max_pages=spider_max_pages,
        spider_max_depth=spider_max_depth,
        results_dir=results_dir,
    )
```

- [ ] **Step 3: Run config tests to confirm no regressions**

```
pytest tests/test_config.py tests/test_config_sidecar.py -v
```

Expected: all existing tests pass.

- [ ] **Step 4: Migrate `routes.py` — delete local serializers, import from history.py**

In `vibe_iterator/server/routes.py`:

**Delete** the entire `_finding_dict` function (lines 71–88) and `_result_dict` function (lines 91–128).

**Add** this import in the imports section (after the existing `from vibe_iterator...` imports):

```python
from vibe_iterator.history import finding_dict, serialize_result
```

**Update `get_results`** (the line that was `return _result_dict(runner.get_result())`):

```python
    return serialize_result(runner.get_result())
```

**Update `get_finding`** (the line that was `return _finding_dict(f)`):

```python
            return finding_dict(f)
```

- [ ] **Step 5: Run routes tests to confirm migration didn't break anything**

```
pytest tests/test_server/test_routes.py -v
```

Expected: all existing tests pass.

- [ ] **Step 6: Commit**

```
git add vibe_iterator/config.py vibe_iterator/server/routes.py
git commit -m "refactor: centralize serializers in history.py; add results_dir to Config"
```

---

### Task 3: Auto-save in CLI and GUI mode

**Files:**
- Modify: `vibe_iterator/cli.py`
- Modify: `vibe_iterator/server/routes.py`

- [ ] **Step 1: Add auto-save to `_run_headless()` in `cli.py`**

In `vibe_iterator/cli.py`, after the try/except block that calls `asyncio.run(runner.run(stage))` and before the `click.echo("...Complete...")` line, insert:

```python
    from vibe_iterator.history import save_result
    try:
        saved_path = save_result(result, config.results_dir)
        click.echo(f"[vibe-iterator] Result saved to: {saved_path}")
    except Exception as exc:
        click.echo(f"[WARN] Could not save result: {exc}", err=True)
```

The full updated block (lines 161–181 after the change):

```python
    try:
        import asyncio

        runner = ScanRunner(config, on_event=_event_handler, browser_headless=headless)
        result = asyncio.run(runner.run(stage))
    except Exception as exc:
        click.echo(f"[ERROR] Scan failed: {exc}", err=True)
        sys.exit(1)

    from vibe_iterator.history import save_result
    try:
        saved_path = save_result(result, config.results_dir)
        click.echo(f"[vibe-iterator] Result saved to: {saved_path}")
    except Exception as exc:
        click.echo(f"[WARN] Could not save result: {exc}", err=True)

    click.echo(
        f"[vibe-iterator] Complete: status={result.status} "
        f"findings={len(result.findings)} score={result.score or 'n/a'}"
    )
    if output:
        try:
            from vibe_iterator.report.generator import generate
            generate(result, output_path=output)
            click.echo(f"[vibe-iterator] Report saved to: {output}")
        except Exception as exc:
            click.echo(f"[ERROR] Could not write report: {exc}", err=True)
```

- [ ] **Step 2: Add auto-save to `_on_done` callback in `routes.py`**

In `vibe_iterator/server/routes.py`, inside `start_scan`, replace the `_on_done` function:

**Before:**
```python
    def _on_done(t: asyncio.Task) -> None:
        if not t.cancelled() and t.exception():
            logger.exception("Background scan task failed", exc_info=t.exception())
```

**After:**
```python
    def _on_done(t: asyncio.Task) -> None:
        if not t.cancelled() and t.exception():
            logger.exception("Background scan task failed", exc_info=t.exception())
            return
        result = new_runner.get_result()
        if result is not None:
            from vibe_iterator.history import save_result
            try:
                save_result(result, config.results_dir)
            except Exception as exc:
                logger.warning("Could not save scan result: %s", exc)
```

`config` and `new_runner` are both defined earlier in the enclosing `start_scan` scope, so the closure captures them correctly without any extra plumbing.

- [ ] **Step 3: Run full suite to confirm no regressions**

```
pytest tests/ -q --tb=short
```

Expected: all tests pass. (Auto-save path is not exercised by unit tests; route tests use a MagicMock config whose `.results_dir` attribute is itself a MagicMock — `save_result` is never called by existing tests since they don't trigger `_on_done`.)

- [ ] **Step 4: Commit**

```
git add vibe_iterator/cli.py vibe_iterator/server/routes.py
git commit -m "feat: auto-save scan results to vibe-iterator-results/ on scan completion"
```

---

### Task 4: History API routes + `tests/test_server/test_history_routes.py`

**Files:**
- Modify: `vibe_iterator/server/routes.py`
- Create: `tests/test_server/test_history_routes.py`

- [ ] **Step 1: Write failing tests in `tests/test_server/test_history_routes.py`**

```python
"""Tests for GET /api/history and GET /api/history/{filename}."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from vibe_iterator.history import save_result
from vibe_iterator.server.app import create_app
from tests.test_server.test_routes import _make_config, _make_scan_result


def _config_with_results_dir(results_dir: Path) -> MagicMock:
    cfg = _make_config()
    cfg.results_dir = results_dir
    return cfg


async def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ---------------------------------------------------------------------------
# GET /api/history
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_history_empty(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get("/api/history")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_get_history_with_results(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    save_result(_make_scan_result(), results_dir)
    save_result(_make_scan_result(), results_dir)

    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get("/api/history")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 2
    for item in items:
        assert "filename" in item
        assert "stage" in item
        assert "score" in item
        assert "finding_count" in item


# ---------------------------------------------------------------------------
# GET /api/history/{filename}
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_historical_result_ok(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    result = _make_scan_result()
    path = save_result(result, results_dir)

    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get(f"/api/history/{path.name}")
    assert r.status_code == 200
    data = r.json()
    assert data["scan_id"] == result.scan_id
    assert data["stage"] == result.stage
    assert "findings" in data


@pytest.mark.asyncio
async def test_get_historical_result_invalid_name(tmp_path: Path) -> None:
    app = create_app(_config_with_results_dir(tmp_path))
    async with await _client(app) as c:
        r = await c.get("/api/history/notaresult.json")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_get_historical_result_not_found(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    app = create_app(_config_with_results_dir(results_dir))
    async with await _client(app) as c:
        r = await c.get("/api/history/result-20260530-120000.json")
    assert r.status_code == 404
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/test_server/test_history_routes.py -v
```

Expected: `404 Not Found` for all history routes — they don't exist yet.

- [ ] **Step 3: Add history routes to `routes.py`**

In `vibe_iterator/server/routes.py`, add the two new routes immediately after `get_finding` (after the `raise HTTPException(status_code=404, ...)` line around 276) and before `@router.post("/api/scan/findings/mark")`:

```python
@router.get("/api/history")
async def get_history(request: Request) -> list:
    from vibe_iterator.history import list_results
    config = request.app.state.config
    return list_results(config.results_dir)


@router.get("/api/history/{filename}")
async def get_historical_result(filename: str, request: Request) -> dict:
    from vibe_iterator.history import load_result
    config = request.app.state.config
    try:
        return load_result(filename, config.results_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Result not found")
```

- [ ] **Step 4: Run history route tests to confirm they pass**

```
pytest tests/test_server/test_history_routes.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Run full server test suite**

```
pytest tests/test_server/ -v
```

Expected: all tests pass (existing routes unaffected by the new routes).

- [ ] **Step 6: Commit**

```
git add vibe_iterator/server/routes.py tests/test_server/test_history_routes.py
git commit -m "feat: add GET /api/history and GET /api/history/{filename} routes"
```

---

### Task 5: Frontend — history panel HTML, CSS, and JS

**Files:**
- Modify: `vibe_iterator/server/static/results.html`
- Modify: `vibe_iterator/server/static/css/dashboard.css`
- Modify: `vibe_iterator/server/static/js/app.js`

No automated tests — validate by running the dashboard manually (see Step 5).

- [ ] **Step 1: Add history panel HTML to `results.html`**

In `vibe_iterator/server/static/results.html`, insert the following block immediately before `<!-- Executive Summary -->` (before line 31 — the `<div class="exec-summary" id="exec-summary">` element):

```html
<!-- Scan History -->
<div id="history-panel" class="history-panel" style="display:none">
  <span class="history-label">SCAN HISTORY</span>
  <select id="history-select" class="history-select" onchange="loadHistoricalResult(this.value)">
    <!-- populated by loadHistory() -->
  </select>
</div>

```

- [ ] **Step 2: Add history panel CSS to `dashboard.css`**

Append to the end of `vibe_iterator/server/static/css/dashboard.css`:

```css
/* ---- Scan History Panel ---- */
.history-panel {
  display: flex;
  align-items: center;
  gap: 1rem;
  background: var(--bg-card-2);
  border: 1px solid var(--border-bright);
  border-radius: var(--radius);
  padding: 0.75rem 1.5rem;
  margin: 0 auto 1rem;
  max-width: 1100px;
}

.history-label {
  font-size: 11px;
  letter-spacing: 0.12em;
  color: var(--cyan);
  white-space: nowrap;
  font-family: var(--font-mono);
}

.history-select {
  flex: 1;
  background: var(--bg-card);
  border: 1px solid var(--border-bright);
  border-radius: 4px;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 0.4rem 0.6rem;
  cursor: pointer;
}

.history-select:focus {
  outline: none;
  border-color: var(--cyan);
}
```

- [ ] **Step 3: Refactor `initResultsPage()` and add history functions in `app.js`**

In `vibe_iterator/server/static/js/app.js`, replace the existing `initResultsPage()` function (lines 729–763) with the following two functions:

```javascript
function renderResults(data) {
  _allFindings = data.findings;
  renderExecSummary(data);
  renderFindings(data);
  renderPassedChecks(data);
  setupResultsFilters();
  setupMarkActions();
  setupActionBar(data);
  checkCompareAvailability(data);
  checkDeepDiveHash();
  renderDiscoverySurface(data);
}

async function initResultsPage() {
  try {
    _results = await apiFetch('/api/scan/results');
  } catch (e) {
    if (e.status === 404) {
      document.getElementById('findings-container').innerHTML =
        '<div class="empty-state">No scan results found. <a href="/">Run a scan first →</a></div>';
      return;
    }
    document.getElementById('findings-container').innerHTML =
      `<div class="empty-state">Error loading results: ${escHtml(e.message)}</div>`;
    return;
  }

  if (_results.status === 'running') {
    window.location.href = '/scan';
    return;
  }

  renderResults(_results);
  await loadHistory();

  // Re-scan goes back home with same stage pre-selected
  document.getElementById('rescan-btn').addEventListener('click', () => {
    window.location.href = '/';
  });
}
```

Then add the two history functions immediately after `initResultsPage()`:

```javascript
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const items = await res.json();
    if (!items.length) return;

    const panel = document.getElementById('history-panel');
    const select = document.getElementById('history-select');
    panel.style.display = 'flex';

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
    renderResults(_results);
    return;
  }
  try {
    const res = await fetch(`/api/history/${encodeURIComponent(filename)}`);
    if (!res.ok) { console.warn('History load failed:', res.status); return; }
    const data = await res.json();
    renderResults(data);
  } catch (e) {
    console.warn('Could not load historical result:', e);
  }
}
```

- [ ] **Step 4: Run the full test suite to confirm no regressions**

```
pytest tests/ -q --tb=short
```

Expected: all tests pass.

- [ ] **Step 5: Manual smoke test — verify the dropdown works**

1. Start the dashboard: `vibe-iterator`
2. Run a scan to completion — confirm terminal prints `[vibe-iterator] Result saved to: vibe-iterator-results/result-*.json`
3. Navigate to the results page — the history dropdown should be hidden (only one entry matches the current scan)
4. Run a second scan (same or different stage)
5. Navigate to the results page — the "SCAN HISTORY" panel appears with a dropdown showing 2 entries (newest first)
6. Switch to the older scan in the dropdown — results update to show that scan's findings
7. Switch back to "(current scan)" — current results reload
8. Confirm that switching dropdown entries never navigates away from the results page

- [ ] **Step 6: Commit**

```
git add vibe_iterator/server/static/results.html vibe_iterator/server/static/css/dashboard.css vibe_iterator/server/static/js/app.js
git commit -m "feat: add Scan History dropdown panel to results dashboard"
```

---

### Task 6: Full suite verification

**Files:** None (verification only)

- [ ] **Step 1: Run the complete test suite**

```
pytest tests/ -v --tb=short
```

Expected: all tests pass, including:
- 13 tests in `tests/test_history.py`
- 5 tests in `tests/test_server/test_history_routes.py`
- All pre-existing tests unchanged

- [ ] **Step 2: Confirm `vibe-iterator-results/` is in `.gitignore`**

```
python -c "
text = open('.gitignore').read()
assert 'vibe-iterator-results/' in text, 'Missing gitignore entry'
print('gitignore OK')
"
```

If missing, add to `.gitignore`:

```
vibe-iterator-results/
```

Then commit:

```
git add .gitignore
git commit -m "chore: gitignore vibe-iterator-results/ directory"
```

---

## Self-Review

**Spec coverage:**

| Spec requirement | Task that implements it |
|---|---|
| `history.py` — `serialize_result`, `save_result`, `list_results`, `load_result` | Task 1 ✅ |
| `_finding_dict` logic moved to `history.py` as `finding_dict` | Task 1 ✅ |
| `Config.results_dir` field with default | Task 2 ✅ |
| `load_config()` sets `results_dir = yaml_file.parent / "vibe-iterator-results"` | Task 2 ✅ |
| `routes.py` imports from history.py instead of its own serializers | Task 2 ✅ |
| Auto-save in CLI headless mode | Task 3 ✅ |
| Auto-save in GUI mode (`_on_done` callback) | Task 3 ✅ |
| `GET /api/history` route | Task 4 ✅ |
| `GET /api/history/{filename}` route (400 invalid, 404 not found) | Task 4 ✅ |
| `<div id="history-panel">` in results.html | Task 5 ✅ |
| CSS for history panel | Task 5 ✅ |
| `renderResults(data)` extracted from `initResultsPage()` | Task 5 ✅ |
| `loadHistory()` fetches and populates dropdown | Task 5 ✅ |
| `loadHistoricalResult(filename)` loads and renders past result | Task 5 ✅ |
| `.gitignore` entry for `vibe-iterator-results/` | Task 6 ✅ |

**Placeholder scan:** No TBDs or incomplete steps found.

**Type consistency:**
- `finding_dict(f: Finding) -> dict` — defined in Task 1, imported in Task 2 and Task 4.
- `serialize_result(result: ScanResult) -> dict` — defined in Task 1, imported in Task 2 (replaces `_result_dict`) and used by `save_result` in Task 1.
- `save_result(result: ScanResult, results_dir: Path) -> Path` — defined in Task 1, called in Task 3.
- `list_results(results_dir: Path) -> list[dict]` — defined in Task 1, called in Task 4.
- `load_result(filename: str, results_dir: Path) -> dict` — defined in Task 1, called in Task 4.
- `config.results_dir: Path` — added in Task 2, consumed in Task 3 (`save_result(result, config.results_dir)`) and Task 4 routes.
- `renderResults(data)` — defined in Task 5, called from both `initResultsPage()` and `loadHistoricalResult()`.

All names consistent across tasks.

**`get_finding` route:** Uses `_finding_dict` (old name) — Task 2 Step 4 explicitly renames it to `finding_dict` in the import and the return statement. ✅

**`_on_done` closure:** `config` and `new_runner` are both defined in `start_scan`'s local scope before `_on_done` is defined, so the closure captures both correctly. ✅
