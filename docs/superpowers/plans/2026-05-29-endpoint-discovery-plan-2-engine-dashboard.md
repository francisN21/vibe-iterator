# Endpoint Discovery — Plan 2: Engine, Config, API, Dashboard & Docs

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the spider module into the scan engine (discover stage routing), add sidecar merging to config loading, expose `discovered_surface` in the API, add a "Discover Endpoints" button to the dashboard, and update docs.

**Architecture:** All changes are additive — no existing scan pipeline is modified. `runner.py` gets an early-exit branch for `stage == "discover"`. `config.py` gets sidecar merging after YAML parsing. `routes.py` gets a bypass for the discover stage in the validation block. Dashboard gets one new button and one new results panel.

**Tech Stack:** Python, FastAPI, HTML, JavaScript, CSS, YAML

**Prerequisite:** Plan 1 complete (all spider components and discover_runner passing tests).

**Spec:** `docs/superpowers/specs/2026-05-29-endpoint-discovery-design.md`

---

## Task 1: `ScanResult.discovered_surface` + API serialization + route bypass

**Files:**
- Modify: `vibe_iterator/engine/runner.py` (add `discovered_surface` field to `ScanResult`)
- Modify: `vibe_iterator/server/routes.py` (add to `_result_dict`; bypass discover in stage validation)
- Create: `tests/test_engine/test_discover_result_serialization.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_engine/test_discover_result_serialization.py
"""Tests for discovered_surface field in ScanResult and _result_dict serialization."""
from __future__ import annotations
from vibe_iterator.engine.runner import ScanResult, ScannerResult
from vibe_iterator.server.routes import _result_dict


def _base_result(**overrides) -> ScanResult:
    defaults = dict(
        scan_id="abc123", stage="pre-deploy", target="http://localhost:3000",
        status="completed", started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:01:00Z",
        findings=[], scanner_results=[], finding_marks=[],
        score=100, score_grade="A", duration_seconds=5.0,
        pages_crawled=[], requests_captured={"total": 0, "GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0},
        stack_detected="custom", stack_detection_source="auto-detect",
        second_account_used=False, scanner_overrides_applied=None,
        discovered_surface=None,
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


def test_discovered_surface_none_by_default():
    r = _base_result()
    assert r.discovered_surface is None


def test_result_dict_includes_discovered_surface_none():
    r = _base_result()
    d = _result_dict(r)
    assert "discovered_surface" in d
    assert d["discovered_surface"] is None


def test_result_dict_serializes_discovery_result():
    from vibe_iterator.engine.discover_runner import DiscoveryResult
    ds = DiscoveryResult(
        pages=["/", "/about"],
        api_endpoints=["GET /api/users"],
        discovered_at="2026-01-01T00:00:00Z",
    )
    r = _base_result(stage="discover", discovered_surface=ds)
    d = _result_dict(r)
    assert d["discovered_surface"]["pages"] == ["/", "/about"]
    assert d["discovered_surface"]["api_endpoints"] == ["GET /api/users"]
    assert d["discovered_surface"]["discovered_at"] == "2026-01-01T00:00:00Z"
```

- [ ] **Step 2: Run tests to verify they fail**

```
py -m pytest tests/test_engine/test_discover_result_serialization.py -v
```
Expected: `TypeError` — `ScanResult.__init__() got an unexpected keyword argument 'discovered_surface'`

- [ ] **Step 3: Add `discovered_surface` to `ScanResult` in `runner.py`**

In `vibe_iterator/engine/runner.py`, add the import at the top (after existing imports):

```python
from vibe_iterator.engine.discover_runner import DiscoveryResult
```

Then in the `ScanResult` dataclass (around line 63), add `discovered_surface` as the last field:

```python
@dataclass
class ScanResult:
    """Full result of a completed (or in-progress) scan run."""

    scan_id: str
    stage: str
    target: str
    status: str
    started_at: str
    completed_at: str | None
    findings: list[Finding]
    scanner_results: list[ScannerResult]
    finding_marks: list[FindingMark]
    score: int | None
    score_grade: str | None
    duration_seconds: float | None
    pages_crawled: list[dict]
    requests_captured: dict
    stack_detected: str
    stack_detection_source: str
    second_account_used: bool
    scanner_overrides_applied: list[str] | None
    discovered_surface: DiscoveryResult | None = None
```

- [ ] **Step 4: Update `_result_dict` in `routes.py`**

In `vibe_iterator/server/routes.py`, find `_result_dict` (around line 91). Add `discovered_surface` to the returned dict. The full updated function:

```python
def _result_dict(r: ScanResult) -> dict:
    ds = r.discovered_surface
    return {
        "scan_id": r.scan_id,
        "stage": r.stage,
        "target": r.target,
        "status": r.status,
        "started_at": r.started_at,
        "completed_at": r.completed_at,
        "findings": [_finding_dict(f) for f in r.findings],
        "scanner_results": [
            {
                "scanner_name": sr.scanner_name,
                "status": sr.status,
                "findings_count": sr.findings_count,
                "duration_seconds": sr.duration_seconds,
                "skip_reason": sr.skip_reason,
            }
            for sr in r.scanner_results
        ],
        "finding_marks": [
            {"finding_id": m.finding_id, "status": m.status, "note": m.note}
            for m in r.finding_marks
        ],
        "score": r.score,
        "score_grade": r.score_grade,
        "duration_seconds": r.duration_seconds,
        "pages_crawled": r.pages_crawled,
        "requests_captured": r.requests_captured,
        "stack_detected": r.stack_detected,
        "stack_detection_source": r.stack_detection_source,
        "second_account_used": r.second_account_used,
        "scanner_overrides_applied": r.scanner_overrides_applied,
        "discovered_surface": {
            "pages": ds.pages,
            "api_endpoints": ds.api_endpoints,
            "discovered_at": ds.discovered_at,
        } if ds is not None else None,
    }
```

- [ ] **Step 5: Bypass stage validation for `discover` in `start_scan`**

In `vibe_iterator/server/routes.py`, find the `start_scan` handler (around line 181). The current validation block:

```python
    # Validate stage
    stage_scanners = config.scanners_for_stage(body.stage)
    if not stage_scanners:
        raise HTTPException(status_code=400, detail=f"Unknown stage: '{body.stage}'")
    if body.scanner_overrides is not None:
        if not body.scanner_overrides:
            raise HTTPException(status_code=400, detail="scanner_overrides must include at least one scanner.")
        invalid = [s for s in body.scanner_overrides if s not in stage_scanners]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid scanner_overrides for stage '{body.stage}': {invalid}. "
                    f"Valid names: {stage_scanners}"
                ),
            )
```

Replace with:

```python
    # Validate stage — 'discover' is a special stage (no scanner list)
    if body.stage != "discover":
        stage_scanners = config.scanners_for_stage(body.stage)
        if not stage_scanners:
            raise HTTPException(status_code=400, detail=f"Unknown stage: '{body.stage}'")
        if body.scanner_overrides is not None:
            if not body.scanner_overrides:
                raise HTTPException(status_code=400, detail="scanner_overrides must include at least one scanner.")
            invalid = [s for s in body.scanner_overrides if s not in stage_scanners]
            if invalid:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Invalid scanner_overrides for stage '{body.stage}': {invalid}. "
                        f"Valid names: {stage_scanners}"
                    ),
                )
```

- [ ] **Step 6: Run tests to verify they pass**

```
py -m pytest tests/test_engine/test_discover_result_serialization.py -v
```
Expected: 3 PASSED

- [ ] **Step 7: Commit**

```
git add vibe_iterator/engine/runner.py vibe_iterator/server/routes.py tests/test_engine/test_discover_result_serialization.py
git commit -m "feat: add discovered_surface to ScanResult, _result_dict, bypass discover stage validation"
```

---

## Task 2: Config sidecar merging — load discovered pages into `config.pages`

**Files:**
- Modify: `vibe_iterator/config.py` (merge sidecar at end of `load_config`)
- Create: `tests/test_config_sidecar.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_sidecar.py
"""Test that load_config merges vibe-iterator.discovered.yaml into config.pages."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import yaml
import pytest
from vibe_iterator.config import load_config


def _write_yaml(path: Path, data: dict) -> None:
    with path.open("w") as fh:
        yaml.dump(data, fh)


def test_sidecar_pages_merged_into_config():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Write minimal config YAML
        _write_yaml(tmp_path / "vibe-iterator.config.yaml", {
            "target": "http://localhost:3000",
            "pages": ["/", "/login"],
        })
        # Write sidecar with extra pages
        _write_yaml(tmp_path / "vibe-iterator.discovered.yaml", {
            "pages": ["/about", "/admin"],
            "api_endpoints": ["GET /api/users"],
            "discovered_at": "2026-01-01T00:00:00Z",
        })
        env = {
            "VIBE_ITERATOR_TEST_EMAIL": "test@example.com",
            "VIBE_ITERATOR_TEST_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env):
            cfg = load_config(yaml_path=tmp_path / "vibe-iterator.config.yaml")
        assert "/about" in cfg.pages
        assert "/admin" in cfg.pages
        assert "/" in cfg.pages
        assert "/login" in cfg.pages


def test_no_sidecar_leaves_pages_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write_yaml(tmp_path / "vibe-iterator.config.yaml", {
            "target": "http://localhost:3000",
            "pages": ["/", "/login"],
        })
        env = {
            "VIBE_ITERATOR_TEST_EMAIL": "test@example.com",
            "VIBE_ITERATOR_TEST_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env):
            cfg = load_config(yaml_path=tmp_path / "vibe-iterator.config.yaml")
        assert cfg.pages == ["/", "/login"]


def test_sidecar_does_not_duplicate_existing_pages():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _write_yaml(tmp_path / "vibe-iterator.config.yaml", {
            "target": "http://localhost:3000",
            "pages": ["/", "/login"],
        })
        _write_yaml(tmp_path / "vibe-iterator.discovered.yaml", {
            "pages": ["/", "/about"],   # "/" already in config
            "api_endpoints": [],
            "discovered_at": "2026-01-01T00:00:00Z",
        })
        env = {
            "VIBE_ITERATOR_TEST_EMAIL": "test@example.com",
            "VIBE_ITERATOR_TEST_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env):
            cfg = load_config(yaml_path=tmp_path / "vibe-iterator.config.yaml")
        assert cfg.pages.count("/") == 1  # no duplicate
        assert "/about" in cfg.pages
```

- [ ] **Step 2: Run tests to verify they fail**

```
py -m pytest tests/test_config_sidecar.py -v
```
Expected: 3 FAILED — `AssertionError: '/about' not in cfg.pages`

- [ ] **Step 3: Add sidecar merging to `load_config`**

In `vibe_iterator/config.py`, find the `pages` section (around line 188). After `pages: list[str] = [str(p) for p in pages_raw]`, add the sidecar merge block. The complete pages section becomes:

```python
    # ------------------------------------------------------------------ #
    # Pages                                                               #
    # ------------------------------------------------------------------ #
    pages_raw = yaml_data.get("pages", _DEFAULT_PAGES)
    if not isinstance(pages_raw, list) or not pages_raw:
        import warnings
        warnings.warn(
            "No pages configured in vibe-iterator.config.yaml — using defaults.",
            stacklevel=2,
        )
        pages_raw = _DEFAULT_PAGES
    pages: list[str] = [str(p) for p in pages_raw]

    # Merge sidecar discovered pages (vibe-iterator.discovered.yaml beside config)
    _sidecar_path = yaml_file.parent / "vibe-iterator.discovered.yaml"
    if _sidecar_path.exists():
        try:
            with _sidecar_path.open(encoding="utf-8") as _fh:
                _sidecar_data = yaml.safe_load(_fh) or {}
            _sidecar_pages = _sidecar_data.get("pages", [])
            if isinstance(_sidecar_pages, list):
                _existing = set(pages)
                for _p in _sidecar_pages:
                    _p = str(_p)
                    if _p not in _existing:
                        pages.append(_p)
                        _existing.add(_p)
        except Exception:
            pass  # sidecar load failure is non-fatal
```

- [ ] **Step 4: Run tests to verify they pass**

```
py -m pytest tests/test_config_sidecar.py -v
```
Expected: 3 PASSED

- [ ] **Step 5: Commit**

```
git add vibe_iterator/config.py tests/test_config_sidecar.py
git commit -m "feat: merge vibe-iterator.discovered.yaml pages into config.pages on load"
```

---

## Task 3: Engine routing — `discover` stage delegates to `discover_runner`

**Files:**
- Modify: `vibe_iterator/engine/runner.py` (add `_run_discovery` method + early-exit in `run`)
- Create: `tests/test_engine/test_discover_stage_routing.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_engine/test_discover_stage_routing.py
"""Test that runner.run('discover') routes to discover_runner, not scanner pipeline."""
from __future__ import annotations
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from vibe_iterator.engine.runner import ScanRunner
from vibe_iterator.engine.discover_runner import DiscoveryResult


def _make_config() -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.pages = ["/"]
    cfg.spider_max_pages = 30
    cfg.spider_max_depth = 3
    cfg.stack.backend = "custom"
    cfg.stack.detection_source = "auto-detect"
    return cfg


def test_discover_stage_returns_completed_result():
    config = _make_config()
    runner = ScanRunner(config, on_event=lambda e: None, scan_id="test-123")

    mock_discovery = DiscoveryResult(
        pages=["/", "/about"],
        api_endpoints=["GET /api/users"],
        discovered_at="2026-01-01T00:00:00Z",
    )

    with patch("vibe_iterator.engine.runner.browser_mod") as mock_browser, \
         patch("vibe_iterator.engine.runner.run_discovery", return_value=mock_discovery) as mock_run, \
         patch("vibe_iterator.engine.runner.NetworkListener") as mock_net_cls:
        mock_session = MagicMock()
        mock_browser.launch.return_value = mock_session
        mock_network = MagicMock()
        mock_net_cls.return_value = mock_network

        result = asyncio.run(runner.run("discover"))

    assert result.stage == "discover"
    assert result.status == "completed"
    assert result.discovered_surface is not None
    assert result.discovered_surface.pages == ["/", "/about"]
    assert result.scanner_results == []  # no scanners run


def test_discover_stage_does_not_run_scanner_pipeline():
    config = _make_config()
    runner = ScanRunner(config, on_event=lambda e: None, scan_id="test-456")

    mock_discovery = DiscoveryResult(pages=[], api_endpoints=[], discovered_at="")

    with patch("vibe_iterator.engine.runner.browser_mod") as mock_browser, \
         patch("vibe_iterator.engine.runner.run_discovery", return_value=mock_discovery), \
         patch("vibe_iterator.engine.runner.NetworkListener") as mock_net_cls, \
         patch("vibe_iterator.engine.runner._load_scanner") as mock_load:
        mock_browser.launch.return_value = MagicMock()
        mock_net_cls.return_value = MagicMock()

        asyncio.run(runner.run("discover"))

    mock_load.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

```
py -m pytest tests/test_engine/test_discover_stage_routing.py -v
```
Expected: FAILED — `ValueError: Unknown stage 'discover' or stage has no scanners configured.`

- [ ] **Step 3: Add imports and `_run_discovery` method to `runner.py`**

In `vibe_iterator/engine/runner.py`, at the top of the file, add module-level imports (alongside the existing imports at the bottom of the import block):

```python
# Imported lazily inside methods to avoid circular imports at module load time:
# from vibe_iterator.crawler import browser as browser_mod  — already done inside run()
# Add discover_runner imports for the discover stage
from vibe_iterator.engine.discover_runner import DiscoveryResult, run_discovery
```

Wait — `run_discovery` needs to be imported. But `discover_runner` imports from `config` and `listeners`. There's no circular dependency. Add to the top-level imports in `runner.py`:

```python
from vibe_iterator.engine.discover_runner import DiscoveryResult, run_discovery
```

(This replaces the earlier `from vibe_iterator.engine.discover_runner import DiscoveryResult` added in Task 1.)

Then in `ScanRunner.run()`, add the early-exit check as the **first thing inside the method body**, before any existing code:

```python
    async def run(self, stage: str) -> ScanResult:
        """Execute all scanners for the given stage and return the ScanResult."""
        # Discover stage: route to spider pipeline instead of scanner pipeline
        if stage == "discover":
            return await self._run_discovery()

        from vibe_iterator.crawler import browser as browser_mod
        # ... rest of existing method unchanged
```

Then add the `_run_discovery` method to `ScanRunner` (after `run`, before `_emit`):

```python
    async def _run_discovery(self) -> ScanResult:
        """Run the spider/discovery pipeline and return a ScanResult."""
        from vibe_iterator.crawler import browser as browser_mod
        from vibe_iterator.listeners.network import NetworkListener

        scan_id = self.scan_id
        started_at = datetime.now(timezone.utc).isoformat()
        scan_start = time.monotonic()

        self._result = ScanResult(
            scan_id=scan_id,
            stage="discover",
            target=self.config.target,
            status="running",
            started_at=started_at,
            completed_at=None,
            findings=[],
            scanner_results=[],
            finding_marks=[],
            score=None,
            score_grade=None,
            duration_seconds=None,
            pages_crawled=[],
            requests_captured={"total": 0, "GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0},
            stack_detected=self.config.stack.backend,
            stack_detection_source=self.config.stack.detection_source,
            second_account_used=False,
            scanner_overrides_applied=None,
            discovered_surface=None,
        )

        self._emit("scan_started", {
            "stage": "discover",
            "target": self.config.target,
            "scanner_count": 0,
            "scanner_names": [],
            "pages": self.config.pages,
        })

        session = None
        network = NetworkListener()
        try:
            session = browser_mod.launch(headless=self.browser_headless)
            network.attach(session)

            def _on_progress(msg: str) -> None:
                self._emit("scanner_progress", {
                    "scanner_name": "spider",
                    "message": msg,
                    "level": "info",
                })

            discovery = run_discovery(
                self.config, session, network,
                on_progress=_on_progress,
            )
            self._result.discovered_surface = discovery
            self._result.requests_captured = network.summary()
            self._result.status = "completed"
            self._result.completed_at = datetime.now(timezone.utc).isoformat()
            self._result.duration_seconds = round(time.monotonic() - scan_start, 2)

            self._emit("scan_completed", {
                "total_findings": 0,
                "by_severity": {},
                "duration_seconds": self._result.duration_seconds,
                "score": None,
                "score_grade": None,
                "scanners_run": 0,
                "scanners_skipped": 0,
            })

        except Exception as exc:
            logger.exception("Discovery run failed")
            self._emit("scan_error", {
                "error_type": "browser_crash",
                "error": str(exc),
                "recoverable": False,
            })
            if self._result:
                self._result.status = "error"
                self._result.completed_at = datetime.now(timezone.utc).isoformat()
                self._result.duration_seconds = round(time.monotonic() - scan_start, 2)

        finally:
            if session:
                session.quit()
            try:
                network.detach()
            except Exception:
                pass

        assert self._result is not None
        return self._result
```

The test patches `vibe_iterator.engine.runner.browser_mod`, `vibe_iterator.engine.runner.run_discovery`, and `vibe_iterator.engine.runner.NetworkListener`. For these patches to work, all three must be **module-level names** in `runner.py` (not lazily imported inside methods).

Add these two imports at the top of `runner.py` (alongside the other existing top-level imports):

```python
from vibe_iterator.crawler import browser as browser_mod
from vibe_iterator.listeners.network import NetworkListener
```

Then remove the lazy versions of both from inside `run()`:
- Remove: `from vibe_iterator.crawler import browser as browser_mod`
- Remove: `from vibe_iterator.listeners.network import NetworkListener`

The `auth_mod`, `nav_mod`, `ConsoleListener`, and `StorageListener` imports can remain lazy inside `run()` — they are not used by `_run_discovery` and do not need to be patched.

- [ ] **Step 4: Run tests to verify they pass**

```
py -m pytest tests/test_engine/test_discover_stage_routing.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: Commit**

```
git add vibe_iterator/engine/runner.py tests/test_engine/test_discover_stage_routing.py
git commit -m "feat: add discover stage routing to ScanRunner._run_discovery"
```

---

## Task 4: Dashboard home — "Discover Endpoints" button

**Files:**
- Modify: `vibe_iterator/server/static/index.html`
- Modify: `vibe_iterator/server/static/js/app.js`
- Modify: `vibe_iterator/server/static/css/dashboard.css`

No automated test — verify visually by running `vibe-iterator` and checking the home page.

- [ ] **Step 1: Add the Discover button to `index.html`**

In `vibe_iterator/server/static/index.html`, find the `<!-- Start scan -->` comment (around line 105). Insert the Discover button **before** the START SCAN button:

```html
  <!-- Discover Endpoints button -->
  <button class="btn btn-ghost btn-discover" id="discover-btn" type="button">
    &#x1F50E; DISCOVER ENDPOINTS
  </button>

  <!-- Start scan -->
  <button class="btn btn-primary btn-start-scan" id="start-btn" disabled>
    START SCAN
  </button>
```

- [ ] **Step 2: Add `startDiscovery()` to `app.js` and wire it in `initHomePage`**

In `vibe_iterator/server/static/js/app.js`, find `initHomePage()` (around line 65). Add the discover button event listener after the start-btn listener:

```javascript
  document.getElementById('start-btn').addEventListener('click', onStartScan);
  document.getElementById('cancel-existing-btn').addEventListener('click', cancelExistingAndStart);
  document.getElementById('discover-btn').addEventListener('click', startDiscovery);
```

Then add `startDiscovery()` after the existing `startFirebaseScan()` function (before the `// SCAN PAGE` section divider):

```javascript
async function startDiscovery() {
  try {
    await apiFetch('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify({ stage: 'discover' }),
    });
    window.location.href = '/scan?stage=discover';
  } catch (e) {
    if (e.status === 409) {
      document.getElementById('running-modal').classList.add('open');
    } else {
      showToast('Failed to start discovery: ' + e.message);
    }
  }
}
```

- [ ] **Step 3: Add button styles to `dashboard.css`**

At the end of `vibe_iterator/server/static/css/dashboard.css`, append:

```css
/* ---- Discover button ---- */
.btn-discover {
  display: block;
  width: 100%;
  margin-bottom: 0.75rem;
  text-align: center;
  letter-spacing: 0.08em;
  font-size: 11px;
}
```

- [ ] **Step 4: Commit**

```
git add vibe_iterator/server/static/index.html vibe_iterator/server/static/js/app.js vibe_iterator/server/static/css/dashboard.css
git commit -m "feat: add Discover Endpoints button to dashboard home page"
```

---

## Task 5: Dashboard results — "Discovered Surface" panel

**Files:**
- Modify: `vibe_iterator/server/static/results.html`
- Modify: `vibe_iterator/server/static/js/app.js`
- Modify: `vibe_iterator/server/static/css/dashboard.css`

No automated test — verify visually.

- [ ] **Step 1: Add the Discovered Surface panel to `results.html`**

In `vibe_iterator/server/static/results.html`, find the `<!-- Sticky filter bar -->` comment (around line 66). Insert the Discovered Surface panel **before** the filter bar:

```html
<!-- Discovered Surface panel (shown for discover stage only) -->
<div id="discovery-panel" class="discovery-panel" style="display:none">
  <div class="discovery-panel__head">
    <span class="discovery-panel__icon">&#x1F50E;</span>
    <h2>DISCOVERED SURFACE</h2>
    <button class="btn btn-ghost discovery-copy-btn" id="copy-discovery-btn" type="button">COPY ALL</button>
  </div>
  <div class="discovery-panel__cols">
    <div class="discovery-col">
      <div class="discovery-col__label">PAGES <span class="discovery-col__count" id="discovery-pages-count"></span></div>
      <ul class="discovery-list" id="discovery-pages-list"></ul>
    </div>
    <div class="discovery-col">
      <div class="discovery-col__label">API ENDPOINTS <span class="discovery-col__count" id="discovery-endpoints-count"></span></div>
      <ul class="discovery-list" id="discovery-endpoints-list"></ul>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add `renderDiscoverySurface()` to `app.js`**

In `vibe_iterator/server/static/js/app.js`, find `initResultsPage()` (around line 708). After the line `checkDeepDiveHash();`, add:

```javascript
  renderDiscoverySurface(_results);
```

Then add the `renderDiscoverySurface` function **at the end of the RESULTS PAGE section** (before the `// Auto-dispatch init function` block at the bottom of the file):

```javascript
function renderDiscoverySurface(r) {
  const panel = document.getElementById('discovery-panel');
  if (!panel) return;
  const ds = r && r.discovered_surface;
  if (!ds) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = '';

  const pages = ds.pages || [];
  const endpoints = ds.api_endpoints || [];

  document.getElementById('discovery-pages-count').textContent = `(${pages.length})`;
  document.getElementById('discovery-endpoints-count').textContent = `(${endpoints.length})`;

  const pagesList = document.getElementById('discovery-pages-list');
  pagesList.innerHTML = pages.map(p => `<li>${escHtml(p)}</li>`).join('');

  const endpointsList = document.getElementById('discovery-endpoints-list');
  endpointsList.innerHTML = endpoints.map(e => `<li>${escHtml(e)}</li>`).join('');

  document.getElementById('copy-discovery-btn').addEventListener('click', () => {
    const text = [
      '=== DISCOVERED PAGES ===',
      ...pages,
      '',
      '=== API ENDPOINTS ===',
      ...endpoints,
    ].join('\n');
    copyToClipboard(text, null);
    showToast(`Copied ${pages.length} pages + ${endpoints.length} endpoints`);
  });
}
```

- [ ] **Step 3: Add discovery panel styles to `dashboard.css`**

At the end of `vibe_iterator/server/static/css/dashboard.css`, append:

```css
/* ---- Discovered Surface Panel ---- */
.discovery-panel {
  background: var(--bg-card-2);
  border: 1px solid var(--border-bright);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  margin: 0 auto 1.5rem;
  max-width: 1100px;
}

.discovery-panel__head {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 1rem;
}

.discovery-panel__icon {
  font-size: 1.1rem;
}

.discovery-panel__head h2 {
  font-size: 12px;
  letter-spacing: 0.12em;
  color: var(--cyan);
  margin: 0;
  flex: 1;
}

.discovery-copy-btn {
  font-size: 10px;
  padding: 0.3rem 0.75rem;
}

.discovery-panel__cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
}

@media (max-width: 600px) {
  .discovery-panel__cols { grid-template-columns: 1fr; }
}

.discovery-col__label {
  font-size: 10px;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 0.5rem;
}

.discovery-col__count {
  color: var(--cyan);
}

.discovery-list {
  list-style: none;
  padding: 0;
  margin: 0;
  max-height: 240px;
  overflow-y: auto;
}

.discovery-list li {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-dim);
  padding: 0.15rem 0;
  border-bottom: 1px solid var(--border);
}

.discovery-list li:last-child {
  border-bottom: none;
}
```

- [ ] **Step 4: Commit**

```
git add vibe_iterator/server/static/results.html vibe_iterator/server/static/js/app.js vibe_iterator/server/static/css/dashboard.css
git commit -m "feat: add Discovered Surface panel to results page"
```

---

## Task 6: Config example + docs updates

**Files:**
- Modify: `vibe-iterator.config.yaml.example`
- Modify: `docs/CONFIG.md`
- Modify: `docs/SCANNERS.md`

- [ ] **Step 1: Update `vibe-iterator.config.yaml.example`**

In `vibe-iterator.config.yaml.example`, after the `# scanner_timeout_seconds: 60` line, add:

```yaml
# Endpoint discovery (spider) settings — used when running --stage discover.
# spider:
#   max_pages: 30    # stop crawl after this many unique pages (default: 30)
#   max_depth: 3     # do not follow links deeper than this level (default: 3)
```

Also add `discover` to the stages section, after the `firebase` stage:

```yaml
  discover:
    # Special stage — runs the endpoint spider, not scanners.
    # Results are saved to vibe-iterator.discovered.yaml beside your config.
    # Run once to map your app's attack surface; all other stages auto-merge results.
```

Wait — the `discover` stage has no `scanners:` key. The current config validation code requires a `scanners:` key for stages defined in YAML:

```python
if isinstance(stage_cfg, dict) and "scanners" in stage_cfg:
```

Since the condition is `if ... "scanners" in stage_cfg`, a stage without `scanners:` is silently ignored by the validator. That's fine — we don't need to add `discover` to the YAML example's stages section. Just add the spider comment block.

So the only change to `vibe-iterator.config.yaml.example` is appending the spider comment:

```yaml
# Endpoint discovery (spider) settings — used when running --stage discover.
# spider:
#   max_pages: 30    # stop crawl after this many unique pages (default: 30)
#   max_depth: 3     # do not follow links deeper than this level (default: 3)
#
# Results are written to vibe-iterator.discovered.yaml beside this file.
# All scan stages automatically merge discovered pages on the next run.
```

- [ ] **Step 2: Update `docs/CONFIG.md`**

Find the scanner_timeout_seconds section in `docs/CONFIG.md` and add after it:

```markdown
### `spider` (optional)

Configures endpoint discovery behavior when running `--stage discover`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_pages` | int | `30` | Stop crawl after this many unique pages |
| `max_depth` | int | `3` | Do not follow links deeper than this hop count |

**Sidecar file:** After a discover run, `vibe-iterator.discovered.yaml` is written beside your config. All subsequent scan stages automatically merge its `pages` list into the crawl targets.

**Example:**
```yaml
spider:
  max_pages: 50
  max_depth: 4
```
```

Find the stages table in `docs/CONFIG.md` and add the `discover` row:

```markdown
| `discover` | Spider stage — maps attack surface (pages + API endpoints), writes `vibe-iterator.discovered.yaml` |
```

- [ ] **Step 3: Update `docs/SCANNERS.md`**

Find the scanner registry table in `docs/SCANNERS.md` and add a note section for the discover stage after the table (or as a note row), describing that `discover` is a special non-scanner stage:

Add below the scanner table:

```markdown
### Special Stages

| Stage | Type | Description |
|-------|------|-------------|
| `discover` | Spider (not scanners) | Runs sitemap fetcher, BFS DOM crawler, JS framework route extractor, and API endpoint harvester. Writes `vibe-iterator.discovered.yaml`. Does not run any scanners. |
```

- [ ] **Step 4: Commit**

```
git add vibe-iterator.config.yaml.example docs/CONFIG.md docs/SCANNERS.md
git commit -m "docs: add spider config, discover stage, and sidecar docs"
```

---

## Task 7: Full suite verification

**Files:** None — verification only

- [ ] **Step 1: Run all new tests**

```
py -m pytest tests/test_engine/test_discover_result_serialization.py tests/test_engine/test_discover_stage_routing.py tests/test_config_sidecar.py -v
```
Expected: all PASS

- [ ] **Step 2: Run full suite to check for regressions**

```
py -m pytest tests/ -q
```
Expected: green. All previously passing tests still pass. New tests add ~11 more.

- [ ] **Step 3: Commit if any fixes needed**

```
git add -p
git commit -m "fix: resolve discover stage integration regressions"
```

- [ ] **Step 4: Final baton-pass commit**

```
git add .
git commit -m "feat: complete endpoint discovery — engine wiring, config sidecar, API, dashboard, docs"
```

---

**Plans 1 and 2 complete — Automatic endpoint discovery / spidering fully implemented.**
