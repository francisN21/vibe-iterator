# Phase 9 Product Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add scanner drift gates and a reduced-risk `safe-live` scan profile for real-app smoke scans.

**Architecture:** Keep the existing scanner architecture intact. Add invariant tests around the runner/config/server metadata boundary, then add one new stage profile that flows through config, CLI, API metadata, and the dashboard stage card list.

**Tech Stack:** Python 3.11, pytest, Click CLI, FastAPI route metadata, existing static dashboard JavaScript.

---

### Task 1: Commit Phase 9 Spec And Plan

**Files:**
- Create: `docs/superpowers/specs/2026-06-06-phase-9-product-hardening-design.md`
- Create: `docs/superpowers/plans/2026-06-06-phase-9-product-hardening.md`

- [ ] Review spec for placeholders and contradictions.
- [ ] Run `git diff --check`.
- [ ] Commit with `docs: plan phase 9 product hardening`.

### Task 2: Add General Scanner Exposure Matrix Test

**Files:**
- Create: `tests/test_scanner_exposure_matrix.py`
- Create: `scripts/check_scanner_exposure.py`

- [ ] Add a test that imports `_DEFAULT_STAGES`, `_VALID_SCANNER_NAMES`, `_SCANNER_MODULE_MAP`, and `_SCANNER_META`.
- [ ] Assert every module-map scanner appears in at least one stage preset.
- [ ] Assert preset names are all valid and importable.
- [ ] Assert every scanner has server metadata with `label`, `category`, `est_seconds`, `requires_stack`, `requires_second_account`, `mutates_state`, and `risk_level`.
- [ ] Assert each scanner module's `Scanner` class metadata matches server metadata for `requires_stack`, `requires_second_account`, and category.
- [ ] Add a script that runs the same exposure matrix outside pytest for local/CI smoke checks.
- [ ] Run `python -m pytest tests/test_scanner_exposure_matrix.py -q`.
- [ ] Run `python scripts/check_scanner_exposure.py`.
- [ ] Commit with `test: add scanner exposure matrix gate`.

### Task 3: Add Scanner Risk Metadata

**Files:**
- Modify: `vibe_iterator/server/routes.py`
- Modify: `tests/test_server/test_routes.py`
- Modify: `tests/test_scanner_exposure_matrix.py`

- [ ] Add `mutates_state: bool` and `risk_level: "low" | "medium" | "high"` to each `_SCANNER_META` entry.
- [ ] Update `_scanner_availability()` to include those fields in `/api/config` scanner objects.
- [ ] Add route tests that assert scanner metadata includes these fields.
- [ ] Run `python -m pytest tests/test_scanner_exposure_matrix.py tests/test_server/test_routes.py -q`.
- [ ] Commit with `feat: expose scanner risk metadata`.

### Task 4: Add Safe-Live Stage

**Files:**
- Modify: `vibe_iterator/config.py`
- Modify: `vibe_iterator/cli.py`
- Modify: `vibe_iterator/server/routes.py`
- Modify: `vibe_iterator/server/static/js/app.js`
- Modify: `tests/test_config.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_server/test_routes.py`
- Modify: `tests/test_server/test_frontend_static_contracts.py`
- Modify: `README.md`
- Modify: `docs/CONFIG.md`

- [ ] Add `_SAFE_LIVE_SCANNERS` list in `config.py` using the approved reduced-risk scanner set: `data_leakage`, `api_key_exposure`, `cors_check`, `info_disclosure`, `open_redirect_check`, and `websocket_check`.
- [ ] Add `"safe-live"` to `_DEFAULT_STAGES`.
- [ ] Add `"safe-live"` to the Click `--stage` choices.
- [ ] Add `_STAGE_LABELS["safe-live"]` with label `SAFE LIVE`, tag `Smoke-safe`, and an estimated runtime.
- [ ] Add a `safe-live` stage card to `app.js`.
- [ ] Add tests that `safe-live` exists, includes approved low-risk scanners, and excludes active or mutation-prone scanners such as `auth_check`, `api_exposure`, `rate_limit_check`, `path_traversal_check`, `ssrf_check`, `csrf_check`, `webhook_check`, `unsafe_payload_check`, and `file_upload_check`.
- [ ] Add CLI and frontend static contract tests for the new stage.
- [ ] Update README and config docs with the new profile.
- [ ] Run `python -m pytest tests/test_config.py tests/test_cli.py tests/test_server/test_routes.py tests/test_server/test_frontend_static_contracts.py -q`.
- [ ] Commit with `feat: add safe live scan profile`.

### Task 5: Final Verification

**Files:**
- Modify only docs if verification snapshots need alignment.

- [ ] Run `python -m pytest -q`.
- [ ] Run scanner exposure matrix script:

```powershell
@'
from vibe_iterator.config import _DEFAULT_STAGES, _VALID_SCANNER_NAMES
from vibe_iterator.engine.runner import _SCANNER_MODULE_MAP
from vibe_iterator.server.routes import _SCANNER_META

preset_names = {name for scanners in _DEFAULT_STAGES.values() for name in scanners}
print({
    "registered": len(_SCANNER_MODULE_MAP),
    "preset_names": len(preset_names),
    "missing_from_presets": sorted(set(_SCANNER_MODULE_MAP) - preset_names),
    "invalid_presets": sorted(preset_names - set(_SCANNER_MODULE_MAP)),
    "missing_valid": sorted(set(_SCANNER_MODULE_MAP) - set(_VALID_SCANNER_NAMES)),
    "missing_meta": sorted(set(_SCANNER_MODULE_MAP) - set(_SCANNER_META)),
    "meta_without_module": sorted(set(_SCANNER_META) - set(_SCANNER_MODULE_MAP)),
})
'@ | python -
```

- [ ] Run `graphify update . --force`.
- [ ] Commit final docs if changed.
