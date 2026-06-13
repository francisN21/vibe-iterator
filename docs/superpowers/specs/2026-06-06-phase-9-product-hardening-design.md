# Phase 9 Product Hardening Design

## Goal

Phase 9 turns the expanded Phase 8 scanner set into a safer product surface for real app testing. The first slice adds durable scanner drift gates and a `safe-live` scan profile that can be used for smoke testing live or shared environments without running the most mutation-prone probes.

## Scope

This phase starts with two implementation tracks:

1. **Scanner Exposure CI Gate**
   - Add a generalized test that verifies every scanner in `ScanRunner` is present in config presets, valid scanner names, server metadata, and dashboard-consumable stage metadata.
   - Verify metadata has required labels, categories, estimated runtime, stack requirements, and mutating-risk fields.
   - Replace narrow Phase 8-only drift coverage with a repo-wide invariant.

2. **Safe Live Scan Profile**
   - Add a new `safe-live` stage to `vibe_iterator/config.py`.
   - Expose it through the CLI, FastAPI stage metadata, and dashboard stage cards.
   - Keep mutating or potentially state-changing scanners out of `safe-live` by default.
   - Mark scanner metadata with a `mutates_state` boolean and a short `risk_level` so the dashboard/API can explain why some scanners belong only in pre-deploy/all.

## Safe-Live Scanner Policy

`safe-live` should favor bounded read-only checks that give a useful smoke signal without writes, uploads, brute/pressure behavior, or high-risk active payloads:

- `data_leakage`
- `cors_check`
- `api_key_exposure`
- `info_disclosure`
- `open_redirect_check`
- `websocket_check`

The first version excludes scanners that intentionally write, upload, tamper client state, send unsafe mutations, brute/pressure endpoints, or submit higher-risk active payloads:

- `auth_check`
- `client_tampering`
- `rls_bypass`
- `tier_escalation`
- `bucket_limits`
- `sql_injection`
- `xss_check`
- `api_exposure`
- `mass_assignment`
- `idor_check`
- `http_method_tampering`
- `rate_limit_check`
- `path_traversal_check`
- `ssrf_check`
- `csrf_check`
- `graphql_check`
- `webhook_check`
- `unsafe_payload_check`
- `file_upload_check`
- Firebase write/storage/function scanners unless a later Firebase-specific safe profile is designed.

## User Experience

The dashboard should show `SAFE LIVE` beside the existing stage cards. It should be labeled as a smoke-safe profile, not a full audit. Scanner cards returned by `/api/config` should include `mutates_state` and `risk_level`, allowing the UI to show a concise warning for riskier scanners in advanced mode.

The CLI should accept:

```powershell
vibe-iterator scan --stage safe-live
```

## Non-Goals

- Do not redesign the whole dashboard in this slice.
- Do not change scanner internals or proof criteria.
- Do not move mutation-prone scanners into `post-deploy`.
- Do not make `safe-live` a guarantee of zero side effects; document it as reduced-risk smoke scanning.

## Verification

- Add focused tests for the generalized scanner exposure matrix.
- Add config, CLI, server route, and frontend static contract tests for `safe-live`.
- Run:
  - `python -m pytest tests/test_scanner_exposure_matrix.py tests/test_config.py tests/test_cli.py tests/test_server/test_routes.py tests/test_server/test_frontend_static_contracts.py -q`
  - `python -m pytest -q`
  - scanner exposure matrix script
