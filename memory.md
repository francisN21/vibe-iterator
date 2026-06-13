# Vibe Iterator Memory

## Current Branch

- Branch: `codex/phase9-product-hardening`
- Active product direction: API Intelligence Foundation.
- Goal: add endpoint inventory model, method-aware discovery, hidden parameter discovery, API inventory reporting, and feed the inventory into scanners.
- Do not commit unrelated local artifacts unless explicitly requested:
  - `docs/results.md`
  - `graphify-out/`
  - `vibe-iterator.discovered.yaml`

## API Intelligence Policy

- Default API intelligence mode is `auto`.
- `auto` resolves public domain targets to `safe`.
- `auto` resolves local targets to `aggressive`.
- Local targets include `localhost`, `127.0.0.1`, `::1`, private IP ranges, and `.local`.
- End user must be able to toggle `Auto`, `Safe`, `Aggressive`, or `Off`.
- Aggressive mode must show a warning that extra HTTP requests may trigger logs, rate limits, analytics events, emails, audit alerts, WAF rules, or other side effects.

## Committed Planning Docs

- `0aa4a1b docs: design api intelligence foundation`
  - Spec: `docs/superpowers/specs/2026-06-06-api-intelligence-foundation-design.md`
- `7f95a7f docs: plan api intelligence foundation`
  - Plan: `docs/superpowers/plans/2026-06-06-api-intelligence-foundation.md`

## Completed Implementation Checkpoints

- `c0dd4e2 feat: add api intelligence config`
- `b829316 fix: harden api intelligence config parsing`
- `1cd0db7 feat: add api inventory model`
- `436fd0d fix: harden api inventory deserialization`
- `f30c8af feat: build api inventory from traffic`
- `a080b75 fix: capture backend api inventory traffic`
- `ef6f8e0 fix: preserve api inventory origins`
- `8bf1da5 fix: tighten api inventory risk tags`

## Task Status

### Task 1: API Intelligence Config And Mode Resolver

Status: complete.

Review state:

- Spec compliance approved.
- Code quality approved after config parsing hardening.

Verification recorded by agents:

- `python -m ruff check vibe_iterator/api_inventory.py vibe_iterator/config.py tests/test_api_inventory.py tests/test_config.py`: passed.
- `python -m pytest tests/test_api_inventory.py tests/test_config.py -q`: 35 passed.

### Task 2: Inventory Dataclasses And Serialization

Status: complete.

Review state:

- Spec compliance approved.
- Code quality approved after deserialization hardening.

Verification recorded by agents:

- `python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py`: passed.
- `python -m pytest tests/test_api_inventory.py -q`: 11 passed after Task 2 hardening.

### Task 3: Build Inventory From Captured Network Requests

Status: implemented, spec-approved, code-quality review still needs final approval.

Implemented features:

- `build_inventory_from_network(...)`.
- API path filtering.
- method-aware endpoints.
- integer/UUID-like ID normalization.
- query parameter extraction.
- JSON body key extraction, including missing content type and `application/*+json`.
- form body key extraction.
- request and response content type tracking.
- auth detection from `authorization`, `cookie`, and `x-api-key`.
- status code tracking.
- state-changing method tags.
- risk tags for GraphQL, upload, webhook, admin, redirect, file, and SSRF.
- duplicate merging while preserving distinct origins.
- aggressive mode warning.
- token-aware risk tag matching so `/api/profile` is not tagged as `file`.

Review state:

- Initial spec review requested backend-origin traffic and relaxed JSON extraction; fixed in `a080b75`.
- Second spec review requested origin-aware merge keys; fixed in `ef6f8e0`.
- Final spec review approved: `python -m pytest tests/test_api_inventory.py -q` produced 21 passed at that time.
- Code quality review requested token-aware risk matching; fixed in `8bf1da5`.
- The final code-quality re-review could not complete because the thread hit the usage limit.

Next safest action:

1. Run:

   ```powershell
   python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
   python -m pytest tests/test_api_inventory.py -q
   ```

2. Review `vibe_iterator/api_inventory.py` around risk-tag tokenization and builder merge behavior.
3. If approved, mark Task 3 complete in the working plan and proceed to Task 4.

## Remaining Plan

Continue from `docs/superpowers/plans/2026-06-06-api-intelligence-foundation.md`:

1. Task 4: DiscoveryResult sidecar and history serialization.
2. Task 5: Build inventory during discover and normal scans, inject `listeners["api_inventory"]`.
3. Task 6: Hidden parameter inference.
4. Task 7: Bounded aggressive route and parameter probing.
5. Task 8: Dashboard toggle, warning, and inventory report panel.
6. Task 9: Exported HTML report inventory.
7. Task 10: Mass assignment and IDOR inventory migration.
8. Task 11: API exposure and rate limit inventory migration.
9. Task 12: URL and GraphQL scanner inventory migration.
10. Task 13: Documentation and final verification.

## Current Known Local State

- Tracked work should be clean after the baton-pass commit.
- Untracked artifacts intentionally left alone:
  - `docs/results.md`
  - `graphify-out/`
  - `vibe-iterator.discovered.yaml`

## Final Completion Criteria

Do not mark the API Intelligence Foundation goal complete until current evidence proves:

- endpoint inventory model exists and is serialized.
- method-aware discovery differentiates method, origin, and normalized path.
- hidden parameter discovery works and records source/confidence.
- dashboard/results render API inventory and aggressive warning.
- exported report includes API inventory.
- runner injects `listeners["api_inventory"]`.
- scanners consume inventory with network fallback.
- safe/aggressive/off/auto mode policy is implemented.
- public targets resolve safe; local targets resolve aggressive.
- user can toggle mode.
- full `python -m pytest -q` passes.
- `python scripts/check_scanner_exposure.py` passes.
