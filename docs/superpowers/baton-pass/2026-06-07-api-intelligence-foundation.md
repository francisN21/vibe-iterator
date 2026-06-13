# Baton Pass: API Intelligence Foundation

## Situation

We are mid-build on the API Intelligence Foundation for Vibe Iterator.

Current branch:

```text
codex/phase9-product-hardening
```

Active objective:

```text
Build the API Intelligence Foundation for Vibe Iterator: add an endpoint inventory model, method-aware discovery, hidden parameter discovery, API inventory reporting in dashboard/results, and feed the inventory into existing scanners so they test the real attack surface more deeply.
```

The user chose:

```text
safe-by-default for public domain links, aggressive for localhost/localserver apps, still toggleable by end user, with warning.
```

## Do Not Touch Without Permission

Untracked local artifacts exist and have intentionally been left alone:

```text
docs/results.md
graphify-out/
vibe-iterator.discovered.yaml
```

## Important Docs

Design spec:

```text
docs/superpowers/specs/2026-06-06-api-intelligence-foundation-design.md
```

Implementation plan:

```text
docs/superpowers/plans/2026-06-06-api-intelligence-foundation.md
```

Memory:

```text
MEMORY.md
```

## Recent Commit Trail

API Intelligence planning:

```text
0aa4a1b docs: design api intelligence foundation
7f95a7f docs: plan api intelligence foundation
```

Task 1:

```text
c0dd4e2 feat: add api intelligence config
b829316 fix: harden api intelligence config parsing
```

Task 2:

```text
1cd0db7 feat: add api inventory model
436fd0d fix: harden api inventory deserialization
```

Task 3:

```text
f30c8af feat: build api inventory from traffic
a080b75 fix: capture backend api inventory traffic
ef6f8e0 fix: preserve api inventory origins
8bf1da5 fix: tighten api inventory risk tags
```

## What Is Done

### Task 1: API Intelligence Config And Mode Resolver

Done and reviewed.

Implemented:

- `ApiIntelligenceConfig`.
- `resolve_mode`.
- Config parsing in `load_config`.
- Invalid config mode becomes `ConfigError`.
- Non-dict `api_intelligence` and `wordlists` normalize safely.
- Bad/null numeric config values raise `ConfigError`.

Known passing verification:

```powershell
python -m ruff check vibe_iterator/api_inventory.py vibe_iterator/config.py tests/test_api_inventory.py tests/test_config.py
python -m pytest tests/test_api_inventory.py tests/test_config.py -q
```

Last recorded result:

```text
35 passed
```

### Task 2: Inventory Dataclasses And Serialization

Done and reviewed.

Implemented:

- `ApiParameter`.
- `ApiEndpoint`.
- `ApiInventory`.
- `parameter_to_dict`.
- `parameter_from_dict`.
- `endpoint_to_dict`.
- `endpoint_from_dict`.
- `inventory_to_dict`.
- `inventory_from_dict`.
- safer bool deserialization.
- safer endpoint defaults.

Known passing verification:

```powershell
python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
python -m pytest tests/test_api_inventory.py -q
```

Last recorded result after Task 2:

```text
11 passed
```

### Task 3: Build Inventory From Captured Network Requests

Implemented and spec-approved, but final code-quality re-review was interrupted by usage limit.

Implemented:

- `build_inventory_from_network`.
- request-to-endpoint conversion.
- API path filtering.
- method-aware endpoint objects.
- origin-aware merge key.
- integer/UUID-like ID normalization.
- query parameter extraction.
- JSON object body extraction for real string `post_data`, missing content type, and `application/*+json`.
- form body extraction.
- content type tracking.
- auth detection.
- status code tracking.
- state-changing risk tag.
- GraphQL/upload/webhook/admin/redirect/file/SSRF tags.
- aggressive mode warning.
- token-aware risk tags to prevent `/api/profile` -> `file` false positive.

Task 3 review history:

- Spec reviewer requested backend/different-origin API traffic support and JSON extraction improvements.
- Fixed in `a080b75`.
- Spec reviewer requested origin-aware duplicate merge keys.
- Fixed in `ef6f8e0`.
- Spec reviewer approved after those fixes.
- Code quality reviewer requested token-aware risk tag matching.
- Fixed in `8bf1da5`.
- Final code-quality re-review errored because of account usage limit.

## Exact Next Step

Resume with Task 3 final code-quality review.

Run:

```powershell
python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
python -m pytest tests/test_api_inventory.py -q
```

Then manually review:

```text
vibe_iterator/api_inventory.py
tests/test_api_inventory.py
```

Specifically check:

- token-aware risk tagging does not use raw substring matching.
- `/api/profile` is not tagged as `file`.
- actual file/download/path/upload parameters still tag correctly.
- origin + method + normalized path are used for duplicate merging.
- backend/Supabase origin API traffic is preserved.
- MagicMock-like request fields are not accidentally treated as real strings/dicts.

If good:

```text
Mark Task 3 complete and move to Task 4.
```

## Remaining Tasks From Plan

Continue from:

```text
docs/superpowers/plans/2026-06-06-api-intelligence-foundation.md
```

Remaining:

1. Task 4: DiscoveryResult sidecar and history serialization.
2. Task 5: Build inventory during discover and normal scans.
3. Task 6: Hidden parameter inference.
4. Task 7: Bounded aggressive route and parameter probing.
5. Task 8: Dashboard toggle, warning, and inventory panel.
6. Task 9: Exported HTML report inventory.
7. Task 10: Mass assignment and IDOR inventory migration.
8. Task 11: API exposure and rate limit inventory migration.
9. Task 12: URL and GraphQL scanner inventory migration.
10. Task 13: Documentation and final verification.

## Suggested Resume Prompt

Use this to resume:

```text
Resume API Intelligence Foundation from docs/superpowers/baton-pass/2026-06-07-api-intelligence-foundation.md. First finish Task 3 final code-quality review after commit 8bf1da5, then continue Task 4 from docs/superpowers/plans/2026-06-06-api-intelligence-foundation.md. Do not touch untracked docs/results.md, graphify-out/, or vibe-iterator.discovered.yaml.
```

## Completion Warning

The active goal is not complete.

Do not call it complete until the full implementation plan is done and verified:

```powershell
python -m pytest -q
python scripts/check_scanner_exposure.py
```

Also verify API inventory exists in:

- discovery sidecar/history serialization
- normal scan runner listener injection
- dashboard/results UI
- exported HTML report
- migrated scanner evidence
