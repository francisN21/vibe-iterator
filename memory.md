# Vibe Iterator Memory

## Current Branch

- Branch: `codex/firebase-stage-config-alignment`
- Phase 8 scanner-family expansion is implemented across all named exploit families.
- Do not commit local generated/untracked artifacts unless explicitly requested:
  - `docs/results.md`
  - `graphify-out/`
  - `vibe-iterator.discovered.yaml`

## Phase 8 Scanner Families Added

- `open_redirect_check`: proves external 3xx `Location` header on redirect-like params.
- `path_traversal_check`: proves `.env` or `/etc/passwd`-style disclosure from file/path params.
- `ssrf_check`: proves server-side URL fetches with a local callback listener.
- `csrf_check`: proves cookie-auth unsafe methods accept cross-site Origin/Referer after CSRF headers are stripped.
- `graphql_check`: proves unauth introspection, unauth sensitive data, and bounded depth query acceptance.
- `webhook_check`: proves missing or invalid webhook signatures still process events.
- `websocket_check`: proves unauthenticated or untrusted-Origin WebSocket handshakes return `101`.
- `unsafe_payload_check`: proves harmless SSTI evaluation or unsafe parser/deserialization error signatures.
- `file_upload_check`: proves dangerous extension, MIME, SVG/HTML polyglot, or EICAR test-string uploads are accepted/stored.

All Phase 8 scanners are registered in:

- `vibe_iterator/engine/runner.py`
- `vibe_iterator/config.py`
- `vibe_iterator/server/routes.py`
- `tests/test_phase8_scanner_registration.py`
- `docs/SCANNERS.md`
- `docs/CONFIG.md`
- `README.md`

## Verification Snapshot

- `python -m pytest -q`: 613 passed, 4 skipped
- `python -m pytest --cov=vibe_iterator --cov-report=term-missing`: 613 passed, 4 skipped, 84% total coverage
- Scanner exposure matrix: 30 registered, 30 preset-visible, no missing valid-name/server-meta/module-map entries
- New scanner line coverage:
  - `path_traversal_check`: 91%
  - `ssrf_check`: 95%
  - `csrf_check`: 90%
  - `graphql_check`: 92%
  - `webhook_check`: 94%
  - `websocket_check`: 91%
  - `unsafe_payload_check`: 95%
  - `file_upload_check`: 95%

## Recent Commit Trail

- `5ab936c feat: add unsafe payload scanner`
- `67e3e0e feat: add generic file upload scanner`

Earlier Phase 8 commits on this branch include open redirect, path traversal, SSRF, CSRF, GraphQL, webhook, and WebSocket scanner slices.

## Sensible Next Checks

- Run against the user's live DetermiNext stack with `VIBE_ITERATOR_TARGET=http://localhost:3000` and `VIBE_ITERATOR_BACKEND_URL=http://localhost:4000` after confirming the backend is actually listening.
- Consider a small live-app smoke config that runs only the newest Phase 8 scanners first.
- If preparing to merge, run one final full suite and coverage command after any docs-only cleanup.
