# Phase 8 Scanner Family Expansion Design

## Goal

Expand Vibe Iterator into broader runtime coverage for full-stack web apps by adding proof-oriented scanners for the missing exploit families identified in the Phase 8 audit:

- SSRF
- Generic path traversal and file read
- Open redirect outside OAuth
- CSRF on state-changing endpoints
- GraphQL introspection, unauthenticated access, and bounded depth abuse
- Webhook signature verification
- WebSocket auth and origin checks
- Unsafe deserialization and server-side template injection
- Generic file upload content-type, extension, and polyglot checks beyond Supabase/Firebase storage

The work must proceed one exploit family at a time with TDD, vulnerable fixture coverage, scanner registry/config/server metadata/frontend exposure, documentation alignment, full-suite verification, and frequent commits.

## Architecture

Each exploit family becomes a dedicated scanner when it has a distinct proof model. This keeps findings clear and keeps each scanner small enough to test well:

| Scanner | Primary proof |
| --- | --- |
| `ssrf_check` | URL-bearing API parameter causes server-side fetch evidence or blocked-private-target weakness |
| `path_traversal_check` | File/path parameter returns sensitive local-file signatures or traversal-normalized response |
| `open_redirect_check` | Redirect parameter returns 3xx `Location` to attacker-controlled absolute URL |
| `csrf_check` | State-changing endpoint accepts cross-site request without CSRF token/origin protection |
| `graphql_check` | GraphQL endpoint allows unauth introspection, unauth data query, or bounded excessive depth |
| `webhook_check` | Webhook-shaped endpoint accepts unsigned or invalidly signed event |
| `websocket_check` | WebSocket endpoint accepts missing auth or untrusted origin |
| `unsafe_payload_check` | SSTI/deserialization marker produces execution signal or dangerous parser error |
| `file_upload_check` | Generic upload endpoint accepts dangerous MIME/extension/polyglot probe without rejection |

The scanners should use existing `BaseScanner`, `Finding`, `Severity`, `request_targets.rewrite_to_backend_url`, and `frontend_origin` patterns. Active probes must stay bounded, use harmless payloads, avoid external callbacks, and prefer local fixture-proof evidence over broad heuristics.

## Stage Defaults

Add all new scanners to `pre-deploy` and `all`. Add only low-risk passive or bounded checks to `post-deploy` after implementation proves they do not mutate durable state. For the initial Phase 8 rollout, keep mutation-prone scanners out of `post-deploy` by default:

- `pre-deploy`: all Phase 8 scanners
- `all`: all Phase 8 scanners
- `post-deploy`: none initially, except later opt-in after separate review
- `dev`: none initially

Users can still run custom YAML stages after the scanner names are valid.

## Fixture Strategy

Extend `tests/fixtures/vulnerable_app/app.py` with local-only endpoints that prove each family:

- `/api/redirect?next=...`
- `/api/fetch?url=...`
- `/api/file?path=...`
- `/api/csrf-transfer`
- `/graphql`
- `/api/webhooks/stripe`
- `/ws`
- `/api/render`
- `/api/upload`

Each endpoint must have at least one vulnerable behavior and one negative-control behavior where useful. Tests should assert proof-quality fields and not only finding titles.

## Registry and UI Contract

For every scanner:

1. Add scanner file in `vibe_iterator/scanners/`.
2. Add to `_SCANNER_MODULE_MAP` in `vibe_iterator/engine/runner.py`.
3. Add to `_DEFAULT_STAGES` and `_VALID_SCANNER_NAMES` through config defaults.
4. Add `_SCANNER_META` in `vibe_iterator/server/routes.py`.
5. Add docs in `docs/SCANNERS.md`, `docs/CONFIG.md`, `README.md`, and `docs/ADDING_SCANNERS.md` where needed.
6. Keep frontend exposure dynamic through `/api/config`; no hardcoded checkbox list should be needed.

## Testing Requirements

Each scanner must have:

- Unit tests for target discovery and false-positive filters.
- Proof tests against `VulnerableApp`.
- Negative tests for safe endpoints and static assets.
- Backend URL routing tests when applicable.
- Registry/config/server metadata tests.

Verification gates after each family:

- Targeted scanner tests pass.
- Config/server metadata tests pass.
- Scanner exposure matrix has no missing registry/config/UI metadata.
- Full suite passes before committing a completed family.

## Coverage Target

Aim for 90%+ line coverage per new scanner where practical. If a scanner remains below 90%, the gap must be mostly unreachable defensive exception handling or documented as a follow-up. The target must not be achieved by weakening proof quality, deleting defensive code, or adding tests that only exercise mocks without proving runtime behavior.

## Implementation Order

1. `open_redirect_check`
2. `path_traversal_check`
3. `ssrf_check`
4. `csrf_check`
5. `graphql_check`
6. `webhook_check`
7. `websocket_check`
8. `unsafe_payload_check`
9. `file_upload_check`

This order starts with lower-risk request/response proof models, then moves into state-changing and protocol-specific scanners.
