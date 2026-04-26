# CONFIG.md — Configuration Schema

## `.env` (secrets only)

Secrets and credentials live here. Never committed to git.

```
# Test account credentials (required)
VIBE_ITERATOR_TEST_EMAIL=test@example.com
VIBE_ITERATOR_TEST_PASSWORD=testpassword123

# Target URL (can also be set via CLI flag)
VIBE_ITERATOR_TARGET=http://localhost:3000

# GUI port (default 3001)
VIBE_ITERATOR_PORT=3001

# Optional: Supabase project details for deeper scanning
VIBE_ITERATOR_SUPABASE_URL=https://xxx.supabase.co
VIBE_ITERATOR_SUPABASE_ANON_KEY=eyJ...

# Optional: Second test account for cross-user testing (IDOR, RLS)
VIBE_ITERATOR_TEST_EMAIL_2=test2@example.com
VIBE_ITERATOR_TEST_PASSWORD_2=testpassword456
```

### Required vs Optional

| Variable | Required | Purpose |
|----------|----------|---------|
| `VIBE_ITERATOR_TEST_EMAIL` | Yes | Primary test account email |
| `VIBE_ITERATOR_TEST_PASSWORD` | Yes | Primary test account password |
| `VIBE_ITERATOR_TARGET` | Yes (or via CLI) | Target app URL |
| `VIBE_ITERATOR_PORT` | No (default: 3001) | Dashboard GUI port |
| `VIBE_ITERATOR_SUPABASE_URL` | No | Enables deeper Supabase-specific scans |
| `VIBE_ITERATOR_SUPABASE_ANON_KEY` | No | Used for direct Supabase API testing |
| `VIBE_ITERATOR_TEST_EMAIL_2` | No | Enables cross-user IDOR/RLS testing |
| `VIBE_ITERATOR_TEST_PASSWORD_2` | No | Second test account password |

---

## `vibe-iterator.config.yaml` (scan scope)

Defines what pages to crawl, which scanners to run per stage, and technology detection.

```yaml
target: ${VIBE_ITERATOR_TARGET}

# Pages to crawl (order matters — login page should come first if auth is needed)
pages:
  - /
  - /login
  - /dashboard
  - /profile
  - /settings
  - /upload

# Stage-specific scanner selection
stages:
  dev:
    scanners: [data_leakage, auth_check, client_tampering]
    description: "Catch basics during development"
  pre-deploy:
    scanners: [data_leakage, auth_check, client_tampering, rls_bypass, tier_escalation, bucket_limits, sql_injection, xss_check, api_exposure]
    description: "Full audit before going live"
  post-deploy:
    scanners: [cors_check, data_leakage, auth_check, api_exposure, bucket_limits, sql_injection]
    description: "External-facing checks on live site"
  all:
    scanners: [data_leakage, rls_bypass, tier_escalation, bucket_limits, auth_check, client_tampering, sql_injection, cors_check, xss_check, api_exposure]
    description: "Run every scanner regardless of stage"

# Technology detection (auto-detect if not specified — see Auto-Detection section below)
stack:
  backend: supabase     # supabase | firebase | custom
  auth: supabase-auth   # supabase-auth | firebase-auth | custom
  storage: supabase     # supabase | s3 | custom
```

---

## Stage Profiles

### DEV — "Catch basics during development"
- **When:** During active development, run frequently
- **Scanners:** `data_leakage`, `auth_check`, `client_tampering`
- **Focus:** Quick feedback loop — catch leaked tokens, weak auth, and client-side trust issues early
- **Speed:** Fast (3 scanners)

### PRE-DEPLOY — "Full audit before going live"
- **When:** Before deploying to production, run once before each release
- **Scanners:** `data_leakage`, `auth_check`, `client_tampering`, `rls_bypass`, `tier_escalation`, `bucket_limits`, `sql_injection`, `xss_check`, `api_exposure`
- **Focus:** Comprehensive — everything that could be exploited in production
- **Speed:** Thorough (9 scanners)

### POST-DEPLOY — "External-facing checks on live site"
- **When:** After deployment, run against the live URL
- **Scanners:** `cors_check`, `data_leakage`, `auth_check`, `api_exposure`, `bucket_limits`, `sql_injection`
- **Focus:** External attack surface — what's visible and exploitable from outside
- **Speed:** Moderate (6 scanners)

### ALL — "Run every scanner regardless of stage"
- **When:** Deep audit, debugging, CI pipeline where you want maximum coverage
- **Scanners:** All 10 scanners in a logical order (data first, auth second, injection last)
- **Focus:** Complete — every check the tool can perform
- **Speed:** Slow (all 10 scanners — expect 10–20 minutes on a typical app)
- **Triggered by:** "ALL SCANNERS" toggle in the dashboard home, or `--stage all` CLI flag

---

## Stack Auto-Detection

When `stack` is omitted from `vibe-iterator.config.yaml`, the engine auto-detects by inspecting network traffic captured during the initial page crawl:

| Signal | Detected As |
|--------|-------------|
| Requests to `*.supabase.co` | `backend: supabase` |
| `X-Powered-By: supabase-postgrest` response header | `backend: supabase` |
| Supabase anon key pattern (`eyJ...`) in Authorization header | `auth: supabase-auth` |
| Requests to `*.firebaseapp.com` or `googleapis.com/identitytoolkit` | `backend: firebase` |
| Firebase Storage requests (`firebasestorage.googleapis.com`) | `storage: firebase` |
| None of the above | `backend: custom`, `auth: custom`, `storage: custom` |

Auto-detection only affects which backend-specific scanners activate (`rls_bypass`, `tier_escalation`, `bucket_limits` require `backend: supabase`). All generic scanners (`xss_check`, `cors_check`, `api_exposure`, `data_leakage`, `auth_check`, `client_tampering`, `sql_injection`) run regardless of detected stack.

When auto-detection fires, the dashboard terminal emits: `[INFO] Detected stack: supabase / supabase-auth / supabase`.

---

## Config Loading Priority

1. CLI flags (highest priority) — `--target`, `--stage`, `--port`
2. `POST /api/scan/start` body — `{ stage, scanner_overrides: ["sql_injection", "auth_check"] }` (GUI advanced mode, session-only)
3. `.env` file — secrets and defaults
4. `vibe-iterator.config.yaml` — scan scope and stage definitions
5. Built-in defaults (lowest priority) — port 3001, dev stage

The `scanner_overrides` field is only available from the GUI's Advanced panel. It restricts the stage's scanner list to only the named scanners for that single run — it does not modify the YAML config.

## Config Validation

On startup, the config loader MUST:
1. Check that required `.env` vars are set (test email, password, target)
2. Validate YAML structure (pages is a list, stages have scanners arrays)
3. Verify all scanner names in stage configs map to actual scanner modules
4. Warn (not error) if optional vars like Supabase URL are missing — some scanners will just be skipped
