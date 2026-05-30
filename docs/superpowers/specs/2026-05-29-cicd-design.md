# CI/CD Integration — Design Spec

## Goal

Two independent but complementary deliverables:

1. **Maintainer CI/CD** — upgrade vibe-iterator's own GitHub Actions pipeline with linting, coverage enforcement, and automated PyPI publishing on version tags.
2. **User-facing scan template** — a ready-to-use GitHub Actions workflow that users copy into their own repos to run vibe-iterator security scans on demand (manually triggered or called from other workflows).

## Context

The existing `.github/workflows/ci.yml` runs `pytest` across Python 3.11 + 3.12 on every push/PR but has no linting, no coverage threshold, and no publish step.

The user-facing template fills a gap: vibe-iterator is a tool you reach for intentionally — after adding a major feature (auth, Firebase, payments), before merging a security-sensitive branch, or any time you want to validate a specific attack surface. It should work like Postman: you open it when you want it, not on every commit.

---

## Architecture

### Files created / modified

| File | Change |
|------|--------|
| `.github/workflows/ci.yml` | Add `lint` job (ruff); add coverage threshold to `test` job |
| `.github/workflows/release.yml` | New — publish to PyPI on `v*.*.*` tag via OIDC trusted publishing |
| `examples/github-actions/vibe-iterator-scan.yml` | New — user-facing on-demand scan template |
| `README.md` | Add "GitHub Actions Integration" section |

---

## Component Design

### 1. `.github/workflows/ci.yml` — Maintainer CI

**Two jobs:**

**`lint` job:**
- Runs on every push and PR (same triggers as existing)
- Installs `ruff` and runs `ruff check vibe_iterator/ tests/`
- Fast — fails the pipeline immediately on style/error issues before tests run
- No mypy: the heavy `MagicMock` usage in tests produces noisy false positives that would require extensive type stubs without meaningful safety gain

**`test` job (existing, extended):**
- Adds `--cov=vibe_iterator --cov-fail-under=70` to the pytest command
- 70% threshold: high enough to catch regressions, low enough that Selenium-dependent code paths (not runnable without a real browser) don't block CI
- Coverage report printed to the log — no external service (Codecov etc.) needed

### 2. `.github/workflows/release.yml` — PyPI Publish

**Trigger:** `push: tags: ["v*.*.*"]`

**Steps:**
1. `actions/checkout@v4`
2. `actions/setup-python@v5` (Python 3.11)
3. `pip install build`
4. `python -m build` → produces `dist/*.whl` + `dist/*.tar.gz`
5. `pypa/gh-action-pypi-publish` with OIDC trusted publishing

**OIDC trusted publishing:** No `PYPI_API_TOKEN` secret stored in the repo. The trust relationship is configured once in PyPI's project settings (Trusted Publisher → GitHub Actions). The workflow exchanges a short-lived OIDC token at publish time.

**Release process:** Push a version tag → CI publishes automatically:
```bash
git tag v0.2.0
git push origin v0.2.0
```

### 3. `examples/github-actions/vibe-iterator-scan.yml` — User Template

**Triggers:**

```yaml
on:
  workflow_dispatch:
    inputs:
      stage:
        required: true
        type: choice
        options: [pre-deploy, auth, firebase, discover, full]
        description: "Which scan stage to run"
      target_url:
        required: false
        description: "Override target URL from config (optional)"
  workflow_call:
    inputs:
      stage:
        required: true
        type: string
      target_url:
        required: false
        type: string
```

`workflow_dispatch` — manual trigger from the GitHub Actions UI with a dropdown for stage and an optional URL override.

`workflow_call` — makes the workflow reusable: power users can call it from other workflows with `uses:` at specific points in their own pipelines.

**Single job — `security-scan` on `ubuntu-latest`:**

1. `actions/checkout@v4` — checks out the calling repo (which must contain `vibe-iterator.config.yaml`)
2. `actions/setup-python@v5` (Python 3.11)
3. `pip install vibe-iterator` — installs latest release from PyPI
4. Write `.env` from GitHub secrets:
   ```
   VIBE_ITERATOR_TEST_EMAIL=${{ secrets.VIBE_ITERATOR_TEST_EMAIL }}
   VIBE_ITERATOR_TEST_PASSWORD=${{ secrets.VIBE_ITERATOR_TEST_PASSWORD }}
   VIBE_ITERATOR_TEST_EMAIL_2=${{ secrets.VIBE_ITERATOR_TEST_EMAIL_2 }}   # optional
   VIBE_ITERATOR_TEST_PASSWORD_2=${{ secrets.VIBE_ITERATOR_TEST_PASSWORD_2 }} # optional
   ```
5. Run scan:
   ```bash
   vibe-iterator --stage ${{ inputs.stage }} --headless \
     ${{ inputs.target_url != '' && format('--target {0}', inputs.target_url) || '' }}
   ```
6. `actions/upload-artifact@v4` — uploads `vibe-iterator-report-*.html` as a downloadable artifact from the run page

**Chrome:** Pre-installed on `ubuntu-latest`. Selenium 4.6+ `selenium-manager` auto-downloads the matching ChromeDriver — no manual driver setup required.

**Secrets contract** (documented in the template file header):

| Secret | Required | Description |
|--------|----------|-------------|
| `VIBE_ITERATOR_TEST_EMAIL` | Yes | Test account email |
| `VIBE_ITERATOR_TEST_PASSWORD` | Yes | Test account password |
| `VIBE_ITERATOR_TEST_EMAIL_2` | No | Second test account (privilege escalation tests) |
| `VIBE_ITERATOR_TEST_PASSWORD_2` | No | Second test account password |

### 4. `README.md` — GitHub Actions Integration Section

New section added after the existing "Usage" section. Three sub-sections:

**Quick start (5 steps):**
1. Copy `examples/github-actions/vibe-iterator-scan.yml` → `.github/workflows/` in your repo
2. Ensure `vibe-iterator.config.yaml` is committed to your repo
3. Add secrets in repo Settings → Secrets and variables → Actions
4. Go to Actions tab → "vibe-iterator Security Scan" → Run workflow → choose stage
5. Download the HTML report from the run artifacts when complete

**Reusable workflow example:**
```yaml
jobs:
  security-scan:
    uses: your-org/your-repo/.github/workflows/vibe-iterator-scan.yml@main
    with:
      stage: firebase
    secrets: inherit
```

**When to run it:**
> Run this after adding a major feature (auth, Firebase, payments), before merging a security-sensitive branch, or any time you want to validate a specific attack surface — not on every commit.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Scan finds HIGH/CRITICAL vulnerabilities | Exit code non-zero → workflow job fails → GitHub marks the run red. Report artifact still uploaded. |
| Chrome not found | `selenium-manager` downloads it; if download fails, job fails with a clear error. |
| Missing required secrets | `.env` write step produces empty values → `load_config` raises `ConfigError` with a clear message → job fails. |
| `vibe-iterator.config.yaml` not in repo | `load_config` raises `ConfigError` → job fails with message pointing to the missing file. |
| Ruff lint failure | `lint` job fails before `test` job runs (jobs run in parallel by default — consider making `test` depend on `lint` to save runner minutes). |
| Coverage below 70% | `test` job fails with pytest-cov's built-in threshold message. |

---

## Testing

The CI improvements are self-validating (the upgraded `ci.yml` runs on every push). The release workflow is tested by pushing a `v0.0.0-test` pre-release tag to a test branch.

The user-facing template is verified by:
- Copying it into a minimal test repo with a `vibe-iterator.config.yaml` pointing at the vulnerable fixture app
- Triggering `workflow_dispatch` manually
- Confirming the report artifact is produced

No unit tests are written for the workflow YAML itself — GitHub Actions has no local test runner worth maintaining.

---

## What This Enables

- **Maintainer:** Lint and coverage gates prevent quality regressions from being merged; `git tag v0.x.x && git push --tags` is all it takes to publish a release
- **Users:** One file copy + three secrets → on-demand security scanning from the GitHub UI, with a downloadable HTML report — no local setup required
- **Power users:** Call the template workflow from their own pipelines at specific milestones (post-firebase-merge, pre-prod-deploy) without writing any scan orchestration themselves
