# Contributing to vibe-iterator

Thank you for contributing! This guide covers two ways to contribute: adding a new scanner and fixing a bug in an existing one.

---

## Contributing a New Scanner

### 1. Fork and branch

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/vibe-iterator.git
cd vibe-iterator
pip install -e ".[dev]"
git checkout -b scanner/<name>
```

### 2. Scaffold the boilerplate

Run this from the project root:

```bash
vibe-iterator new-scanner <name> [--category <category>]
```

**Valid categories:** `injection`, `access_control`, `authentication`, `client_tampering`, `data_leakage`, `misconfiguration`, `api_security`

**Example:**
```bash
vibe-iterator new-scanner stripe_check --category api_security
```

This generates two files and updates the registry:
- `vibe_iterator/scanners/stripe_check.py` — full `BaseScanner` stub with all required fields
- `tests/test_scanners/test_stripe_check.py` — test stub with the fixture app wired in
- `docs/SCANNERS.md` — new registry row added automatically

### 3. Fill in the TODOs

Open `vibe_iterator/scanners/<name>.py` and complete:

1. **`run()` method** — your scan logic. Use `listeners["network"].get_requests()` for captured traffic, `session` to drive the browser.
2. **`_build_finding()` evidence dict** — fill in the actual request/response, payload, or leaked value. Real evidence only — no placeholders.
3. **`description`** — 2–4 sentences explaining the vulnerability and what an attacker can do.
4. **`remediation`** — follow the [Remediation Guidance Template](docs/SCANNERS.md#remediation-guidance-template).
5. **`_build_llm_prompt()`** — fill in the WHAT WAS FOUND and EVIDENCE sections with actual scan data.
6. **`stages`** — verify the pre-suggested stages match where your scanner should run.
7. **`requires_stack`** — change to `["supabase"]` or `["firebase"]` if your scanner only targets those stacks.

### 4. Write real tests

Replace the placeholder tests in `tests/test_scanners/test_<name>.py`:

- **Positive test**: send a request that should trigger a finding, assert the finding appears with expected severity and a keyword in the title
- **Negative test**: send a clean request, assert no findings for your scanner category

Run your tests against the vulnerable fixture app — it starts automatically via the `vuln_app` pytest fixture:

```bash
pytest tests/test_scanners/test_<name>.py -v
```

If the fixture app (`tests/fixtures/vulnerable_app/app.py`) doesn't have an endpoint that exercises your scanner, add one and explain why in your PR.

### 5. Verify everything passes

```bash
pytest tests/ -q                        # All tests green (338+ passing expected)
ruff check vibe_iterator/ tests/        # Zero lint errors
```

### 6. Open a PR

Use this checklist in your PR description:

- [ ] `vibe-iterator new-scanner` was used to generate the boilerplate
- [ ] `run()` returns `[]` for clean endpoints (no false positives)
- [ ] At least one positive test confirms the vulnerability is detected
- [ ] At least one negative test confirms clean endpoints return no findings
- [ ] `pytest tests/ -q` passes (all tests green)
- [ ] `ruff check vibe_iterator/ tests/` passes (zero lint errors)
- [ ] `docs/SCANNERS.md` registry row is present (added automatically by scaffold)

---

## Contributing a Bug Fix

```bash
git clone https://github.com/<your-username>/vibe-iterator.git
cd vibe-iterator
pip install -e ".[dev]"
git checkout -b fix/<scanner>-<description>

# Fix the issue
pytest tests/ -q                        # All tests green
ruff check vibe_iterator/ tests/        # Zero lint errors

# Open a PR describing:
#   - What was broken
#   - How you reproduced it
#   - What your fix changes
```

---

## Design Principles

Keep these in mind when writing or reviewing scanners:

- **One scanner = one attack surface.** Don't bundle unrelated checks into a single scanner.
- **Real evidence only.** Every `Finding.evidence` must contain the specific URL, payload, request/response, or leaked value. Generic descriptions don't help developers fix the issue.
- **Handle errors gracefully.** If a check throws an exception, catch it, call `self.emit()` with a warning message, and return `[]` for that check. Never crash the scan.
- **Restore browser state.** If your scanner modifies localStorage, cookies, or navigation, restore the original state in a `try/finally` block before returning.

---

## Scanner Reference

See [`docs/SCANNERS.md`](docs/SCANNERS.md) for:
- `BaseScanner` interface contract and all required fields
- `Finding` dataclass field definitions
- Evidence structure by category (injection, access_control, authentication, etc.)
- LLM prompt template
- Remediation guidance template
- Full scanner registry
