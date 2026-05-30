# Scanner Marketplace — Design Spec

## Goal

Lower the barrier to community contribution so anyone can write a new scanner and submit a PR without needing to read SCANNERS.md in full. The deliverable is a contributor kit: a `vibe-iterator new-scanner` scaffold command, auto-updated registry, and a `CONTRIBUTING.md` that covers the full PR flow.

## Context

vibe-iterator's "marketplace" is PR-based open-source contribution, not a plugin registry or PyPI ecosystem. Contributors fork the repo, write a scanner, and submit a PR. The maintainer (Francisco) reviews and merges.

Today's friction points:
- No scaffold: contributors have to reverse-engineer the BaseScanner interface and evidence dict format from `SCANNERS.md` + existing scanner code
- No CONTRIBUTING.md: the end-to-end flow (fork → scaffold → test → PR checklist) isn't documented in one place
- No testing guide: the vulnerable fixture app exists, but there's no guidance on how to point a new scanner at it

---

## Architecture

### Files created / modified

| File | Change |
|------|--------|
| `vibe_iterator/cli.py` | Add `new-scanner` Click subcommand |
| `vibe_iterator/scaffold.py` | New — scanner template + test template as module-level string constants; registry row builder |
| `CONTRIBUTING.md` | New — contributor guide at project root |
| `docs/SCANNERS.md` | Auto-updated by scaffold command (registry table row appended) |

---

## Component Design

### 1. `vibe-iterator new-scanner` CLI Command

**Interface:**

```bash
vibe-iterator new-scanner <name> [--category <category>]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<name>` | Yes | Snake_case scanner name (e.g., `stripe_check`). Must be a valid Python identifier. |
| `--category` | No | One of: `injection`, `access_control`, `authentication`, `client_tampering`, `data_leakage`, `misconfiguration`, `api_security`. Pre-fills evidence dict template and suggests stages. |

**Execution steps:**

1. Validate `<name>` — must be a valid Python identifier (regex `^[a-z][a-z0-9_]*$`). Error with example if invalid.
2. Check for collision — if `vibe_iterator/scanners/<name>.py` or `tests/test_scanners/test_<name>.py` already exists, abort with clear message.
3. Validate `--category` — if provided, must be one of the 7 valid categories. Error listing valid options if unrecognized.
4. Render scanner template → write `vibe_iterator/scanners/<name>.py`.
5. Render test template → write `tests/test_scanners/test_<name>.py`.
6. Append registry row to `docs/SCANNERS.md` — find the scanner registry table by searching for the `| Scanner |` header line, append new row at the end. If the table is not found, warn and skip; do not fail.
7. Print next-steps message.

**Next-steps message printed after success:**

```
Created vibe_iterator/scanners/<name>.py
Created tests/test_scanners/test_<name>.py
Updated docs/SCANNERS.md registry

Next:
  1. Fill in the TODOs in vibe_iterator/scanners/<name>.py
  2. Run: pytest tests/test_scanners/test_<name>.py -v
  3. Run the full suite: pytest tests/ -q
  4. Open a PR — see CONTRIBUTING.md for the checklist
```

---

### 2. `vibe_iterator/scaffold.py` — Template Module

A single Python module with two template strings (`SCANNER_TEMPLATE`, `TEST_TEMPLATE`) and a `build_registry_row()` function. Templates use Python's `str.format()` (not Jinja2 — no added deps).

**Category-to-stages mapping** (used to pre-suggest stages):

| Category | Suggested stages |
|----------|-----------------|
| `injection` | `pre-deploy`, `post-deploy` |
| `access_control` | `pre-deploy`, `post-deploy` |
| `authentication` | `dev`, `pre-deploy`, `post-deploy` |
| `client_tampering` | `dev`, `pre-deploy` |
| `data_leakage` | `dev`, `pre-deploy`, `post-deploy` |
| `misconfiguration` | `post-deploy` |
| `api_security` | `pre-deploy`, `post-deploy` |
| *(none provided)* | `pre-deploy` (minimal default) |

**`SCANNER_TEMPLATE` structure** (generated `<name>.py`):

```python
"""<name> scanner — TODO: describe what this scanner checks."""

from __future__ import annotations

import uuid
from datetime import datetime

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity


class Scanner(BaseScanner):
    name = "<name>"
    # CATEGORIES: injection | access_control | authentication | client_tampering | data_leakage | misconfiguration | api_security
    category = "<category>"
    # STAGES: dev | pre-deploy | post-deploy  — choose which stages this scanner runs in
    stages = [<stages>]
    # STACK: ["any"] | ["supabase"] | ["firebase"] — restrict to specific stacks if needed
    requires_stack = ["any"]
    # Set True if your scanner needs a second test account for cross-user checks
    requires_second_account = False

    def run(self, session, listeners, config) -> list[Finding]:
        """
        Implement your scan logic here. Guidelines:
        - listeners["network"].get_requests() → list of captured HTTP requests
        - session drives the browser (may be None in headless/no-browser mode)
        - Use self.emit() to stream progress to the dashboard terminal
        - Return [] if all checks pass (no vulnerabilities found)
        - If you modify browser state (localStorage, cookies, navigation),
          restore original state in a try/finally block
        """
        self.emit(None, f"Starting {self.name} scan", "info")
        findings = []

        # TODO: Implement your checks here.
        # Example pattern for network-based scanners:
        #
        # network = listeners["network"]
        # for req in network.get_requests():
        #     if self._should_test(req):
        #         finding = self._run_check(req, config)
        #         if finding:
        #             findings.append(finding)

        return findings

    def _build_finding(
        self,
        title: str,
        severity: Severity,
        page: str,
        # TODO: Add the specific evidence values your scanner produces
    ) -> Finding:
        """Build a Finding with the correct evidence structure for this category."""
        # TODO: Fill in the evidence dict using the structure for your category.
        # See docs/SCANNERS.md "Evidence Structure by Category" for the exact format.
        #
        # Example for injection category:
        # evidence = {
        #     "request": {"method": "GET", "url": page, "headers": {}, "body": None},
        #     "response": {"status": 200, "body_excerpt": "...", "body_truncated": False},
        #     "payload_used": "' OR 1=1--",
        #     "payload_type": "error_based",
        #     "injection_point": "url_param:q",
        # }
        evidence = {}  # TODO: replace with real evidence

        return Finding(
            id=str(uuid.uuid4()),
            fingerprint=self.make_fingerprint(self.name, title, page),
            scanner=self.name,
            severity=severity,
            title=title,
            # TODO: 2-4 sentence plain English explanation — what is the issue and what can an attacker do?
            description="TODO: describe the vulnerability in plain English.",
            evidence=evidence,
            screenshots=[],
            llm_prompt=self._build_llm_prompt(title, severity, page, evidence),
            # TODO: follow the Remediation Guidance Template in docs/SCANNERS.md
            remediation="TODO: describe the fix.",
            category=self.category,
            page=page,
            timestamp=datetime.now().isoformat(),
            mark_status="none",
            mark_note=None,
        )

    def _build_llm_prompt(
        self, title: str, severity: Severity, page: str, evidence: dict
    ) -> str:
        # TODO: fill in WHAT WAS FOUND and EVIDENCE with real scan data
        return f"""You are a security expert helping me fix a vulnerability in my web application.

VULNERABILITY: {title}
SEVERITY: {severity.value}
SCANNER: {self.name}
PAGE: {page}
CATEGORY: {self.category}

WHAT WAS FOUND:
TODO: Describe what the scanner found and what an attacker could do.

EVIDENCE:
TODO: Include the actual request/response, payload, or leaked data.

YOUR TASK:
Fix the vulnerability described above in my codebase.

1. Explain what the root cause is
2. Show me the specific code change needed (with before/after if possible)
3. Confirm what I should test after applying the fix to verify it's resolved"""
```

**`TEST_TEMPLATE` structure** (generated `test_<name>.py`):

```python
"""<name> scanner tests — real HTTP against the vulnerable fixture app, no Selenium."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.<name> import Scanner
from vibe_iterator.scanners.base import Severity


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _run(vuln_app, network_requests=None) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests or [])
    return scanner.run(session=None, listeners={"network": net}, config=config)


# ---------------------------------------------------------------------------
# TODO: Replace these placeholders with real tests
# ---------------------------------------------------------------------------

def test_vulnerability_detected(vuln_app) -> None:
    """TODO: Test that the scanner detects the vulnerability in the fixture app."""
    findings = _run(vuln_app)
    # findings is list[Finding]. Example assertions:
    # assert len(findings) >= 1
    # assert findings[0].severity == Severity.HIGH
    # assert "expected keyword" in findings[0].title.lower()
    assert isinstance(findings, list), "Scanner must return a list"


def test_clean_endpoint_no_finding(vuln_app) -> None:
    """TODO: Test that a clean endpoint produces no findings."""
    # Build a mock request to an endpoint that should NOT trigger a finding
    req = MagicMock()
    req.url = vuln_app.base_url + "/api/data"
    req.method = "GET"
    req.status_code = 200
    req.response_body = '{"items": []}'
    req.post_data = None

    findings = _run(vuln_app, [req])
    # Replace with the specific finding type your scanner produces
    matching = [f for f in findings if "keyword" in f.title.lower()]
    assert matching == [], f"Expected no findings, got {matching}"
```

**Template escaping note:** `SCANNER_TEMPLATE` and `TEST_TEMPLATE` are rendered with `str.format()`, using `{name}`, `{category}`, etc. as substitution markers. The generated code contains Python f-strings and dict literals that use `{` and `}` — these must be doubled in the template string (`{{title}}`, `{{severity.value}}`, `{{}}`) so `str.format()` passes them through as literal braces.

**`build_registry_row(name, category, stages, requires_stack, requires_second_account)` → str:**

Returns a markdown table row:
```
| `<name>` | <Category title-cased> | <stages joined ", "> | `<requires_stack>` | `<requires_second_account>` | community |
```

The `new-scanner` command appends this row immediately after the last `|`-prefixed line in the `## Scanner Registry` table section of `docs/SCANNERS.md`.

---

### 3. `CONTRIBUTING.md`

Full path: project root (`CONTRIBUTING.md`).

**Sections:**

**Contributing a New Scanner** (numbered steps):
1. Fork and create a branch: `git checkout -b scanner/<name>`
2. Run `vibe-iterator new-scanner <name> --category <category>` from the repo root
3. Fill in the TODOs in `vibe_iterator/scanners/<name>.py`:
   - Implement `run()` with your scan logic
   - Complete the `_build_finding()` evidence dict
   - Write the description and remediation
4. Write real tests in `tests/test_scanners/test_<name>.py` (replace the placeholder tests)
5. Verify everything passes: `pytest tests/ -q && ruff check vibe_iterator/ tests/`
6. Open a PR — see the checklist below

**Testing Your Scanner**:
- The `vuln_app` pytest fixture in your test file starts the vulnerable fixture app automatically (no manual server start needed)
- Run `pytest tests/test_scanners/test_<name>.py -v` to iterate on your scanner
- Run `pytest tests/ -q` before submitting to check for regressions (expect 338+ passing)
- If the fixture app doesn't have an endpoint that exercises your scanner, add one in `tests/fixtures/vulnerable_app/app.py` and explain why in your PR

**PR Checklist** (markdown checkboxes):
- [ ] `vibe-iterator new-scanner` was used to generate the boilerplate
- [ ] `run()` returns `[]` for clean endpoints (no false positives)
- [ ] At least one positive test confirms the vulnerability is detected
- [ ] At least one negative test confirms clean endpoints return no findings
- [ ] `pytest tests/ -q` passes (all tests green)
- [ ] `ruff check vibe_iterator/ tests/` passes (no lint errors)
- [ ] SCANNERS.md registry row is present (added automatically by scaffold)

**Contributing a Bug Fix**:
1. Fork and create a branch: `git checkout -b fix/<scanner>-<description>`
2. Fix the issue
3. Ensure tests pass: `pytest tests/ -q`
4. Open a PR describing: what was broken, how you reproduced it, what your fix changes

**Design Principles** (brief):
- One scanner = one attack surface. Don't bundle unrelated checks.
- Every `Finding` must include real evidence (specific URL, payload, or leaked value — not generic descriptions).
- If your scanner errors during a check, catch the exception, emit a warning, and return `[]` for that check. Never crash the scan.
- Scanners that modify browser state must restore it in a `try/finally` block.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `<name>` fails `^[a-z][a-z0-9_]*$` | Error: "Invalid scanner name — must be lowercase snake_case (e.g., stripe_check)" |
| `<name>` collides with existing scanner file | Error: "vibe_iterator/scanners/<name>.py already exists. Choose a different name." |
| `--category` not in valid list | Error: "Unknown category '<x>'. Valid options: injection, access_control, ..." |
| Scanner file written, test file already exists | Error before writing scanner file — atomic check, no partial state |
| SCANNERS.md registry table not found | Warning printed, scaffold continues — user told to update manually |

---

## Testing

The scaffold command itself is tested:

- `test_new_scanner_generates_files()` — runs `vibe-iterator new-scanner test_scaffold_scanner --category injection` in a temp directory (using `tmp_path` pytest fixture), verifies both files are created with the correct class name and category pre-filled
- `test_new_scanner_invalid_name()` — passes `"BadName"` and `"123bad"`, asserts exit code is non-zero
- `test_new_scanner_conflict()` — creates a file at the expected path before running, asserts abort
- `test_new_scanner_registry_row()` — verifies the SCANNERS.md file gets a new row appended with correct values
- `test_new_scanner_no_category()` — runs without `--category`, verifies a generic template is generated

The `CONTRIBUTING.md` is documentation — no automated tests. Validated by following the contributor flow end-to-end in the fixture app during implementation.

---

## What This Enables

- **Contributors:** One command generates all boilerplate, they fill in the logic, tests pass, PR submitted. No need to read SCANNERS.md in full before writing a line of code.
- **Maintainer:** PRs arrive with consistent structure — same evidence format, same test pattern, registry already updated. Review focuses on security logic, not boilerplate.
- **Community growth:** A working scanner submission can be completed in a focused 2–3 hour session rather than a half-day archaeology project.
