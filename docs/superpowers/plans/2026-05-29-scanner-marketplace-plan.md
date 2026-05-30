# Scanner Marketplace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `vibe-iterator new-scanner` CLI command that generates a complete scanner + test stub from templates, auto-appends a row to the SCANNERS.md registry, and a `CONTRIBUTING.md` that covers the full contributor flow.

**Architecture:** `vibe_iterator/scaffold.py` holds the two `string.Template` template strings and three helper functions (`render_scanner`, `render_test`, `build_registry_row`, `append_registry_row`). `vibe_iterator/cli.py` gets a `new_scanner` Click subcommand that validates input, calls scaffold, writes the two files, and updates SCANNERS.md. `CONTRIBUTING.md` is a standalone markdown file at the project root.

**Tech Stack:** Python `string.Template` (stdlib, no new deps), Click (already in deps), pytest + CliRunner for tests.

---

## File Map

| File | Change |
|------|--------|
| `vibe_iterator/scaffold.py` | Create — template strings + render/build helpers |
| `vibe_iterator/cli.py` | Modify — add `new_scanner` subcommand |
| `CONTRIBUTING.md` | Create — contributor guide at project root |
| `tests/test_scaffold.py` | Create — unit tests for scaffold module |
| `tests/test_cli_scaffold.py` | Create — CLI integration tests with CliRunner + tmp_path |

---

### Task 1: `vibe_iterator/scaffold.py` — template module

**Files:**
- Create: `vibe_iterator/scaffold.py`
- Test: `tests/test_scaffold.py`

- [ ] **Step 1: Write failing tests for scaffold.py**

Create `tests/test_scaffold.py`:

```python
"""Unit tests for vibe_iterator/scaffold.py."""

from vibe_iterator.scaffold import (
    VALID_CATEGORIES,
    append_registry_row,
    build_registry_row,
    render_scanner,
    render_test,
)


def test_render_scanner_with_category():
    code = render_scanner("stripe_check", "injection")
    assert 'name = "stripe_check"' in code
    assert 'category = "injection"' in code
    assert "['pre-deploy', 'post-deploy']" in code
    assert "class Scanner(BaseScanner):" in code
    assert "def run(self, session, listeners, config)" in code
    assert "def _build_finding(" in code
    assert "def _build_llm_prompt(" in code


def test_render_scanner_without_category():
    code = render_scanner("my_scanner", None)
    assert 'name = "my_scanner"' in code
    assert "['pre-deploy']" in code


def test_render_scanner_all_categories():
    for cat in VALID_CATEGORIES:
        code = render_scanner(f"{cat}_scanner", cat)
        assert f'category = "{cat}"' in code
        stages = VALID_CATEGORIES[cat]
        assert repr(stages) in code


def test_render_test():
    code = render_test("stripe_check")
    assert "from vibe_iterator.scanners.stripe_check import Scanner" in code
    assert "@pytest.fixture(scope=" in code
    assert "def _run(vuln_app" in code
    assert "def test_vulnerability_detected(" in code
    assert "def test_clean_endpoint_no_finding(" in code


def test_build_registry_row():
    row = build_registry_row("stripe_check", "injection", ["pre-deploy", "post-deploy"], ["any"], False)
    assert "| `stripe_check`" in row
    assert "Injection" in row
    assert "pre-deploy, post-deploy" in row
    assert "community" in row


def test_append_registry_row(tmp_path):
    md = tmp_path / "SCANNERS.md"
    md.write_text(
        "## Scanner Registry\n\n"
        "| Scanner | Category | Stages | `requires_stack` | `requires_second_account` | Phase |\n"
        "|---------|----------|--------|-----------------|--------------------------|-------|\n"
        "| `existing` | Injection | pre-deploy | `['any']` | `False` | 2 |\n"
        "\n"
        "Some footnote text\n"
    )
    row = "| `stripe_check` | Injection | pre-deploy, post-deploy | `['any']` | `False` | community |"
    result = append_registry_row(str(md), row)
    assert result is True
    content = md.read_text()
    lines = content.splitlines()
    existing_idx = next(i for i, l in enumerate(lines) if "`existing`" in l)
    stripe_idx = next(i for i, l in enumerate(lines) if "`stripe_check`" in l)
    assert stripe_idx == existing_idx + 1  # appended immediately after last table row


def test_append_registry_row_missing_file(tmp_path):
    result = append_registry_row(str(tmp_path / "nonexistent.md"), "| row |")
    assert result is False


def test_append_registry_row_no_table(tmp_path):
    md = tmp_path / "SCANNERS.md"
    md.write_text("# No table here\n")
    result = append_registry_row(str(md), "| row |")
    assert result is False
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scaffold.py -v
```

Expected: `ImportError` — `scaffold` module doesn't exist yet.

- [ ] **Step 3: Create `vibe_iterator/scaffold.py`**

```python
"""Scanner scaffold — generates boilerplate for new community scanners."""

from __future__ import annotations

from string import Template

# ---- Category metadata -------------------------------------------------------

VALID_CATEGORIES: dict[str, list[str]] = {
    "injection": ["pre-deploy", "post-deploy"],
    "access_control": ["pre-deploy", "post-deploy"],
    "authentication": ["dev", "pre-deploy", "post-deploy"],
    "client_tampering": ["dev", "pre-deploy"],
    "data_leakage": ["dev", "pre-deploy", "post-deploy"],
    "misconfiguration": ["post-deploy"],
    "api_security": ["pre-deploy", "post-deploy"],
}

_EVIDENCE_BY_CATEGORY: dict[str, str] = {
    "injection": (
        '{\n'
        '        "request": {"method": "GET", "url": page, "headers": {}, "body": None},\n'
        '        "response": {"status": 200, "body_excerpt": "...", "body_truncated": False},\n'
        '        "payload_used": "\' OR 1=1--",\n'
        '        "payload_type": "error_based",\n'
        '        "injection_point": "url_param:q",\n'
        '    }'
    ),
    "access_control": (
        '{\n'
        '        "action_attempted": "TODO: describe the attempted action",\n'
        '        "auth_context": "authenticated as test user",\n'
        '        "request": {"method": "GET", "url": page, "headers": {}, "body": None},\n'
        '        "response": {"status": 200, "body_excerpt": "..."},\n'
        '        "expected_response": "403 Forbidden or empty array",\n'
        '        "actual_response": "200 OK with restricted data",\n'
        '        "second_account_used": False,\n'
        '    }'
    ),
    "authentication": (
        '{\n'
        '        "check_group": "TODO: which check group (e.g., Token Security)",\n'
        '        "check_name": "TODO: which specific check",\n'
        '        "evidence_type": "storage_inspection",\n'
        '        "observed_value": "TODO: what was observed",\n'
        '        "expected_behavior": "TODO: what should have happened",\n'
        '    }'
    ),
    "client_tampering": (
        '{\n'
        '        "storage_key": "TODO: which key was tampered",\n'
        '        "original_value": "TODO: original value",\n'
        '        "tampered_value": "TODO: tampered value",\n'
        '        "storage_type": "localStorage",\n'
        '        "action_performed": "TODO: action taken after tampering",\n'
        '        "request": {"method": "POST", "url": page, "headers": {}, "body": "{}"},\n'
        '        "response": {"status": 200, "body_excerpt": "..."},\n'
        '        "expected_response": "403 Forbidden",\n'
        '    }'
    ),
    "data_leakage": (
        '{\n'
        '        "leak_type": "TODO: api_key | jwt | pii_email | supabase_service_key",\n'
        '        "leak_location": "network_response",\n'
        '        "url": page,\n'
        '        "leaked_value_excerpt": "TODO: first ~50 chars of the leaked value",\n'
        '        "context": "TODO: where in the response was it found",\n'
        '    }'
    ),
    "misconfiguration": (
        '{\n'
        '        "test_origin_sent": "https://evil.com",\n'
        '        "request": {"method": "GET", "url": page, "headers": {"Origin": "https://evil.com"}},\n'
        '        "response_headers": {"TODO": "include relevant response headers"},\n'
        '        "issue": "TODO: reflected_origin | null_origin_accepted | credentials_with_wildcard",\n'
        '    }'
    ),
    "api_security": (
        '{\n'
        '        "endpoint": "TODO: HTTP method + path",\n'
        '        "test_performed": "replay_without_auth",\n'
        '        "request": {"method": "GET", "url": page, "headers": {}, "body": None},\n'
        '        "response": {"status": 200, "body_excerpt": "..."},\n'
        '        "expected_response": "401 Unauthorized",\n'
        '    }'
    ),
}

_EVIDENCE_DEFAULT = '{}  # TODO: add evidence — see docs/SCANNERS.md "Evidence Structure by Category"'

# ---- Templates ---------------------------------------------------------------
# Use single-quoted triple strings (''') so triple-quoted docstrings (""") can
# appear unescaped inside the generated code. string.Template uses ${var} for
# substitution; Python brace expressions like {self.name} pass through literally.

_SCANNER_TEMPLATE = Template('''"""${name} scanner — TODO: describe what this scanner checks."""

from __future__ import annotations

import uuid
from datetime import datetime

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity


class Scanner(BaseScanner):
    name = "${name}"
    # CATEGORIES: injection | access_control | authentication | client_tampering | data_leakage | misconfiguration | api_security
    category = "${category}"
    # STAGES: dev | pre-deploy | post-deploy
    stages = ${stages}
    # STACK: ["any"] | ["supabase"] | ["firebase"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session, listeners, config) -> list[Finding]:
        """
        Implement your scan logic here.
        - listeners["network"].get_requests() -> list of captured HTTP requests
        - session drives the browser (may be None in headless mode)
        - Use self.emit() to stream progress to the dashboard terminal
        - Return [] if all checks pass
        - If you modify browser state, restore original state in a try/finally block
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

    def _build_finding(self, title: str, severity: Severity, page: str) -> Finding:
        """Build a Finding with the correct evidence structure for this category."""
        # TODO: Fill in the evidence dict below — see docs/SCANNERS.md "Evidence Structure by Category"
        evidence = ${evidence}

        return Finding(
            id=str(uuid.uuid4()),
            fingerprint=self.make_fingerprint(self.name, title, page),
            scanner=self.name,
            severity=severity,
            title=title,
            # TODO: 2-4 sentence plain English explanation
            description="TODO: describe the vulnerability and what an attacker can do.",
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

    def _build_llm_prompt(self, title: str, severity: Severity, page: str, evidence: dict) -> str:
        return (
            f"You are a security expert helping me fix a vulnerability in my web application.\\n\\n"
            f"VULNERABILITY: {title}\\n"
            f"SEVERITY: {severity.value}\\n"
            f"SCANNER: {self.name}\\n"
            f"PAGE: {page}\\n"
            f"CATEGORY: {self.category}\\n\\n"
            "WHAT WAS FOUND:\\n"
            "TODO: Describe what the scanner found and what an attacker could do.\\n\\n"
            "EVIDENCE:\\n"
            "TODO: Include the actual request/response, payload, or leaked data.\\n\\n"
            "YOUR TASK:\\n"
            "Fix the vulnerability described above in my codebase.\\n"
            "1. Explain the root cause\\n"
            "2. Show the specific code change needed (before/after if possible)\\n"
            "3. Confirm what to test after applying the fix"
        )
''')

_TEST_TEMPLATE = Template('''"""${name} scanner tests — real HTTP against the vulnerable fixture app, no Selenium."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.${name} import Scanner
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
# TODO: Replace these placeholder tests with real tests.
# Pattern:
#   - test_<vulnerability_detected>: hit the fixture, assert finding found with expected severity
#   - test_<negative_case>_no_finding: verify clean endpoint produces no findings
# ---------------------------------------------------------------------------

def test_vulnerability_detected(vuln_app) -> None:
    """TODO: Test that the scanner detects the vulnerability in the fixture app."""
    findings = _run(vuln_app)
    # Example assertions (replace with your scanner\'s expected output):
    # assert len(findings) >= 1
    # assert findings[0].severity == Severity.HIGH
    # assert "expected keyword" in findings[0].title.lower()
    assert isinstance(findings, list), "Scanner must return a list"


def test_clean_endpoint_no_finding(vuln_app) -> None:
    """TODO: Test that a clean endpoint produces no findings."""
    req = MagicMock()
    req.url = vuln_app.base_url + "/api/data"
    req.method = "GET"
    req.status_code = 200
    req.response_body = \'{"items": []}\'
    req.post_data = None

    findings = _run(vuln_app, [req])
    # Replace "keyword" with a word that appears in your scanner\'s finding titles:
    matching = [f for f in findings if "keyword" in f.title.lower()]
    assert matching == [], f"Expected no findings for clean endpoint, got {matching}"
''')


def render_scanner(name: str, category: str | None) -> str:
    """Render the scanner template for the given name and optional category."""
    if category and category in VALID_CATEGORIES:
        stages = repr(VALID_CATEGORIES[category])
        evidence = _EVIDENCE_BY_CATEGORY[category]
    else:
        stages = repr(["pre-deploy"])
        evidence = _EVIDENCE_DEFAULT
    return _SCANNER_TEMPLATE.substitute(
        name=name,
        category=category or "injection",
        stages=stages,
        evidence=evidence,
    )


def render_test(name: str) -> str:
    """Render the test template for the given name."""
    return _TEST_TEMPLATE.substitute(name=name)


def build_registry_row(
    name: str,
    category: str | None,
    stages: list[str],
    requires_stack: list[str],
    requires_second_account: bool,
) -> str:
    """Return a markdown table row for the SCANNERS.md registry."""
    category_display = (category or "injection").replace("_", " ").title()
    stages_display = ", ".join(stages)
    stack_display = repr(requires_stack)
    return (
        f"| `{name}` | {category_display} | {stages_display} "
        f"| `{stack_display}` | `{requires_second_account}` | community |"
    )


def append_registry_row(scanners_md_path: str, row: str) -> bool:
    """
    Append `row` to the main scanner registry table in docs/SCANNERS.md.
    Finds the table with the '| Scanner |' header, inserts after the last row.
    Returns True if the row was appended, False if the table was not found.
    """
    try:
        with open(scanners_md_path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return False

    lines = text.splitlines(keepends=True)
    in_main_table = False
    last_table_idx: int | None = None

    for i, line in enumerate(lines):
        if "| Scanner |" in line:
            in_main_table = True
        if in_main_table and line.strip().startswith("|"):
            last_table_idx = i
        elif in_main_table and last_table_idx is not None and line.strip() and not line.strip().startswith("|"):
            break  # first non-empty, non-table line after table ends

    if last_table_idx is None:
        return False

    lines.insert(last_table_idx + 1, row + "\n")
    with open(scanners_md_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    return True
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_scaffold.py -v
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add vibe_iterator/scaffold.py tests/test_scaffold.py
git commit -m "feat: add scaffold module with scanner and test templates"
```

---

### Task 2: CLI `new-scanner` command

**Files:**
- Modify: `vibe_iterator/cli.py`
- Test: `tests/test_cli_scaffold.py`

- [ ] **Step 1: Write failing CLI tests**

Create `tests/test_cli_scaffold.py`:

```python
"""CLI tests for `vibe-iterator new-scanner`."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from vibe_iterator.cli import cli


def _make_repo_tree(base: Path) -> None:
    """Minimal project directory structure the command expects."""
    (base / "vibe_iterator" / "scanners").mkdir(parents=True)
    (base / "tests" / "test_scanners").mkdir(parents=True)
    (base / "docs").mkdir()
    (base / "docs" / "SCANNERS.md").write_text(
        "## Scanner Registry\n\n"
        "| Scanner | Category | Stages | `requires_stack` | `requires_second_account` | Phase |\n"
        "|---------|----------|--------|-----------------|--------------------------|-------|\n"
        "| `existing_scanner` | Injection | pre-deploy | `['any']` | `False` | 2 |\n"
        "\n"
        "Some footnote text.\n",
        encoding="utf-8",
    )


def test_new_scanner_generates_files(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check", "--category", "injection"])
    assert result.exit_code == 0, result.output

    scanner = tmp_path / "vibe_iterator" / "scanners" / "stripe_check.py"
    test_file = tmp_path / "tests" / "test_scanners" / "test_stripe_check.py"
    assert scanner.exists()
    assert test_file.exists()

    scanner_content = scanner.read_text()
    assert 'name = "stripe_check"' in scanner_content
    assert 'category = "injection"' in scanner_content
    assert "['pre-deploy', 'post-deploy']" in scanner_content

    test_content = test_file.read_text()
    assert "from vibe_iterator.scanners.stripe_check import Scanner" in test_content


def test_new_scanner_updates_registry(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    CliRunner().invoke(cli, ["new-scanner", "stripe_check", "--category", "injection"])

    content = (tmp_path / "docs" / "SCANNERS.md").read_text()
    assert "`stripe_check`" in content
    assert "community" in content
    # New row must appear after existing_scanner row
    existing_pos = content.index("`existing_scanner`")
    stripe_pos = content.index("`stripe_check`")
    assert stripe_pos > existing_pos


def test_new_scanner_no_category(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "my_scanner"])
    assert result.exit_code == 0
    scanner = tmp_path / "vibe_iterator" / "scanners" / "my_scanner.py"
    assert scanner.exists()
    content = scanner.read_text()
    assert "['pre-deploy']" in content


def test_new_scanner_invalid_name(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "BadName"])
    assert result.exit_code != 0
    assert "snake_case" in result.output or "Invalid" in result.output


def test_new_scanner_conflict(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    # Pre-create the scanner file to trigger conflict
    (tmp_path / "vibe_iterator" / "scanners" / "stripe_check.py").write_text("# existing\n")

    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check", "--category", "injection"])
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_new_scanner_wrong_directory(tmp_path, monkeypatch):
    # Empty directory — no vibe_iterator/scanners/ present
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check"])
    assert result.exit_code != 0
    assert "project root" in result.output
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_cli_scaffold.py -v
```

Expected: all 6 tests FAIL with `UsageError` or `NoSuchCommand` — the `new-scanner` command doesn't exist yet.

- [ ] **Step 3: Add `new_scanner` subcommand to `vibe_iterator/cli.py`**

Add the following after the `scan` command block (after line 72 in the current file — after the `scan.params.append(...)` block):

```python
@cli.command()
@click.argument("name")
@click.option(
    "--category",
    default=None,
    type=click.Choice(
        ["injection", "access_control", "authentication", "client_tampering",
         "data_leakage", "misconfiguration", "api_security"]
    ),
    help="Scanner category — pre-fills evidence structure and suggests stages.",
)
def new_scanner(name: str, category: str | None) -> None:
    """Generate boilerplate for a new community scanner.

    Run from the vibe-iterator project root.

    Example: vibe-iterator new-scanner stripe_check --category injection
    """
    import re
    from pathlib import Path

    from vibe_iterator.scaffold import (
        VALID_CATEGORIES,
        append_registry_row,
        build_registry_row,
        render_scanner,
        render_test,
    )

    if not re.match(r"^[a-z][a-z0-9_]*$", name):
        click.echo(
            f"[ERROR] Invalid scanner name '{name}'. "
            "Must be lowercase snake_case (e.g., stripe_check).",
            err=True,
        )
        sys.exit(1)

    root = Path.cwd()
    scanner_dir = root / "vibe_iterator" / "scanners"
    test_dir = root / "tests" / "test_scanners"

    if not scanner_dir.is_dir() or not test_dir.is_dir():
        click.echo(
            "[ERROR] Run this command from the vibe-iterator project root.\n"
            "Expected: vibe_iterator/scanners/ and tests/test_scanners/ in current directory.",
            err=True,
        )
        sys.exit(1)

    scanner_path = scanner_dir / f"{name}.py"
    test_path = test_dir / f"test_{name}.py"

    if scanner_path.exists():
        click.echo(f"[ERROR] {scanner_path} already exists. Choose a different name.", err=True)
        sys.exit(1)
    if test_path.exists():
        click.echo(f"[ERROR] {test_path} already exists. Choose a different name.", err=True)
        sys.exit(1)

    scanner_path.write_text(render_scanner(name, category), encoding="utf-8")
    test_path.write_text(render_test(name), encoding="utf-8")

    stages = VALID_CATEGORIES.get(category, ["pre-deploy"]) if category else ["pre-deploy"]
    row = build_registry_row(name, category, stages, ["any"], False)
    scanners_md = root / "docs" / "SCANNERS.md"
    if append_registry_row(str(scanners_md), row):
        click.echo(f"Updated {scanners_md.relative_to(root)}")
    else:
        click.echo(
            f"[WARN] Could not update docs/SCANNERS.md — add the registry row manually.",
            err=True,
        )

    click.echo(f"Created vibe_iterator/scanners/{name}.py")
    click.echo(f"Created tests/test_scanners/test_{name}.py")
    click.echo()
    click.echo("Next:")
    click.echo(f"  1. Fill in the TODOs in vibe_iterator/scanners/{name}.py")
    click.echo(f"  2. Run: pytest tests/test_scanners/test_{name}.py -v")
    click.echo("  3. Run the full suite: pytest tests/ -q")
    click.echo("  4. Open a PR — see CONTRIBUTING.md for the checklist")
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_cli_scaffold.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Smoke-test the command manually**

From the project root:

```bash
vibe-iterator new-scanner smoke_test --category authentication
```

Expected output:
```
Updated docs/SCANNERS.md
Created vibe_iterator/scanners/smoke_test.py
Created tests/test_scanners/test_smoke_test.py

Next:
  1. Fill in the TODOs in vibe_iterator/scanners/smoke_test.py
  2. Run: pytest tests/test_scanners/test_smoke_test.py -v
  3. Run the full suite: pytest tests/ -q
  4. Open a PR — see CONTRIBUTING.md for the checklist
```

Verify:
- `vibe_iterator/scanners/smoke_test.py` was created and contains `name = "smoke_test"`, `category = "authentication"`, `stages = ['dev', 'pre-deploy', 'post-deploy']`
- `tests/test_scanners/test_smoke_test.py` was created
- `docs/SCANNERS.md` contains `| \`smoke_test\``

Then delete the smoke-test files before committing:

```bash
rm vibe_iterator/scanners/smoke_test.py tests/test_scanners/test_smoke_test.py
# Also revert the SCANNERS.md registry row added by the smoke test:
git checkout docs/SCANNERS.md
```

- [ ] **Step 6: Commit**

```bash
git add vibe_iterator/cli.py tests/test_cli_scaffold.py
git commit -m "feat: add new-scanner CLI command to scaffold community scanner boilerplate"
```

---

### Task 3: `CONTRIBUTING.md`

**Files:**
- Create: `CONTRIBUTING.md`

No automated tests — validated by reading the file.

- [ ] **Step 1: Create `CONTRIBUTING.md` at the project root**

```markdown
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
```

- [ ] **Step 2: Verify CONTRIBUTING.md renders correctly**

```bash
python -c "
text = open('CONTRIBUTING.md').read()
assert 'vibe-iterator new-scanner' in text
assert 'PR Checklist' in text or 'checklist' in text
assert 'Design Principles' in text
print('CONTRIBUTING.md OK')
"
```

Expected: `CONTRIBUTING.md OK`

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md with contributor guide and PR checklist"
```

---

### Task 4: Full suite verification

**Files:** (no changes — verification only)

- [ ] **Step 1: Run ruff on all new files**

```bash
ruff check vibe_iterator/scaffold.py vibe_iterator/cli.py tests/test_scaffold.py tests/test_cli_scaffold.py
```

Expected: `All checks passed!`

Fix any lint errors before continuing. Common issue: unused imports.

- [ ] **Step 2: Run the full test suite**

```bash
pytest tests/ -q
```

Expected: all tests pass (≥338 passing, 0 failures). The two new test files add 14 new passing tests.

- [ ] **Step 3: Push to origin**

```bash
git push origin main
```

Expected: CI runs green — lint job passes, test job passes with coverage ≥70%.

---

## Self-Review

**Spec coverage:**
- `vibe_iterator/scaffold.py` with `VALID_CATEGORIES`, templates, `render_scanner`, `render_test`, `build_registry_row`, `append_registry_row`: Task 1 ✅
- `vibe-iterator new-scanner <name> [--category]` CLI command with validation, file generation, registry update, next-steps message: Task 2 ✅
- Error handling — invalid name, conflict, wrong directory, missing SCANNERS.md table: Task 2 step 3 ✅
- `CONTRIBUTING.md` with 6-step flow, testing guide, PR checklist, bug fix section, design principles: Task 3 ✅
- Tests for scaffold module (8 tests) and CLI command (6 tests): Tasks 1 + 2 ✅

**Placeholder scan:** None.

**Type consistency:** `render_scanner(name: str, category: str | None) -> str` is called with `(name, category)` in cli.py. `build_registry_row(name, category, stages, requires_stack, requires_second_account)` receives `VALID_CATEGORIES.get(category, ["pre-deploy"])` for stages. `append_registry_row(str(scanners_md), row)` receives a string path. All consistent.

**Implementer note — template escaping:** The `_SCANNER_TEMPLATE` and `_TEST_TEMPLATE` use `string.Template` with `'''` delimiters. Python f-string expressions in the generated code like `{self.name}` and `{title}` are NOT `$`-prefixed, so they pass through literally without needing escaping. Only `${name}`, `${category}`, `${stages}`, `${evidence}` are substituted. This is the key reason `string.Template` was chosen over `str.format()`.
