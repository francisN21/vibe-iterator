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
    Append row to the main scanner registry table in docs/SCANNERS.md.
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
