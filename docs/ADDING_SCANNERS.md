# Adding a New Scanner

This guide walks you through building and shipping a new scanner for vibe-iterator from scratch.

For a quick scaffold, run:

```bash
vibe-iterator new-scanner my_scanner --category injection
```

That generates the boilerplate described below. Read this guide to understand what to fill in.

---

## 1. Understand BaseScanner

Every scanner lives in `vibe_iterator/scanners/` and inherits from `BaseScanner`:

```python
# vibe_iterator/scanners/base.py
class BaseScanner:
    name: str          # snake_case identifier, unique across all scanners
    stages: list[str]  # when this scanner runs: "pre-deploy", "post-deploy", or both
    category: str      # one of the 7 valid categories (see below)
    requires_stack: list[str]   # ["supabase"], ["firebase"], or ["any"]
    requires_second_account: bool  # True if scanner needs a second test account

    def run(
        self,
        session: BrowserSession | None,
        listeners: dict[str, Any],
        config: Config,
    ) -> list[Finding]:
        ...
```

**Valid categories:** `injection`, `access_control`, `authentication`, `client_tampering`, `data_leakage`, `misconfiguration`, `api_security`

**Valid stages:** `dev`, `pre-deploy`, `post-deploy`, `all`

---

## 2. Create the Scanner File

Create `vibe_iterator/scanners/my_scanner.py`:

```python
"""My scanner -- one-line description of what it detects."""

from __future__ import annotations

from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity


class Scanner(BaseScanner):
    name = "my_scanner"
    stages = ["pre-deploy"]
    category = "injection"
    requires_stack = ["any"]
    requires_second_account = False

    def run(
        self,
        session: Any,
        listeners: dict[str, Any],
        config: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Your detection logic here.
        # Use listeners["network"].get_requests() for captured HTTP traffic.
        # Use listeners["storage"].get_latest() for localStorage / cookies.
        # Use config.target for the base URL.

        return findings
```

### Emitting a Finding

```python
findings.append(
    Finding(
        scanner=self.name,
        severity=Severity.HIGH,
        title="Descriptive title of the vulnerability",
        description="What the vulnerability is and why it matters.",
        evidence={
            "url": "https://example.com/api/endpoint",
            "payload": "injected payload",
            "response": "error message that proves the issue",
        },
        remediation="How the developer should fix this.",
        category=self.category,
        page=config.target,
        llm_prompt=(
            "You have a SQL injection vulnerability at /api/endpoint. "
            "The payload `OR 1=1--` returns all rows. Fix: use parameterized queries."
        ),
    )
)
```

**Severity levels:** `Severity.CRITICAL`, `Severity.HIGH`, `Severity.MEDIUM`, `Severity.LOW`, `Severity.INFO`

---

## 3. Implement `run()`

### Passive analysis (Group 1)

Inspect already-captured network traffic -- no new requests:

```python
network = listeners.get("network")
if network:
    for req in network.get_requests():
        if "error" in (req.response_body or "").lower():
            # flag it
```

### Active probing (Group 3+)

Make new HTTP requests against the live target:

```python
import urllib.request, urllib.parse, urllib.error

def _probe(url: str, payload: str) -> tuple[int, str]:
    full_url = f"{url}?q={urllib.parse.quote(payload)}"
    try:
        with urllib.request.urlopen(full_url, timeout=5) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", errors="replace")
    except Exception:
        return 0, ""
```

### Working without Selenium

If your scanner only replays captured traffic or sends raw HTTP requests, `session` will be `None` -- guard it:

```python
if session is None:
    return findings  # or skip Selenium-dependent steps
```

---

## 4. Declare Stages

Set `stages` to control when vibe-iterator runs your scanner:

| Stage | When to use |
|-------|-------------|
| `pre-deploy` | Logic checks that do not need a live prod environment |
| `post-deploy` | Checks that need the real deployed app |
| `dev` | Local-only checks during development |
| `all` | Every scan stage |

Most scanners use `["pre-deploy"]` or `["pre-deploy", "post-deploy"]`.

---

## 5. Write Tests

Create `tests/test_scanners/test_my_scanner.py`.

### Minimum test set

```python
"""Tests for my_scanner."""

from unittest.mock import MagicMock
from vibe_iterator.scanners.my_scanner import Scanner
from vibe_iterator.scanners.base import Severity


def _make_config(target: str = "http://localhost:9999") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _run(network_requests=None, target="http://localhost:9999") -> list:
    scanner = Scanner()
    config = _make_config(target)
    net = _make_network(network_requests or [])
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_vulnerability_detected() -> None:
    """Positive: scanner produces a finding when the vulnerability is present."""
    findings = _run(...)
    assert len(findings) >= 1
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_no_false_positive_on_clean_response() -> None:
    """Negative: scanner produces no finding when the app is not vulnerable."""
    findings = _run()
    assert findings == []


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "my_scanner"
    assert isinstance(s.stages, list)
    assert len(s.stages) >= 1
```

### Run the tests

```bash
# Just your scanner
pytest tests/test_scanners/test_my_scanner.py -v

# Full suite (must stay green)
pytest tests/ -q
```

---

## 6. Register in the Scanner Registry

Add a row to `docs/SCANNERS.md` in the **Scanner Registry** table:

```markdown
| `my_scanner` | Injection | pre-deploy | `['any']` | `False` | community |
```

The `vibe-iterator new-scanner` command does this automatically. If you created the file manually, add the row yourself.

---

## Checklist Before Opening a PR

- [ ] `Scanner.name` is unique -- check `vibe_iterator/scanners/` for conflicts
- [ ] `stages`, `category`, `requires_stack` are all set (no `None`)
- [ ] At least one positive test (vulnerability detected) and one negative test (no false positive)
- [ ] `pytest tests/ -q` passes with no new failures
- [ ] `ruff check vibe_iterator/ tests/` reports no errors
- [ ] Row added to `docs/SCANNERS.md`
- [ ] PR description explains: what the scanner detects, how it probes, and a sample finding

---

## Design Principles

- **Prove it, do not guess.** A finding must come from observable evidence -- a real HTTP response, a captured network request, a storage value. Never emit a finding based on the URL pattern alone.
- **Non-destructive.** Payloads may trigger error responses, but must not write persistent data, delete records, or cause side effects in the target app.
- **Fail silently.** If a probe errors (timeout, connection refused), return an empty findings list. Never let a scanner crash the overall scan.
- **One responsibility.** A scanner detects one class of vulnerability. If you find yourself writing two unrelated detection groups, split into two scanners.
