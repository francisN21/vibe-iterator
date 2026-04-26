"""Core data structures and BaseScanner abstract class."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vibe_iterator.crawler.browser import BrowserSession
    from vibe_iterator.config import Config


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Screenshot:
    """A labeled screenshot captured during a scan."""

    label: str   # e.g. "Before tampering", "Payload injected", "Server response"
    data: str    # base64-encoded PNG: "data:image/png;base64,..."


@dataclass
class Finding:
    """A confirmed vulnerability with full evidence and fix guidance."""

    id: str                          # uuid4 — unique per scan run, not for cross-scan identity
    fingerprint: str                 # sha256(scanner+title+page)[:16] — stable across scans
    scanner: str
    severity: Severity
    title: str
    description: str                 # plain-English, 2–4 sentences, no jargon
    evidence: dict[str, Any]         # category-specific structure — see SCANNERS.md
    screenshots: list[Screenshot]    # ordered: before/during/after
    llm_prompt: str                  # copy-paste prompt for AI assistant
    remediation: str                 # structured fix block
    category: str
    page: str                        # full URL where finding was discovered
    timestamp: str                   # ISO 8601
    mark_status: str = "none"        # "none"|"resolved"|"accepted_risk"|"false_positive"
    mark_note: str | None = None


@dataclass
class ScanEvent:
    """An event emitted by the scan engine to the dashboard or stdout."""

    type: str       # event type string — see ENGINE.md
    timestamp: str  # ISO 8601
    data: dict[str, Any]

    @staticmethod
    def now(event_type: str, data: dict[str, Any]) -> "ScanEvent":
        """Create a ScanEvent with the current UTC timestamp."""
        return ScanEvent(
            type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
        )


class BaseScanner:
    """Abstract base for all scanners.

    Subclasses must set class-level attributes and implement run().
    The engine calls run() via asyncio.to_thread() — keep it synchronous.
    """

    name: str = ""
    category: str = ""
    stages: list[str] = []
    requires_stack: list[str] = ["any"]      # ["supabase"] | ["any"]
    requires_second_account: bool = False

    def run(
        self,
        session: "BrowserSession",
        listeners: dict[str, Any],
        config: "Config",
    ) -> list[Finding]:
        """Execute the scan. Return findings (empty list = all checks passed)."""
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")

    def emit(self, runner: Any, message: str, level: str = "info") -> None:
        """Send a progress message to the terminal feed."""
        event = ScanEvent.now(
            "scanner_progress",
            {"scanner_name": self.name, "message": message, "level": level},
        )
        try:
            runner.on_event(event)
        except Exception:
            pass

    @staticmethod
    def make_fingerprint(scanner: str, title: str, page: str) -> str:
        """Stable cross-scan identity. Always call this when creating a Finding."""
        raw = f"{scanner}::{title}::{page}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def build_llm_prompt(
        *,
        title: str,
        severity: "Severity",
        scanner: str,
        page: str,
        category: str,
        description: str,
        evidence_summary: str,
        stack: str = "unknown",
    ) -> str:
        """Generate a structured LLM fix prompt from raw fields."""
        return (
            f"You are a security expert helping me fix a vulnerability in my web application.\n\n"
            f"VULNERABILITY: {title}\n"
            f"SEVERITY: {severity.value.upper()}\n"
            f"SCANNER: {scanner}\n"
            f"PAGE: {page}\n"
            f"CATEGORY: {category}\n\n"
            f"WHAT WAS FOUND:\n{description}\n\n"
            f"EVIDENCE:\n{evidence_summary}\n\n"
            f"YOUR TASK:\n"
            f"Fix the vulnerability described above in my codebase.\n\n"
            f"1. Explain what the root cause is\n"
            f"2. Show me the specific code change needed (with before/after if possible)\n"
            f"3. If this involves {stack}-specific config (RLS policies, storage rules, auth settings), "
            f"show me the exact config change\n"
            f"4. Confirm what I should test after applying the fix to verify it's resolved\n\n"
            f"My stack: {stack}"
        )

    @staticmethod
    def new_finding(
        *,
        scanner: str,
        severity: Severity,
        title: str,
        description: str,
        evidence: dict[str, Any],
        llm_prompt: str,
        remediation: str,
        category: str,
        page: str,
        screenshots: list[Screenshot] | None = None,
    ) -> Finding:
        """Construct a Finding with generated id, fingerprint, and timestamp."""
        return Finding(
            id=str(uuid.uuid4()),
            fingerprint=BaseScanner.make_fingerprint(scanner, title, page),
            scanner=scanner,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            screenshots=screenshots or [],
            llm_prompt=llm_prompt,
            remediation=remediation,
            category=category,
            page=page,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
