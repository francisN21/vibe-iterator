"""XSS check scanner — Phase 4 (stub)."""
from vibe_iterator.scanners.base import BaseScanner, Finding
from typing import Any

class Scanner(BaseScanner):
    name = "xss_check"
    category = "Injection"
    stages = ["pre-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        return []  # Implemented in Phase 4
