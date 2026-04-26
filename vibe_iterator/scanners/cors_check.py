"""CORS check scanner — Phase 4 (stub)."""
from vibe_iterator.scanners.base import BaseScanner, Finding
from typing import Any

class Scanner(BaseScanner):
    name = "cors_check"
    category = "Misconfiguration"
    stages = ["post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        return []  # Implemented in Phase 4
