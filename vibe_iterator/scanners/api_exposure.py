"""API exposure scanner — Phase 4 (stub)."""
from vibe_iterator.scanners.base import BaseScanner, Finding
from typing import Any

class Scanner(BaseScanner):
    name = "api_exposure"
    category = "API Security"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        return []  # Implemented in Phase 4
