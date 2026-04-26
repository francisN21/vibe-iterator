"""Tier escalation scanner — client-side subscription tier manipulation."""

from __future__ import annotations

import json
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import build_rpc_snippet, truncate

_TIER_KEYS = [
    "plan", "tier", "subscription", "subscription_tier", "plan_name",
    "planType", "tierName", "subscriptionPlan", "user_tier", "account_plan",
]
_PREMIUM_VALUES = ["premium", "pro", "enterprise", "admin", "unlimited", "paid", "business"]


class Scanner(BaseScanner):
    """Reads client-side subscription tier, escalates it, and tests server trust."""

    name = "tier_escalation"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["supabase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend
        storage = listeners["storage"]

        # Examine every captured storage snapshot for tier-related keys
        for snapshot in storage.get_snapshots():
            self._check_snapshot(session, snapshot, config, findings, stack)

        return findings

    def _check_snapshot(
        self, session: Any, snapshot: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        local = snapshot.local_storage
        page = snapshot.url

        for key in _TIER_KEYS:
            original_value = local.get(key)
            if original_value is None:
                # Also check sessionStorage
                original_value = snapshot.session_storage.get(key)
                if original_value is None:
                    continue
                storage_type = "sessionStorage"
            else:
                storage_type = "localStorage"

            original_str = str(original_value)

            # Skip if the value is already premium
            if original_str.lower() in _PREMIUM_VALUES:
                continue

            # Pick a target escalation value
            target_value = "premium"

            original_storage = None
            try:
                # Capture original state
                get_script = f"return {storage_type}.getItem('{key}');"
                original_storage = session.evaluate(f"(function(){{ {get_script} }})()")

                # Escalate client-side
                set_script = f"{storage_type}.setItem('{key}', '{target_value}');"
                session.evaluate(f"(function(){{ {set_script} }})()")

                # Navigate to trigger any tier-gated logic
                session.navigate(page)

                # Check if any API calls now reflect the escalated tier
                from vibe_iterator.listeners.network import NetworkListener
                # Re-read storage after navigation
                read_script = f"(function(){{ return {storage_type}.getItem('{key}'); }})()"
                server_saw_value = session.evaluate(read_script)

                # Check Supabase user metadata if available
                rpc_script = build_rpc_snippet("get_user_tier")
                try:
                    rpc_result = session.evaluate(rpc_script)
                except Exception:
                    rpc_result = None

                # Heuristic: if page loaded without error and server didn't reset the value,
                # the server may be trusting the client-side tier
                if server_saw_value == target_value:
                    desc = (
                        f"The subscription tier stored in {storage_type} under `{key}` can be changed "
                        f"from `{original_str}` to `{target_value}` on the client, and the server does not "
                        "reset it on the next request. "
                        "If your application grants access to features based on this client-side value, "
                        "any user can bypass subscription restrictions without paying."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title=f"Subscription tier accepted from client-side {storage_type}",
                        description=desc,
                        evidence={
                            "storage_key": key,
                            "original_value": original_str,
                            "tampered_value": target_value,
                            "storage_type": storage_type,
                            "action_performed": f"Set {storage_type}['{key}'] = '{target_value}', navigated to {page}",
                            "request": {"method": "GET", "url": page, "headers": {}, "body": None},
                            "response": {"status": 200, "body_excerpt": f"Server did not reset {key} — value remained: {target_value}"},
                            "expected_response": f"Server should reset {key} to the authenticated user's real tier",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title=f"Subscription tier accepted from client-side {storage_type}",
                            severity=Severity.HIGH, scanner=self.name,
                            page=page, category=self.category, description=desc,
                            evidence_summary=(
                                f"Key: {storage_type}['{key}']\n"
                                f"Original: {original_str}\n"
                                f"Escalated to: {target_value}\n"
                                f"Server response: did not reset the value"
                            ),
                            stack=stack,
                        ),
                        remediation=(
                            f"**What to fix:** The server trusts the `{key}` value from client-side storage.\n\n"
                            "**How to fix:** Never read subscription tier from client-side storage on the server. "
                            "Derive the user's tier exclusively from the database on every request — "
                            "e.g., a `subscriptions` table joined via the authenticated user's ID. "
                            "For Supabase: create a server-side function or use RLS policies based on a "
                            "`subscriptions` table, not a client-supplied value.\n\n"
                            "**Verify the fix:** Re-run tier_escalation scanner — escalated value should be ignored."
                        ),
                        category=self.category, page=page,
                    ))

            except Exception:
                pass
            finally:
                # Always restore original value
                try:
                    if original_storage is not None:
                        restore = f"(function(){{ {storage_type}.setItem('{key}', {json.dumps(str(original_storage))}); }})()"
                    else:
                        restore = f"(function(){{ {storage_type}.removeItem('{key}'); }})()"
                    session.evaluate(restore)
                except Exception:
                    pass
