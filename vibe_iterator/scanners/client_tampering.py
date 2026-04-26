"""Client tampering scanner — modifies client-side state and tests server trust."""

from __future__ import annotations

import json
import time
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# Keys that indicate roles, permissions, or feature flags
_ROLE_KEYS = [
    "role", "user_role", "userRole", "account_type", "accountType",
    "permissions", "is_admin", "isAdmin", "admin", "is_premium", "isPremium",
    "tier", "plan", "planType", "subscription", "feature_flags", "featureFlags",
]
_ESCALATION_VALUES = {
    "role": "admin",
    "user_role": "admin",
    "userRole": "admin",
    "account_type": "admin",
    "accountType": "admin",
    "is_admin": "true",
    "isAdmin": "true",
    "admin": "true",
    "tier": "premium",
    "plan": "premium",
    "planType": "enterprise",
    "subscription": "premium",
}


class Scanner(BaseScanner):
    """Modifies localStorage/cookie values for role/permissions and checks server trust."""

    name = "client_tampering"
    category = "Client-Side Tampering"
    stages = ["dev", "pre-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        storage = listeners["storage"]

        latest = storage.get_latest()
        if not latest:
            return findings

        page = latest.url
        self._check_localstorage_tampering(session, latest, network, config, findings, stack, page)
        self._check_cookie_tampering(session, config, network, findings, stack, page)
        self._check_role_in_jwt_payload(session, config, findings, stack)

        return findings

    # ------------------------------------------------------------------ #
    # localStorage tampering                                               #
    # ------------------------------------------------------------------ #

    def _check_localstorage_tampering(
        self, session: Any, snapshot: Any, network: Any, config: Any,
        findings: list[Finding], stack: str, page: str
    ) -> None:
        local = snapshot.local_storage

        for key in _ROLE_KEYS:
            original_value = local.get(key)
            if original_value is None:
                continue

            original_str = str(original_value)
            target_value = _ESCALATION_VALUES.get(key, "admin")

            if original_str.lower() == target_value.lower():
                continue  # already the highest value

            original_restored: str | None = None
            try:
                # Snapshot original value
                original_restored = session.evaluate(
                    f"(function(){{ return localStorage.getItem('{key}'); }})()"
                )

                # Tamper
                session.evaluate(
                    f"(function(){{ localStorage.setItem('{key}', {json.dumps(target_value)}); }})()"
                )
                network.clear()

                # Trigger server interaction
                session.navigate(page)
                time.sleep(1.0)

                # Check if server acted on the tampered value
                suspicious = _detect_server_acceptance(network, target_value)
                # Also check if the value persisted (server didn't reset it)
                current = session.evaluate(
                    f"(function(){{ return localStorage.getItem('{key}'); }})()"
                )
                server_trusted = suspicious or (current == target_value)

                if server_trusted:
                    desc = (
                        f"The server appears to trust the `{key}` value stored in localStorage. "
                        f"By changing `{key}` from `{original_str}` to `{target_value}`, "
                        "a user can escalate their own privileges or access features reserved for higher tiers. "
                        "Client-side storage must never be the source of truth for authorization decisions."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title=f"Server trusts client-supplied `{key}` from localStorage",
                        description=desc,
                        evidence={
                            "storage_key": key,
                            "original_value": original_str,
                            "tampered_value": target_value,
                            "storage_type": "localStorage",
                            "action_performed": f"Set localStorage['{key}'] = '{target_value}', reloaded {page}",
                            "request": {"method": "GET", "url": page, "headers": {}, "body": None},
                            "response": {"status": 200, "body_excerpt": f"Page loaded with tampered {key}={target_value}; server did not reject or reset it"},
                            "expected_response": f"Server should derive {key} from database, not client storage",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title=f"Server trusts client-supplied `{key}` from localStorage",
                            severity=Severity.HIGH, scanner=self.name,
                            page=page, category=self.category, description=desc,
                            evidence_summary=(
                                f"localStorage['{key}']: '{original_str}' → '{target_value}'\n"
                                f"Page reloaded — server did not reset the value or reject the tampered state."
                            ),
                            stack=stack,
                        ),
                        remediation=(
                            f"**What to fix:** The application reads `{key}` from client-side localStorage for authorization.\n\n"
                            "**How to fix:** Remove all role/permission checks that read from `localStorage` or cookies. "
                            "Derive the user's role exclusively from authenticated JWT claims or a server-side DB lookup. "
                            "For Supabase: add the role to `app_metadata` in the users table and read it from the JWT "
                            "`auth.jwt() -> 'app_metadata' -> 'role'` in RLS policies.\n\n"
                            "**Verify the fix:** Re-run client_tampering scanner — tampered value should have no effect."
                        ),
                        category=self.category, page=page,
                    ))

            except Exception:
                pass
            finally:
                # Always restore original state
                try:
                    if original_restored is not None:
                        session.evaluate(
                            f"(function(){{ localStorage.setItem('{key}', {json.dumps(str(original_restored))}); }})()"
                        )
                    else:
                        session.evaluate(
                            f"(function(){{ localStorage.removeItem('{key}'); }})()"
                        )
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Cookie tampering                                                    #
    # ------------------------------------------------------------------ #

    def _check_cookie_tampering(
        self, session: Any, config: Any, network: Any,
        findings: list[Finding], stack: str, page: str
    ) -> None:
        try:
            cookies = session.driver.get_cookies()
        except Exception:
            return

        for cookie in cookies:
            name = cookie.get("name", "")
            val = cookie.get("value", "")

            if not any(kw in name.lower() for kw in ["role", "plan", "tier", "admin", "perm"]):
                continue

            if cookie.get("httpOnly"):
                continue  # Can't tamper with HttpOnly cookies via JS

            original_value = val
            target_value = "admin"
            if original_value.lower() == target_value:
                continue

            try:
                # Tamper cookie via Selenium
                session.driver.add_cookie({
                    **cookie,
                    "value": target_value,
                })
                network.clear()
                session.navigate(page)
                time.sleep(0.8)

                suspicious = _detect_server_acceptance(network, target_value)

                if suspicious:
                    desc = (
                        f"The `{name}` cookie value was changed from `{original_value}` to `{target_value}`. "
                        "The server appears to have accepted this tampered value. "
                        "Cookie values that control authorization must never be trusted without server-side verification."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.HIGH,
                        title=f"Server trusts client-supplied `{name}` cookie for authorization",
                        description=desc,
                        evidence={
                            "storage_key": name,
                            "original_value": original_value,
                            "tampered_value": target_value,
                            "storage_type": "cookie",
                            "action_performed": f"Changed cookie `{name}` to `{target_value}`, reloaded {page}",
                            "request": {"method": "GET", "url": page, "headers": {"Cookie": f"{name}={target_value}"}, "body": None},
                            "response": {"status": 200, "body_excerpt": "Server accepted tampered cookie value"},
                            "expected_response": "Server should derive authorization from JWT/session, not plain cookie value",
                        },
                        llm_prompt=self.build_llm_prompt(
                            title=f"Server trusts client-supplied `{name}` cookie for authorization",
                            severity=Severity.HIGH, scanner=self.name,
                            page=page, category=self.category, description=desc,
                            evidence_summary=(
                                f"Cookie `{name}`: '{original_value}' → '{target_value}'\n"
                                f"Server accepted the tampered cookie."
                            ),
                            stack=stack,
                        ),
                        remediation=(
                            f"**What to fix:** The `{name}` cookie controls server-side authorization.\n\n"
                            "**How to fix:** Never use plain (non-signed) cookies to convey authorization roles. "
                            "Use a signed JWT (which cannot be tampered without the signing key) or derive roles "
                            "from the server-side session. Sign cookies with HMAC if you must store state in them.\n\n"
                            "**Verify the fix:** Re-run client_tampering scanner."
                        ),
                        category=self.category, page=page,
                    ))
            except Exception:
                pass
            finally:
                # Restore original cookie
                try:
                    session.driver.add_cookie({**cookie, "value": original_value})
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # JWT payload claim tampering                                        #
    # ------------------------------------------------------------------ #

    def _check_role_in_jwt_payload(
        self, session: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Check if the JWT role claim is taken from client-side storage rather than server-signed."""
        try:
            from vibe_iterator.utils.supabase_helpers import extract_session_token
            token = session.evaluate(extract_session_token())
            if not token:
                return

            # Decode payload
            import base64
            parts = token.split(".")
            if len(parts) != 3:
                return
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            role = payload.get("role") or payload.get("user_role")

            if role and role.lower() in ("authenticated", "anon", "public"):
                return  # Standard Supabase roles — fine

            # The role is in the JWT — this is only a concern if the JWT is self-issued
            # without proper server verification. Flag as info-level.
            if role and role.lower() not in ("authenticated", "anon"):
                desc = (
                    f"The JWT payload contains a custom `role` claim with value `{role}`. "
                    "If your application grants permissions based on this claim and an attacker can "
                    "forge or escalate this claim (e.g., via alg:none or weak secret), "
                    "they can gain elevated privileges. "
                    "Ensure this claim is verified server-side and cannot be client-supplied."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.INFO,
                    title=f"Custom role claim in JWT payload: `{role}`",
                    description=desc,
                    evidence={
                        "storage_key": "JWT payload.role",
                        "original_value": role,
                        "tampered_value": "not tested — informational",
                        "storage_type": "JWT",
                        "action_performed": "Decoded JWT payload — found custom role claim",
                        "request": None,
                        "response": None,
                        "expected_response": "If role is used for authorization, it must be server-verified",
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Custom role claim in JWT payload: `{role}`",
                        severity=Severity.INFO, scanner=self.name,
                        page=config.target, category=self.category, description=desc,
                        evidence_summary=f"JWT payload contains role='{role}'. Verify this is set by the server and cannot be forged.",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** Custom `role` claim (`{role}`) found in JWT.\n\n"
                        "**How to fix:** Ensure the role is set in `app_metadata` by your server or Supabase hooks, "
                        "not by the client. In Supabase, set user metadata via the Admin API: "
                        "`supabase.auth.admin.updateUserById(uid, { app_metadata: { role: 'admin' } })`. "
                        "Never allow users to set their own app_metadata.\n\n"
                        "**Verify the fix:** Confirm role is populated server-side."
                    ),
                    category=self.category, page=config.target,
                ))
        except Exception:
            pass


def _detect_server_acceptance(network: Any, tampered_value: str) -> bool:
    """Heuristic: check if any post-navigation API response references the tampered value."""
    for req in network.get_requests():
        if "/api/" not in req.url and "supabase.co" not in req.url:
            continue
        body = (req.response_body or "").lower()
        if tampered_value.lower() in body:
            return True
    return False
