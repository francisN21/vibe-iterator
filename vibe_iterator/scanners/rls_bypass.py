"""RLS bypass scanner — tests Supabase Row Level Security policies."""

from __future__ import annotations

import json
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import (
    build_table_query_snippet,
    extract_session_token,
    is_postgrest_error,
    parse_postgrest_url,
    truncate,
)

# Tables commonly present in Supabase apps that should have RLS
_COMMON_TABLES = ["profiles", "users", "accounts", "posts", "messages", "orders", "payments", "subscriptions"]


class Scanner(BaseScanner):
    """Attempts unauthorized Supabase table queries to detect missing or weak RLS."""

    name = "rls_bypass"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["supabase"]
    requires_second_account = True

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend
        network = listeners["network"]

        # Discover tables from captured network traffic
        tables = _discover_tables(network)
        if not tables:
            tables = _COMMON_TABLES

        self._check_unauthenticated_access(session, tables, config, findings, stack)
        self._check_cross_user_access(session, tables, config, findings, stack)
        self._check_overpermissive_policies(session, tables, config, findings, stack, network)

        return findings

    # ------------------------------------------------------------------ #
    # Check 1: Unauthenticated access                                     #
    # ------------------------------------------------------------------ #

    def _check_unauthenticated_access(
        self, session: Any, tables: list[str], config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Query tables without auth header — should return 401 or empty."""
        import urllib.request
        base_url = (config.supabase_url or "").rstrip("/")
        anon_key = config.supabase_anon_key or ""
        if not base_url or not anon_key:
            return

        for table in tables[:6]:  # limit to avoid timeout
            url = f"{base_url}/rest/v1/{table}?select=*&limit=1"
            try:
                req = urllib.request.Request(url, headers={"apikey": anon_key})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    data = json.loads(body) if body else []
                    if isinstance(data, list) and len(data) > 0:
                        desc = (
                            f"The `{table}` table is readable by any unauthenticated user using only the anon key. "
                            "If this table contains user data, attackers can read all rows without logging in. "
                            "This usually means RLS is disabled or the policy uses `USING (true)` without "
                            "checking authentication."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.CRITICAL,
                            title=f"Table `{table}` readable without authentication",
                            description=desc,
                            evidence={
                                "action_attempted": f"SELECT * FROM {table} LIMIT 1 (no auth header)",
                                "auth_context": "unauthenticated — anon key only",
                                "request": {"method": "GET", "url": url, "headers": {"apikey": "anon-key"}, "body": None},
                                "response": {"status": 200, "body_excerpt": truncate(body, 300)},
                                "expected_response": "401 Unauthorized or empty array",
                                "actual_response": f"200 OK with {len(data)} row(s)",
                                "second_account_used": False,
                            },
                            llm_prompt=self.build_llm_prompt(
                                title=f"Table `{table}` readable without authentication",
                                severity=Severity.CRITICAL, scanner=self.name,
                                page=config.target, category=self.category, description=desc,
                                evidence_summary=f"GET {url}\nReturned {len(data)} row(s) with anon key only.",
                                stack=stack,
                            ),
                            remediation=(
                                f"**What to fix:** Enable RLS on the `{table}` table and add restrictive policies.\n\n"
                                f"**How to fix:** In Supabase dashboard → Table Editor → {table} → RLS, enable RLS. "
                                f"Then add: `CREATE POLICY \"auth only\" ON {table} FOR SELECT TO authenticated USING (true);`\n"
                                f"Or for per-user rows: `USING (auth.uid() = user_id);`\n\n"
                                "**Verify the fix:** Re-run rls_bypass scanner — unauthenticated query should return 401."
                            ),
                            category=self.category, page=config.target,
                        ))
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Check 2: Cross-user access (requires second account)               #
    # ------------------------------------------------------------------ #

    def _check_cross_user_access(
        self, session: Any, tables: list[str], config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Log in as account 2 and attempt to read account 1's rows."""
        if not config.second_account_configured:
            return

        from vibe_iterator.crawler.auth import login as auth_login, AuthError

        # Get account 1's user ID while still authenticated as account 1
        user1_id = None
        try:
            token_script = extract_session_token()
            token = session.evaluate(token_script)
            if token:
                user1_id = _extract_sub(token)
        except Exception:
            pass

        if not user1_id:
            return

        try:
            auth_login(session, config, account=2)
        except AuthError:
            return

        try:
            for table in tables[:4]:
                snippet = build_table_query_snippet(table, filters={"user_id": user1_id})
                try:
                    result = session.evaluate(snippet)
                except Exception:
                    continue

                if not result or result.get("error"):
                    continue

                data = result.get("data", [])
                if isinstance(data, list) and len(data) > 0:
                    desc = (
                        f"While authenticated as a second test account, we were able to read rows from "
                        f"the `{table}` table that belong to a different user (user_id={truncate(user1_id, 30)}). "
                        "This is an IDOR (Insecure Direct Object Reference) vulnerability. "
                        "Any authenticated user can read any other user's data by querying with their user_id."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.CRITICAL,
                        title=f"IDOR: Cross-user data access on `{table}` table",
                        description=desc,
                        evidence={
                            "action_attempted": f"SELECT * FROM {table} WHERE user_id = '{truncate(user1_id, 20)}' (as user 2)",
                            "auth_context": "authenticated as second test account",
                            "request": {"method": "JS", "url": "CDP Runtime.evaluate", "headers": {}, "body": snippet[:300]},
                            "response": {"status": 200, "body_excerpt": truncate(json.dumps(data[:2]), 300)},
                            "expected_response": "Empty array — RLS should block cross-user access",
                            "actual_response": f"{len(data)} rows returned belonging to user 1",
                            "second_account_used": True,
                        },
                        llm_prompt=self.build_llm_prompt(
                            title=f"IDOR: Cross-user data access on `{table}` table",
                            severity=Severity.CRITICAL, scanner=self.name,
                            page=config.target, category=self.category, description=desc,
                            evidence_summary=(
                                f"Authenticated as user2, queried {table} WHERE user_id = user1_id.\n"
                                f"Received {len(data)} row(s) that belong to user1.\n"
                                f"user1_id: {truncate(user1_id, 30)}"
                            ),
                            stack=stack,
                        ),
                        remediation=(
                            f"**What to fix:** The RLS policy on `{table}` allows any authenticated user to read any row.\n\n"
                            "**How to fix:** Update the SELECT policy to restrict access to the user's own rows:\n"
                            f"```sql\nCREATE POLICY \"Users can only read own rows\"\nON {table} FOR SELECT\nUSING (auth.uid() = user_id);\n```\n\n"
                            "**Verify the fix:** Re-run rls_bypass with second account — cross-user query should return empty array."
                        ),
                        category=self.category, page=config.target,
                    ))
        finally:
            # Always restore primary session
            try:
                auth_login(session, config, account=1)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Check 3: Overly permissive policies in network traffic             #
    # ------------------------------------------------------------------ #

    def _check_overpermissive_policies(
        self, session: Any, tables: list[str], config: Any,
        findings: list[Finding], stack: str, network: Any
    ) -> None:
        """Inspect PostgREST responses for data beyond what the user should see."""
        for req in network.get_requests():
            if "rest/v1/" not in req.url:
                continue
            parsed = parse_postgrest_url(req.url)
            if not parsed:
                continue

            body = req.response_body or ""
            if is_postgrest_error(body):
                continue

            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                continue

            if not isinstance(data, list) or len(data) < 5:
                continue

            # Heuristic: if a list endpoint returns more than 5 rows with no filter,
            # it may be missing a user-scoping policy
            table = parsed.get("table", "unknown")
            filters = parsed.get("filters", {})
            if not filters:
                desc = (
                    f"A request to the `{table}` table returned {len(data)} rows with no filtering. "
                    "If this table contains user-specific data, the RLS policy may be using `USING (true)` "
                    "which allows any authenticated user to read all rows. "
                    "Verify that RLS is scoped to the authenticated user's own rows."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title=f"Table `{table}` returns all rows without user filter",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET {req.url}",
                        "auth_context": "authenticated as primary test account",
                        "request": {"method": req.method, "url": req.url, "headers": {}, "body": None},
                        "response": {"status": req.status_code, "body_excerpt": truncate(body, 300)},
                        "expected_response": "Rows scoped to authenticated user only",
                        "actual_response": f"{len(data)} rows returned with no user_id filter",
                        "second_account_used": False,
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Table `{table}` returns all rows without user filter",
                        severity=Severity.MEDIUM, scanner=self.name,
                        page=req.url, category=self.category, description=desc,
                        evidence_summary=f"GET {req.url}\nReturned {len(data)} rows — no user_id filter in query.",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{table}` RLS SELECT policy is not scoped to the authenticated user.\n\n"
                        f"**How to fix:** Update the policy: "
                        f"`ALTER POLICY ... ON {table} USING (auth.uid() = user_id);`\n\n"
                        "**Verify the fix:** Re-run rls_bypass scanner."
                    ),
                    category=self.category, page=req.url,
                ))
                break  # one finding per scan for this check


def _discover_tables(network: Any) -> list[str]:
    """Extract Supabase table names from captured network requests."""
    tables = []
    seen: set[str] = set()
    for req in network.get_requests():
        if "rest/v1/" not in req.url:
            continue
        parsed = parse_postgrest_url(req.url)
        table = parsed.get("table")
        if table and table not in seen:
            seen.add(table)
            tables.append(table)
    return tables


def _extract_sub(token: str) -> str | None:
    """Extract the 'sub' claim (user ID) from a JWT without verification."""
    try:
        import base64
        import json
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        return payload.get("sub")
    except Exception:
        return None
