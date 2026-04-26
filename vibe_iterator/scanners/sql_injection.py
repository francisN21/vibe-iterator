"""SQL injection scanner — PostgREST-specific, classic SQLi, blind, ORM bypass."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import (
    is_postgrest_error,
    parse_postgrest_url,
    truncate,
)

# Payloads for error-based detection
_ERROR_PAYLOADS = [
    ("' OR 1=1--", "error_based"),
    ("' UNION SELECT NULL--", "union"),
    ("'; SELECT pg_sleep(0.1)--", "time_based"),
    ("1' AND 1=2--", "boolean"),
    ("%27 OR %271%27=%271", "encoded"),
]

# PostgREST filter operator injection
_OPERATOR_PAYLOADS = [
    "eq.' OR 1=1--",
    "like.*",
    "gt.0',user_id=lt.9999999",
    "in.(1,2,3);SELECT%201--",
]

# Patterns indicating SQL error leakage in responses
_SQL_ERROR_PATTERNS = [
    re.compile(r"syntax error|parse error|unterminated|unexpected token", re.I),
    re.compile(r"pg_catalog|information_schema|pg_class|pg_namespace", re.I),
    re.compile(r"postgresql|pgsql|postgrest error", re.I),
    re.compile(r"relation \"[^\"]+\" does not exist", re.I),
    re.compile(r"column \"[^\"]+\" does not exist", re.I),
    re.compile(r"operator does not exist", re.I),
]

_PG_SLEEP_THRESHOLD = 2.5  # seconds — flag as time-based if response takes longer


class Scanner(BaseScanner):
    """Six-group SQL injection audit covering PostgREST, classic, blind, ORM, and input vectors."""

    name = "sql_injection"
    category = "Injection"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]

        self._group1_passive_analysis(network, config, findings, stack)
        self._group2_postgrest_injection(network, config, findings, stack)
        self._group3_classic_injection(network, config, findings, stack)
        self._group4_blind_injection(network, config, findings, stack)
        self._group5_input_vectors(session, network, config, findings, stack)
        self._group6_post_exploitation(network, config, findings, stack)

        return findings

    # ------------------------------------------------------------------ #
    # Group 1 — Passive Analysis (no active injection needed)            #
    # ------------------------------------------------------------------ #

    def _group1_passive_analysis(
        self, network: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Scan all captured responses for SQL error messages or schema leaks."""
        for req in network.get_requests():
            body = req.response_body or ""
            if not body:
                continue

            for pattern in _SQL_ERROR_PATTERNS:
                if pattern.search(body):
                    desc = (
                        f"A SQL-related error or schema information was found in the response body "
                        f"of `{req.method} {req.url}`. "
                        "Verbose SQL errors can reveal table names, column names, database version, "
                        "and query structure — information that significantly aids SQL injection attacks."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="SQL error message or schema information exposed in response",
                        description=desc,
                        evidence={
                            "request": {"method": req.method, "url": req.url, "headers": {}, "body": req.post_data},
                            "response": {"status": req.status_code, "body_excerpt": truncate(body, 400),
                                         "body_truncated": len(body) > 400},
                            "payload_used": "none (passive)",
                            "payload_type": "passive_analysis",
                            "injection_point": "response_body",
                            "network_events": [],
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="SQL error message exposed in API response",
                            severity=Severity.MEDIUM, scanner=self.name,
                            page=req.url, category=self.category, description=desc,
                            evidence_summary=f"SQL pattern found in {req.method} {req.url} response:\n{truncate(body, 200)}",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** SQL error messages are leaking database internals in API responses.\n\n"
                            "**How to fix:** Ensure your API returns generic error messages (e.g., `'Internal Server Error'`) "
                            "and logs detailed SQL errors server-side only. "
                            "For PostgREST/Supabase: configure `PGRST_LOG_LEVEL=crit` to suppress verbose errors. "
                            "For custom APIs: never expose raw database exceptions in HTTP responses.\n\n"
                            "**Verify the fix:** Re-run sql_injection scanner."
                        ),
                        category=self.category, page=req.url,
                    ))
                    break  # one finding per request

    # ------------------------------------------------------------------ #
    # Group 2 — PostgREST / Supabase Specific                           #
    # ------------------------------------------------------------------ #

    def _group2_postgrest_injection(
        self, network: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Inject payloads into PostgREST filter parameters."""
        postgrest_requests = [r for r in network.get_requests() if "rest/v1/" in r.url]
        if not postgrest_requests:
            return

        token = _get_auth_headers(config)

        for req in postgrest_requests[:5]:
            parsed = parse_postgrest_url(req.url)
            if not parsed or not parsed.get("filters"):
                continue

            table = parsed["table"]
            for col, val in list(parsed["filters"].items())[:2]:
                for payload, payload_type in _ERROR_PAYLOADS[:3]:
                    test_url = _inject_postgrest_filter(req.url, col, val, payload)
                    body, status, elapsed = _make_request(test_url, "GET", None, token)

                    if _has_sql_error(body):
                        desc = (
                            f"A SQL injection payload in the PostgREST filter parameter `{col}` "
                            f"caused a database error in the `{table}` table endpoint. "
                            "The server is not sanitizing query parameters before passing them to PostgreSQL. "
                            "An attacker can use this to extract data from any table in the database."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.CRITICAL,
                            title=f"SQL injection in PostgREST filter parameter `{col}`",
                            description=desc,
                            evidence={
                                "request": {"method": "GET", "url": test_url, "headers": token, "body": None},
                                "response": {"status": status, "body_excerpt": truncate(body, 400), "body_truncated": len(body) > 400},
                                "payload_used": payload,
                                "payload_type": payload_type,
                                "injection_point": f"url_param:{col}",
                                "network_events": [],
                            },
                            llm_prompt=self.build_llm_prompt(
                                title=f"SQL injection in PostgREST filter `{col}`",
                                severity=Severity.CRITICAL, scanner=self.name,
                                page=req.url, category=self.category, description=desc,
                                evidence_summary=(
                                    f"GET {test_url}\n"
                                    f"Payload: {payload}\n"
                                    f"Response: HTTP {status}\n{truncate(body, 200)}"
                                ),
                                stack=stack,
                            ),
                            remediation=(
                                "**What to fix:** PostgREST filter parameters are not sanitized.\n\n"
                                "**How to fix:** Use parameterized queries in your Supabase client: "
                                "`.eq(col, value)` instead of raw URL construction. "
                                "Never build PostgREST URLs by string concatenation with user input. "
                                "For RPC calls, pass arguments as JSON objects, not URL-embedded strings.\n\n"
                                "**Verify the fix:** Re-run sql_injection scanner."
                            ),
                            category=self.category, page=req.url,
                        ))
                        return  # one finding is enough to establish the issue

    # ------------------------------------------------------------------ #
    # Group 3 — Classic SQL Injection                                    #
    # ------------------------------------------------------------------ #

    def _group3_classic_injection(
        self, network: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Replay API requests with classic SQLi payloads in URL params and JSON bodies."""
        token = _get_auth_headers(config)
        tested: set[str] = set()

        for req in network.get_requests():
            if req.url in tested:
                continue
            if not req.url.startswith("http"):
                continue
            if any(skip in req.url for skip in ["/static/", ".js", ".css", "supabase.co/rest"]):
                continue

            tested.add(req.url)

            # Test URL parameters
            parsed = urllib.parse.urlparse(req.url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            for param_name, param_vals in list(params.items())[:3]:
                for payload, payload_type in _ERROR_PAYLOADS[:2]:
                    test_params = {**params, param_name: [payload]}
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

                    body, status, elapsed = _make_request(test_url, "GET", None, token)

                    if _has_sql_error(body):
                        desc = (
                            f"A SQL injection payload in the `{param_name}` URL parameter "
                            f"of `{req.method} {req.url}` caused a database error. "
                            "The parameter value is passed directly to a SQL query without sanitization. "
                            "An attacker can use error-based or UNION-based techniques to extract all database data."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.CRITICAL,
                            title=f"SQL injection in URL parameter `{param_name}`",
                            description=desc,
                            evidence={
                                "request": {"method": "GET", "url": test_url, "headers": token, "body": None},
                                "response": {"status": status, "body_excerpt": truncate(body, 400), "body_truncated": len(body) > 400},
                                "payload_used": payload,
                                "payload_type": payload_type,
                                "injection_point": f"url_param:{param_name}",
                                "network_events": [],
                            },
                            llm_prompt=self.build_llm_prompt(
                                title=f"SQL injection in URL parameter `{param_name}`",
                                severity=Severity.CRITICAL, scanner=self.name,
                                page=req.url, category=self.category, description=desc,
                                evidence_summary=(
                                    f"GET {test_url}\n"
                                    f"Payload in `{param_name}`: {payload}\n"
                                    f"Response: HTTP {status} — SQL error detected"
                                ),
                                stack=stack,
                            ),
                            remediation=(
                                f"**What to fix:** The `{param_name}` parameter is used in a raw SQL query.\n\n"
                                "**How to fix:** Use parameterized queries (prepared statements) for all database operations. "
                                "Never interpolate URL parameters directly into SQL strings. "
                                "Example: `db.query('SELECT * FROM users WHERE id = $1', [req.query.id])` instead of "
                                "`db.query('SELECT * FROM users WHERE id = ' + req.query.id)`.\n\n"
                                "**Verify the fix:** Re-run sql_injection scanner."
                            ),
                            category=self.category, page=req.url,
                        ))
                        return

            # Test JSON body fields
            if req.post_data:
                try:
                    body_data = json.loads(req.post_data)
                    if not isinstance(body_data, dict):
                        continue
                    for field_name, field_val in list(body_data.items())[:3]:
                        if not isinstance(field_val, str):
                            continue
                        for payload, payload_type in _ERROR_PAYLOADS[:2]:
                            test_body = {**body_data, field_name: payload}
                            resp_body, status, _ = _make_request(
                                req.url, req.method,
                                json.dumps(test_body).encode(), token,
                            )
                            if _has_sql_error(resp_body):
                                desc = (
                                    f"A SQL injection payload in the `{field_name}` JSON body field "
                                    f"of `{req.method} {req.url}` caused a database error. "
                                    "JSON body fields are passed directly to SQL without sanitization."
                                )
                                findings.append(self.new_finding(
                                    scanner=self.name, severity=Severity.CRITICAL,
                                    title=f"SQL injection in JSON body field `{field_name}`",
                                    description=desc,
                                    evidence={
                                        "request": {"method": req.method, "url": req.url, "headers": token, "body": json.dumps(test_body)[:200]},
                                        "response": {"status": status, "body_excerpt": truncate(resp_body, 400), "body_truncated": False},
                                        "payload_used": payload,
                                        "payload_type": payload_type,
                                        "injection_point": f"json_field:{field_name}",
                                        "network_events": [],
                                    },
                                    llm_prompt=self.build_llm_prompt(
                                        title=f"SQL injection in JSON body field `{field_name}`",
                                        severity=Severity.CRITICAL, scanner=self.name,
                                        page=req.url, category=self.category, description=desc,
                                        evidence_summary=f"{req.method} {req.url}\nField `{field_name}` = `{payload}`\n→ HTTP {status} with SQL error",
                                        stack=stack,
                                    ),
                                    remediation=(
                                        f"**What to fix:** JSON field `{field_name}` is unsafely used in a SQL query.\n\n"
                                        "**How to fix:** Use parameterized queries for all inputs. "
                                        "Validate and sanitize all incoming JSON fields before using them in database queries.\n\n"
                                        "**Verify the fix:** Re-run sql_injection scanner."
                                    ),
                                    category=self.category, page=req.url,
                                ))
                                return
                except (json.JSONDecodeError, TypeError):
                    pass

    # ------------------------------------------------------------------ #
    # Group 4 — Blind SQL Injection                                      #
    # ------------------------------------------------------------------ #

    def _group4_blind_injection(
        self, network: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Test for time-based and boolean-based blind SQLi in API endpoints."""
        token = _get_auth_headers(config)
        tested: set[str] = set()

        for req in network.get_requests():
            if req.url in tested or not req.url.startswith("http"):
                continue
            if any(skip in req.url for skip in ["/static/", ".js", ".css"]):
                continue
            tested.add(req.url)

            parsed = urllib.parse.urlparse(req.url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            param_name = next(iter(params))
            original_val = params[param_name][0]

            # Time-based: inject pg_sleep
            sleep_payload = f"{original_val}'; SELECT pg_sleep(3)--"
            test_params = {**params, param_name: [sleep_payload]}
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            _, _, elapsed = _make_request(test_url, "GET", None, token, timeout=10)

            if elapsed >= _PG_SLEEP_THRESHOLD:
                desc = (
                    f"A time-based blind SQL injection payload (`pg_sleep(3)`) caused a {elapsed:.1f}s delay "
                    f"in the `{param_name}` parameter of `{req.url}`. "
                    "The database is executing the injected SQL. "
                    "Even without visible error messages, an attacker can extract all data using timing attacks."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.CRITICAL,
                    title=f"Time-based blind SQL injection in parameter `{param_name}`",
                    description=desc,
                    evidence={
                        "request": {"method": "GET", "url": test_url, "headers": token, "body": None},
                        "response": {"status": None, "body_excerpt": f"Response delayed by {elapsed:.1f}s (threshold: {_PG_SLEEP_THRESHOLD}s)", "body_truncated": False},
                        "payload_used": sleep_payload,
                        "payload_type": "time_based",
                        "injection_point": f"url_param:{param_name}",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Time-based blind SQL injection in `{param_name}`",
                        severity=Severity.CRITICAL, scanner=self.name,
                        page=req.url, category=self.category, description=desc,
                        evidence_summary=f"pg_sleep(3) payload in `{param_name}` → {elapsed:.1f}s response time at {req.url}",
                        stack=stack,
                    ),
                    remediation=(
                        "**What to fix:** Parameter is vulnerable to time-based blind SQL injection.\n\n"
                        "**How to fix:** Use parameterized queries — never interpolate user input into SQL. "
                        "Example fix: `db.query('SELECT * FROM t WHERE col = $1', [userInput])`. "
                        "An ORM like Prisma with typed queries prevents this class of vulnerability entirely.\n\n"
                        "**Verify the fix:** Re-run sql_injection scanner — pg_sleep payload must not cause delay."
                    ),
                    category=self.category, page=req.url,
                ))
                return

    # ------------------------------------------------------------------ #
    # Group 5 — Input Vector Discovery                                   #
    # ------------------------------------------------------------------ #

    def _group5_input_vectors(
        self, session: Any, network: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Test form inputs discovered in the live DOM."""
        try:
            from selenium.webdriver.common.by import By
            inputs = session.driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search'], textarea")
        except Exception:
            return

        token = _get_auth_headers(config)

        for input_el in inputs[:5]:
            try:
                name = input_el.get_attribute("name") or input_el.get_attribute("id") or "unknown"
                placeholder = input_el.get_attribute("placeholder") or ""

                network.clear()
                input_el.clear()
                input_el.send_keys("' OR '1'='1")

                # Submit the form
                try:
                    form = input_el.find_element(By.XPATH, "./ancestor::form")
                    form.submit()
                except Exception:
                    from selenium.webdriver.common.keys import Keys
                    input_el.send_keys(Keys.ENTER)

                time.sleep(1.0)

                for req in network.get_requests():
                    body = req.response_body or ""
                    if _has_sql_error(body):
                        desc = (
                            f"A SQL injection payload submitted via the `{name}` form input "
                            f"(placeholder: `{placeholder}`) caused a SQL error in the server response. "
                            "Form inputs are being passed directly to SQL queries without sanitization."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.CRITICAL,
                            title=f"SQL injection via form input `{name}`",
                            description=desc,
                            evidence={
                                "request": {"method": req.method, "url": req.url, "headers": {}, "body": req.post_data},
                                "response": {"status": req.status_code, "body_excerpt": truncate(body, 300), "body_truncated": False},
                                "payload_used": "' OR '1'='1",
                                "payload_type": "error_based",
                                "injection_point": f"form_input:{name}",
                                "network_events": [],
                            },
                            llm_prompt=self.build_llm_prompt(
                                title=f"SQL injection via form input `{name}`",
                                severity=Severity.CRITICAL, scanner=self.name,
                                page=config.target, category=self.category, description=desc,
                                evidence_summary=f"Input '{name}' with payload \"' OR '1'='1\" → SQL error in response",
                                stack=stack,
                            ),
                            remediation=(
                                f"**What to fix:** Form input `{name}` is used unsafely in a SQL query.\n\n"
                                "**How to fix:** Parameterize all database queries. "
                                "Validate and escape all form inputs server-side before use in SQL.\n\n"
                                "**Verify the fix:** Re-run sql_injection scanner."
                            ),
                            category=self.category, page=config.target,
                        ))
                        return
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Group 6 — Post-Exploitation Indicators                             #
    # ------------------------------------------------------------------ #

    def _group6_post_exploitation(
        self, network: Any, config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Check captured traffic for schema leakage and verbose DB errors."""
        schema_patterns = [
            re.compile(r"information_schema\.(tables|columns|routines)", re.I),
            re.compile(r"pg_catalog\.(pg_class|pg_namespace|pg_attribute)", re.I),
            re.compile(r"(PostgreSQL|Supabase|PostgREST)\s+\d+\.\d+", re.I),
        ]

        for req in network.get_requests():
            body = req.response_body or ""
            for pattern in schema_patterns:
                m = pattern.search(body)
                if m:
                    desc = (
                        f"A database schema reference (`{m.group(0)}`) was found in a network response body. "
                        "Schema exposure helps attackers understand the database structure and craft targeted injection attacks."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="Database schema information exposed in API response",
                        description=desc,
                        evidence={
                            "request": {"method": req.method, "url": req.url, "headers": {}, "body": None},
                            "response": {"status": req.status_code, "body_excerpt": truncate(body, 300), "body_truncated": len(body) > 300},
                            "payload_used": "none (passive)",
                            "payload_type": "passive_analysis",
                            "injection_point": "response_body",
                            "network_events": [],
                        },
                        llm_prompt=self.build_llm_prompt(
                            title="Database schema information exposed in API response",
                            severity=Severity.MEDIUM, scanner=self.name,
                            page=req.url, category=self.category, description=desc,
                            evidence_summary=f"Schema reference `{m.group(0)}` in {req.method} {req.url} response.",
                            stack=stack,
                        ),
                        remediation=(
                            "**What to fix:** Internal database schema details are leaking in API responses.\n\n"
                            "**How to fix:** Configure your error handler to return generic messages. "
                            "For PostgREST/Supabase: set `PGRST_LOG_LEVEL=crit` and never expose raw Postgres errors.\n\n"
                            "**Verify the fix:** Re-run sql_injection scanner."
                        ),
                        category=self.category, page=req.url,
                    ))
                    return


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _has_sql_error(body: str) -> bool:
    for pattern in _SQL_ERROR_PATTERNS:
        if pattern.search(body):
            return True
    return False


def _make_request(
    url: str, method: str, data: bytes | None, headers: dict, timeout: int = 6
) -> tuple[str, int | None, float]:
    """Make an HTTP request and return (body, status_code, elapsed_seconds)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(50_000).decode("utf-8", errors="replace")
            elapsed = time.monotonic() - start
            return body, resp.status, elapsed
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(50_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return body, e.code, time.monotonic() - start
    except Exception:
        return "", None, time.monotonic() - start


def _get_auth_headers(config: Any) -> dict:
    headers: dict = {"Content-Type": "application/json"}
    anon_key = getattr(config, "supabase_anon_key", None)
    if anon_key:
        headers["apikey"] = anon_key
        headers["Authorization"] = f"Bearer {anon_key}"
    return headers


def _inject_postgrest_filter(url: str, col: str, original_val: str, payload: str) -> str:
    """Replace a PostgREST filter value with an injection payload."""
    return url.replace(f"{col}=eq.{urllib.parse.quote(original_val)}", f"{col}=eq.{urllib.parse.quote(payload)}")
