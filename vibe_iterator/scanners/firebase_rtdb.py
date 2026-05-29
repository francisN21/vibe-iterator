"""Realtime Database security scanner — open read/write rules detection."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    REQUEST_TIMEOUT,
    detect_firebase_config,
    extract_firebase_config,
    rest_rtdb_delete,
    rest_rtdb_get,
    rest_rtdb_write,
    truncate,
    build_firebase_llm_prompt,
)

_COMMON_PATHS = ["users", "config", "admin", "settings", "messages", "profiles", "orders"]


class Scanner(BaseScanner):
    name = "firebase_rtdb"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        db_url = cfg.get("databaseURL") or (
            f"https://{cfg['projectId']}-default-rtdb.firebaseio.com"
        )
        page = config.target

        try:
            self._group1_unauth_access(db_url, page, findings)
        except Exception:
            pass

        try:
            self._group2_unauth_write(db_url, page, findings)
        except Exception:
            pass

        try:
            self._group3_shallow_enumeration(db_url, page, findings)
        except Exception:
            pass

        return findings

    def _resolve_config(self, session: Any, network: Any, config: Any) -> dict | None:
        if hasattr(config, "_firebase_cfg"):
            return config._firebase_cfg
        cfg: dict = {}
        if session is not None:
            try:
                cfg = extract_firebase_config(session)
            except Exception:
                pass
        if not cfg.get("projectId"):
            try:
                cfg = detect_firebase_config(network.get_requests()) or {}
            except Exception:
                pass
        return cfg if cfg.get("projectId") else None

    def _group1_unauth_access(self, db_url: str, page: str,
                               findings: list[Finding]) -> None:
        body, status = rest_rtdb_get(db_url, "", id_token=None)
        if status == 200:
            try:
                data = json.loads(body)
                has_data = data is not None and data != {}
            except Exception:
                has_data = bool(body and body.strip() != "null")
            if has_data:
                desc = (
                    "The Firebase Realtime Database root is readable without authentication. "
                    "Any anonymous user can fetch the entire database contents. "
                    "This is caused by a Security Rule like '.read: true' at the root level. "
                    "All data in the database is exposed."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.CRITICAL,
                    title="Realtime Database: unauthenticated root read allowed",
                    description=desc,
                    evidence={
                        "action_attempted": "GET /.json (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": f"{db_url}/.json", "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "401 or permission-denied",
                        "actual_response": "200 OK with data",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Realtime Database: unauthenticated root read allowed",
                        severity=Severity.CRITICAL, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET {db_url}/.json returned 200 with data.",
                        detected_services="Realtime Database",
                    ),
                    remediation=(
                        "**What to fix:** Set `.read` to require authentication at the root.\n\n"
                        "**How to fix:** In Firebase Console -> Realtime Database -> Rules:\n"
                        '```json\n{ "rules": { ".read": "auth != null", ".write": "auth != null" } }\n```\n\n'
                        "**Verify the fix:** Re-run firebase_rtdb scanner -- root read should return 401."
                    ),
                    category=self.category, page=page,
                ))

    def _group2_unauth_write(self, db_url: str, page: str,
                              findings: list[Finding]) -> None:
        probe_path = PROBE_PREFIX + "canary"
        probe_data = {"vibe_iterator": True, "ts": "probe"}
        body, status = rest_rtdb_write(db_url, probe_path, probe_data, id_token=None)
        try:
            if status == 200:
                desc = (
                    "The Firebase Realtime Database accepts write operations without authentication. "
                    "An attacker can write arbitrary data to any database path, including overwriting "
                    "user records or injecting malicious content. "
                    "This is caused by a Security Rule like '.write: true' at the root."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.CRITICAL,
                    title="Realtime Database: unauthenticated write allowed",
                    description=desc,
                    evidence={
                        "action_attempted": f"PUT /{probe_path}.json (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "PUT", "url": f"{db_url}/{probe_path}.json",
                                    "headers": {}, "body": '{"vibe_iterator":true,"ts":"probe"}'},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "401 Unauthorized",
                        "actual_response": "200 OK",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Realtime Database: unauthenticated write allowed",
                        severity=Severity.CRITICAL, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"PUT {db_url}/{probe_path}.json (no auth) -> 200.",
                        detected_services="Realtime Database",
                    ),
                    remediation=(
                        "**What to fix:** Require authentication for all writes.\n\n"
                        "**How to fix:** Firebase Console -> Realtime Database -> Rules:\n"
                        '```json\n{ "rules": { ".write": "auth != null" } }\n```\n\n'
                        "**Verify the fix:** Re-run firebase_rtdb scanner -- unauthenticated write should return 401."
                    ),
                    category=self.category, page=page,
                ))
        finally:
            rest_rtdb_delete(db_url, probe_path, id_token=None)

    def _rest_rtdb_shallow(self, db_url: str) -> tuple[str, int | None]:
        """GET /.json?shallow=true — avoids the path-mangling in rest_rtdb_get."""
        base = (db_url or "").rstrip("/")
        url = f"{base}/.json?shallow=true"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _group3_shallow_enumeration(self, db_url: str, page: str,
                                     findings: list[Finding]) -> None:
        body, status = self._rest_rtdb_shallow(db_url)
        if status == 200:
            try:
                data = json.loads(body)
                is_key_map = isinstance(data, dict) and len(data) > 0
            except Exception:
                is_key_map = False
            if is_key_map:
                keys = list(data.keys())[:10]
                url = f"{db_url}/.json?shallow=true"
                desc = (
                    "The Firebase Realtime Database exposes its top-level structure to anonymous users "
                    "via the ?shallow=true parameter. Attackers can enumerate all top-level keys "
                    f"without authentication. Discovered keys: {keys}."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Realtime Database: top-level structure enumerable without auth",
                    description=desc,
                    evidence={
                        "action_attempted": "GET /.json?shallow=true (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "401 or empty",
                        "actual_response": f"200 with keys: {keys}",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Realtime Database: top-level structure enumerable without auth",
                        severity=Severity.MEDIUM, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET /.json?shallow=true -> 200, keys: {keys}",
                        detected_services="Realtime Database",
                    ),
                    remediation=(
                        "**What to fix:** Disable unauthenticated read at the root.\n\n"
                        "**How to fix:** Firebase Console -> Realtime Database -> Rules:\n"
                        '```json\n{ "rules": { ".read": "auth != null" } }\n```\n\n'
                        "**Verify the fix:** Re-run firebase_rtdb scanner -- shallow read should return 401."
                    ),
                    category=self.category, page=page,
                ))
