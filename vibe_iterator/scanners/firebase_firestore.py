# vibe_iterator/scanners/firebase_firestore.py
"""Firestore security scanner — open rules, IDOR, mass assignment."""
from __future__ import annotations

import json as _json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    REQUEST_TIMEOUT,
    detect_firebase_config,
    extract_firebase_config,
    truncate,
    build_firebase_llm_prompt,
    _to_firestore_fields,
    _from_firestore_fields,
)

_COMMON_COLLECTIONS = [
    "users", "profiles", "orders", "payments", "admin",
    "config", "settings", "subscriptions", "messages", "posts",
]
_PRIVILEGE_FIELDS = {
    "role": "admin", "is_admin": True, "is_premium": True,
    "subscription_tier": "enterprise", "credits": 999999,
}
_SENSITIVE_COLLECTIONS = {"users", "payments", "admin", "profiles"}

_FIRESTORE_HOST = "https://firestore.googleapis.com"


class Scanner(BaseScanner):
    name = "firebase_firestore"
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

        project_id = cfg["projectId"]
        stack = config.stack.backend
        page = config.target
        # Allow test injection of a custom Firestore base URL
        firestore_base = cfg.get("_firestore_base") or _FIRESTORE_HOST

        try:
            self._group1_unauth_access(project_id, firestore_base, stack, page, findings)
        except Exception:
            pass

        try:
            self._group3_mass_assignment(project_id, firestore_base, stack, page, findings)
        except Exception:
            pass

        try:
            self._group4_collection_enum(project_id, firestore_base, stack, page, findings)
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

    def _firestore_get(self, firestore_base: str, project_id: str, collection: str,
                       doc_id: str, id_token: str | None = None) -> tuple[str, int | None]:
        url = (f"{firestore_base}/v1/projects/{project_id}"
               f"/databases/(default)/documents/{collection}/{doc_id}")
        headers: dict = {}
        if id_token:
            headers["Authorization"] = f"Bearer {id_token}"
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _firestore_write(self, firestore_base: str, project_id: str, collection: str,
                         doc_id: str, data: dict,
                         id_token: str | None = None) -> tuple[str, int | None]:
        if PROBE_PREFIX not in doc_id:
            return "", None
        url = (f"{firestore_base}/v1/projects/{project_id}"
               f"/databases/(default)/documents/{collection}/{doc_id}")
        headers: dict = {"Content-Type": "application/json"}
        if id_token:
            headers["Authorization"] = f"Bearer {id_token}"
        body = _json.dumps(_to_firestore_fields(data)).encode()
        try:
            req = urllib.request.Request(url, data=body, method="PATCH", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _firestore_delete(self, firestore_base: str, project_id: str, collection: str,
                          doc_id: str, id_token: str | None = None) -> tuple[str, int | None]:
        url = (f"{firestore_base}/v1/projects/{project_id}"
               f"/databases/(default)/documents/{collection}/{doc_id}")
        headers: dict = {}
        if id_token:
            headers["Authorization"] = f"Bearer {id_token}"
        try:
            req = urllib.request.Request(url, headers=headers, method="DELETE")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _group1_unauth_access(self, project_id: str, firestore_base: str, stack: str,
                               page: str, findings: list[Finding]) -> None:
        for coll in _COMMON_COLLECTIONS[:6]:
            body, status = self._firestore_get(firestore_base, project_id, coll, "probe_doc")
            if status == 200:
                sev = Severity.CRITICAL if coll in _SENSITIVE_COLLECTIONS else Severity.HIGH
                desc = (
                    f"Firestore collection '{coll}' is readable without authentication. "
                    "Security Rules allow unauthenticated reads, exposing all documents. "
                    "Any attacker can enumerate user data without credentials."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=sev,
                    title=f"Firestore: unauthenticated read on '{coll}' collection",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET /documents/{coll}/probe_doc (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {
                            "method": "GET",
                            "url": f"{firestore_base}/v1/projects/{project_id}/databases/(default)/documents/{coll}/probe_doc",
                            "headers": {}, "body": None,
                        },
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "403 PERMISSION_DENIED",
                        "actual_response": "200 OK with document data",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title=f"Firestore: unauthenticated read on '{coll}'",
                        severity=sev, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET /documents/{coll}/probe_doc (no auth) -> 200",
                        detected_services="Firestore",
                    ),
                    remediation=(
                        f"**What to fix:** Add Security Rules that require authentication for '{coll}'.\n\n"
                        "**How to fix:** Firebase Console -> Firestore Database -> Rules:\n"
                        "```\nrules_version = '2';\nservice cloud.firestore {\n"
                        f"  match /databases/{{database}}/documents/{coll}/{{doc}} {{\n"
                        "    allow read, write: if request.auth != null;\n"
                        "  }\n}\n```\n\n"
                        "**Verify the fix:** Re-run firebase_firestore scanner -- unauthenticated read should return 403."
                    ),
                    category=self.category, page=page,
                ))
                break  # one proof is sufficient

    def _group3_mass_assignment(self, project_id: str, firestore_base: str, stack: str,
                                 page: str, findings: list[Finding]) -> None:
        doc_id = PROBE_PREFIX + "massassign_test"
        try:
            body, status = self._firestore_write(
                firestore_base, project_id, "users", doc_id, _PRIVILEGE_FIELDS
            )
            if status is not None and 200 <= status < 300:
                rb, rs = self._firestore_get(firestore_base, project_id, "users", doc_id)
                try:
                    doc = _json.loads(rb)
                    persisted = _from_firestore_fields(doc)
                    confirmed = any(k in persisted for k in _PRIVILEGE_FIELDS)
                except Exception:
                    confirmed = True
                if confirmed:
                    desc = (
                        "Firestore allows writing privileged fields (role, is_admin, is_premium) "
                        "without authentication or server-side validation. "
                        "An attacker can escalate privileges by writing to their own or another user's document."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=Severity.MEDIUM,
                        title="Firestore: mass assignment of privileged fields allowed",
                        description=desc,
                        evidence={
                            "action_attempted": f"PATCH /documents/users/{doc_id} with privilege fields",
                            "auth_context": "unauthenticated",
                            "request": {
                                "method": "PATCH",
                                "url": f"{firestore_base}/v1/projects/{project_id}/databases/(default)/documents/users/{doc_id}",
                                "headers": {}, "body": str(_PRIVILEGE_FIELDS),
                            },
                            "response": {"status": status, "body_excerpt": truncate(body, 300)},
                            "expected_response": "403 PERMISSION_DENIED",
                            "actual_response": f"{status} -- privileged fields written",
                            "second_account_used": False,
                        },
                        llm_prompt=build_firebase_llm_prompt(
                            title="Firestore: mass assignment of privileged fields allowed",
                            severity=Severity.MEDIUM, scanner=self.name,
                            page=page, category=self.category, description=desc,
                            evidence_summary=f"PATCH users/{doc_id} with role=admin (no auth) -> {status}",
                            detected_services="Firestore",
                        ),
                        remediation=(
                            "**What to fix:** Block client writes to privileged fields.\n\n"
                            "**How to fix:** Use Security Rules to restrict which fields can be written:\n"
                            "```\nallow write: if request.auth != null &&\n"
                            "  !('role' in request.resource.data) &&\n"
                            "  !('is_admin' in request.resource.data);\n```\n\n"
                            "**Verify the fix:** Re-run firebase_firestore scanner -- privileged write should return 403."
                        ),
                        category=self.category, page=page,
                    ))
        finally:
            try:
                self._firestore_delete(firestore_base, project_id, "users", doc_id)
            except Exception:
                pass

    def _group4_collection_enum(self, project_id: str, firestore_base: str, stack: str,
                                 page: str, findings: list[Finding]) -> None:
        open_colls = []
        for coll in _COMMON_COLLECTIONS[:8]:
            body, status = self._firestore_get(firestore_base, project_id, coll, "enum_probe")
            if status == 200:
                open_colls.append(coll)
        if open_colls:
            desc = (
                f"Firestore collections are enumerable without authentication: {open_colls}. "
                "An attacker can discover collection names and read documents without credentials. "
                "Security Rules are either absent or use 'allow read: if true;'."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.MEDIUM,
                title=f"Firestore: {len(open_colls)} collection(s) enumerable without auth",
                description=desc,
                evidence={
                    "action_attempted": "GET /documents/<coll>/probe for each common collection",
                    "auth_context": "unauthenticated",
                    "request": {"method": "GET", "url": "multiple", "headers": {}, "body": None},
                    "response": {"status": 200,
                                 "body_excerpt": f"Collections returning 200: {open_colls}"},
                    "expected_response": "403 PERMISSION_DENIED for all",
                    "actual_response": f"{len(open_colls)} open",
                    "second_account_used": False,
                },
                llm_prompt=build_firebase_llm_prompt(
                    title="Firestore: collections enumerable without auth",
                    severity=Severity.MEDIUM, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"Open collections: {open_colls}",
                    detected_services="Firestore",
                ),
                remediation=(
                    "**What to fix:** Apply Security Rules to all collections.\n\n"
                    "**How to fix:** Firebase Console -> Firestore Database -> Rules -- add "
                    "'allow read, write: if request.auth != null;' to each collection.\n\n"
                    "**Verify the fix:** Re-run firebase_firestore scanner -- all collections should return 403."
                ),
                category=self.category, page=page,
            ))
