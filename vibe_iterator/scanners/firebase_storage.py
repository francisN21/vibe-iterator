"""Storage security scanner — unauthenticated download/upload/listing detection."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    PROBE_PREFIX,
    REQUEST_TIMEOUT,
    build_firebase_llm_prompt,
    detect_firebase_config,
    extract_firebase_config,
    is_closed_local_url,
    truncate,
)

_COMMON_FILE_PATHS = [
    "public/test.txt", "avatars/user1.png", "uploads/doc.pdf",
    "images/photo.jpg", "users/uid1/profile.jpg",
]
_PROBE_FILE = f"{PROBE_PREFIX}canary.txt"
_PROBE_CONTENT = b"vibe-iterator probe; safe to delete"


class Scanner(BaseScanner):
    name = "firebase_storage"
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

        bucket = cfg.get("storageBucket") or f"{cfg['projectId']}.appspot.com"
        page = config.target
        base = self._storage_base(bucket)

        try:
            self._group1_unauth_download(bucket, base, page, findings)
        except Exception:
            pass

        try:
            self._group2_unauth_upload(bucket, base, page, findings)
        except Exception:
            pass

        try:
            self._group4_bucket_listing(bucket, base, page, findings)
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

    def _storage_base(self, bucket: str) -> str:
        """Return base URL for Storage REST calls. Supports local fixture (127.0.0.1:port)."""
        if ":" in bucket or bucket.startswith("127."):
            return f"http://{bucket}"
        return "https://firebasestorage.googleapis.com"

    def _http_get(self, url: str, token: str | None = None) -> tuple[str, int | None]:
        if is_closed_local_url(url):
            return "", None

        headers: dict = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
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

    def _http_post(self, url: str, content: bytes, content_type: str,
                   token: str | None = None) -> tuple[str, int | None]:
        if is_closed_local_url(url):
            return "", None

        headers: dict = {"Content-Type": content_type}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            req = urllib.request.Request(url, data=content, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _http_delete(self, url: str, token: str | None = None) -> tuple[str, int | None]:
        if is_closed_local_url(url):
            return "", None

        headers: dict = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
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

    def _group1_unauth_download(self, bucket: str, base: str, page: str,
                                 findings: list[Finding]) -> None:
        for path in _COMMON_FILE_PATHS:
            enc = urllib.parse.quote(path, safe="")
            url = f"{base}/v0/b/{bucket}/o/{enc}?alt=media"
            body, status = self._http_get(url)
            if status == 200 and body:
                desc = (
                    f"Firebase Storage file '{path}' is downloadable without authentication. "
                    "An attacker can download private files without any credentials. "
                    "Storage Security Rules are either missing or set to 'allow read: if true;'."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title=f"Storage: unauthenticated file download allowed ({path})",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET /o/{path}?alt=media (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 200)},
                        "expected_response": "403 Forbidden",
                        "actual_response": "200 OK with file bytes",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Storage: unauthenticated file download allowed",
                        severity=Severity.HIGH, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET {path} (no auth) -> 200",
                        detected_services="Storage",
                    ),
                    remediation=(
                        "**What to fix:** Require authentication to read Storage files.\n\n"
                        "**How to fix:** Firebase Console -> Storage -> Rules:\n"
                        "```\nrules_version = '2';\nservice firebase.storage {\n"
                        "  match /b/{bucket}/o {\n"
                        "    match /{allPaths=**} {\n"
                        "      allow read, write: if request.auth != null;\n"
                        "    }\n  }\n}\n```\n\n"
                        "**Verify the fix:** Re-run firebase_storage scanner -- download should return 403."
                    ),
                    category=self.category, page=page,
                ))
                break  # one finding is enough to prove the rule is open

    def _group2_unauth_upload(self, bucket: str, base: str, page: str,
                               findings: list[Finding]) -> None:
        enc = urllib.parse.quote(_PROBE_FILE, safe="")
        upload_url = f"{base}/v0/b/{bucket}/o?name={enc}"
        delete_url = f"{base}/v0/b/{bucket}/o/{enc}"
        body, status = self._http_post(upload_url, _PROBE_CONTENT, "application/octet-stream")
        try:
            if status is not None and 200 <= status < 300:
                desc = (
                    "Firebase Storage accepts file uploads without authentication. "
                    "An attacker can upload arbitrary files to the storage bucket, "
                    "potentially serving malicious content or exhausting storage quota. "
                    "Storage Security Rules are either missing or set to 'allow write: if true;'."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title="Storage: unauthenticated file upload allowed",
                    description=desc,
                    evidence={
                        "action_attempted": f"POST /o?name={_PROBE_FILE} (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "POST", "url": upload_url,
                                    "headers": {}, "body": f"{len(_PROBE_CONTENT)} bytes"},
                        "response": {"status": status, "body_excerpt": truncate(body, 200)},
                        "expected_response": "403 Forbidden",
                        "actual_response": f"{status} -- upload accepted",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Storage: unauthenticated file upload allowed",
                        severity=Severity.HIGH, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"POST probe file (no auth) -> {status}",
                        detected_services="Storage",
                    ),
                    remediation=(
                        "**What to fix:** Require authentication for Storage writes.\n\n"
                        "**How to fix:** Firebase Console -> Storage -> Rules -- require `request.auth != null`.\n\n"
                        "**Verify the fix:** Re-run firebase_storage scanner -- upload should return 403."
                    ),
                    category=self.category, page=page,
                ))
        finally:
            self._http_delete(delete_url)

    def _group4_bucket_listing(self, bucket: str, base: str, page: str,
                                findings: list[Finding]) -> None:
        url = f"{base}/v0/b/{bucket}/o"
        body, status = self._http_get(url)
        if status == 200:
            try:
                data = json.loads(body)
                items = data.get("items", [])
            except Exception:
                items = []
            if items:
                names = [i.get("name", "") for i in items[:5]]
                desc = (
                    "Firebase Storage bucket contents are enumerable without authentication. "
                    f"An attacker can list all stored files. Found {len(items)} item(s): {names}."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title="Storage: bucket file listing allowed without auth",
                    description=desc,
                    evidence={
                        "action_attempted": f"GET /v0/b/{bucket}/o (no auth)",
                        "auth_context": "unauthenticated",
                        "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                        "response": {"status": status, "body_excerpt": truncate(body, 300)},
                        "expected_response": "403 Forbidden",
                        "actual_response": f"200 with {len(items)} items",
                        "second_account_used": False,
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Storage: bucket file listing allowed without auth",
                        severity=Severity.MEDIUM, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary=f"GET bucket listing (no auth) -> 200, {len(items)} files",
                        detected_services="Storage",
                    ),
                    remediation=(
                        "**What to fix:** Disable unauthenticated bucket listing.\n\n"
                        "**How to fix:** Firebase Console -> Storage -> Rules -- require `request.auth != null`.\n\n"
                        "**Verify the fix:** Re-run firebase_storage scanner -- listing should return 403."
                    ),
                    category=self.category, page=page,
                ))
