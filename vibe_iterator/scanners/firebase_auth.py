# vibe_iterator/scanners/firebase_auth.py
"""Firebase Auth scanner — anonymous auth abuse, email enumeration, token exposure."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    IDENTITY_TOOLKIT_BASE,
    REQUEST_TIMEOUT,
    detect_firebase_config,
    extract_firebase_config,
    find_id_tokens,
    truncate,
    build_firebase_llm_prompt,
)


class Scanner(BaseScanner):
    name = "firebase_auth"
    category = "Authentication"
    stages = ["dev", "pre-deploy", "post-deploy"]
    requires_stack = ["firebase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        network = listeners["network"]
        cfg = self._resolve_config(session, network, config)
        if not cfg:
            return findings

        api_key = cfg.get("apiKey")
        if not api_key:
            return findings

        toolkit_base = cfg.get("_toolkit_base") or IDENTITY_TOOLKIT_BASE
        page = config.target

        try:
            self._group1_anonymous_auth(api_key, toolkit_base, page, findings)
        except Exception:
            pass

        try:
            self._group2_email_enumeration(api_key, toolkit_base, page, config, findings)
        except Exception:
            pass

        try:
            self._group4_token_exposure(network, listeners.get("storage"), page, findings)
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

    def _post(self, url: str, payload: dict) -> tuple[str, int | None]:
        body = json.dumps(payload).encode()
        try:
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _group1_anonymous_auth(self, api_key: str, toolkit_base: str, page: str,
                                findings: list[Finding]) -> None:
        url = f"{toolkit_base}/accounts:signUp?key={api_key}"
        body, status = self._post(url, {"returnSecureToken": True})
        if status == 200:
            try:
                data = json.loads(body)
                has_token = bool(data.get("idToken"))
            except Exception:
                has_token = "idToken" in body
            if has_token:
                desc = (
                    "Firebase project has anonymous authentication enabled. "
                    "Any visitor can sign in anonymously and obtain a valid Firebase ID token. "
                    "If Firestore, RTDB, or Storage rules use 'request.auth != null' as the only check, "
                    "anonymous users can access all 'authenticated' data."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title="Firebase Auth: anonymous sign-in enabled",
                    description=desc,
                    evidence={
                        "check_group": "Anonymous Auth Abuse",
                        "check_name": "Anonymous sign-in returns idToken",
                        "evidence_type": "request_replay",
                        "observed_value": "POST accounts:signUp (no email) -> 200 with idToken",
                        "expected_behavior": "Anonymous sign-in disabled (400 error)",
                        "request": {"method": "POST",
                                    "url": url.replace(api_key, "<redacted>"),
                                    "headers": {"Content-Type": "application/json"},
                                    "body": '{"returnSecureToken": true}'},
                        "response": {"status": status,
                                     "body_excerpt": truncate(body.replace(api_key, "<redacted>"), 300)},
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Firebase Auth: anonymous sign-in enabled",
                        severity=Severity.HIGH, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary="POST accounts:signUp (anonymous) -> 200 with idToken.",
                        detected_services="Auth",
                    ),
                    remediation=(
                        "**What to fix:** Disable anonymous sign-in if not required.\n\n"
                        "**How to fix:** Firebase Console -> Authentication -> Sign-in method -> "
                        "Anonymous -> Disable.\n\n"
                        "**Verify the fix:** Re-run firebase_auth scanner -- anonymous signUp should return 400."
                    ),
                    category=self.category, page=page,
                ))

    def _group2_email_enumeration(self, api_key: str, toolkit_base: str, page: str,
                                   config: Any, findings: list[Finding]) -> None:
        url = f"{toolkit_base}/accounts:createAuthUri?key={api_key}"
        target = getattr(config, "target", "http://localhost")

        registered_body, registered_status = self._post(url, {
            "identifier": "test@example.com",
            "continueUri": target,
        })
        random_body, random_status = self._post(url, {
            "identifier": "randomzzz9x7@nonexistentdomain.invalid",
            "continueUri": target,
        })

        if registered_status != 200 or random_status != 200:
            return

        try:
            reg_data = json.loads(registered_body)
            rnd_data = json.loads(random_body)
            reg_flag = reg_data.get("registered", False)
            rnd_flag = rnd_data.get("registered", False)
            if reg_flag != rnd_flag:
                desc = (
                    "Firebase Authentication exposes whether an email address is registered "
                    "via the accounts:createAuthUri endpoint. An attacker can enumerate "
                    "which email addresses have accounts by probing this endpoint."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.LOW,
                    title="Firebase Auth: email enumeration via createAuthUri",
                    description=desc,
                    evidence={
                        "check_group": "Email Enumeration",
                        "check_name": "accounts:createAuthUri registered flag differs",
                        "evidence_type": "request_replay",
                        "observed_value": "registered=True for known email, False for random",
                        "expected_behavior": "Identical response regardless of whether email exists",
                        "request": {"method": "POST",
                                    "url": url.replace(api_key, "<redacted>"),
                                    "headers": {"Content-Type": "application/json"},
                                    "body": '{"identifier": "<email>", "continueUri": "..."}'},
                        "response": {"status": 200,
                                     "body_excerpt": truncate(registered_body, 200)},
                    },
                    llm_prompt=build_firebase_llm_prompt(
                        title="Firebase Auth: email enumeration via createAuthUri",
                        severity=Severity.LOW, scanner=self.name,
                        page=page, category=self.category, description=desc,
                        evidence_summary="createAuthUri returns different 'registered' flag per email.",
                        detected_services="Auth",
                    ),
                    remediation=(
                        "**What to fix:** Enable email enumeration protection.\n\n"
                        "**How to fix:** Firebase Console -> Authentication -> Settings -> "
                        "Email enumeration protection -> Enable.\n\n"
                        "**Verify the fix:** Re-run firebase_auth scanner -- createAuthUri should return identical responses."
                    ),
                    category=self.category, page=page,
                ))
        except Exception:
            pass

    def _group4_token_exposure(self, network: Any, storage: Any,
                                page: str, findings: list[Finding]) -> None:
        try:
            requests = network.get_requests()
            for req in requests:
                url = getattr(req, "url", "") or ""
                if "?" in url:
                    tokens = find_id_tokens(url)
                    if tokens:
                        desc = (
                            "Firebase ID tokens are being transmitted in URL query parameters. "
                            "URL parameters are logged by servers, proxies, and browser history, "
                            "creating a risk of token leakage."
                        )
                        findings.append(self.new_finding(
                            scanner=self.name, severity=Severity.MEDIUM,
                            title="Firebase Auth: ID token exposed in URL parameter",
                            description=desc,
                            evidence={
                                "check_group": "ID Token Exposure",
                                "check_name": "ID token found in URL query string",
                                "evidence_type": "response_analysis",
                                "observed_value": f"Token found in URL: {truncate(url, 100)}",
                                "expected_behavior": "Tokens transmitted only in Authorization headers",
                                "request": {"method": "GET", "url": truncate(url, 100),
                                            "headers": {}, "body": None},
                                "response": {"status": None, "body_excerpt": ""},
                            },
                            llm_prompt=build_firebase_llm_prompt(
                                title="Firebase Auth: ID token exposed in URL parameter",
                                severity=Severity.MEDIUM, scanner=self.name,
                                page=page, category=self.category, description=desc,
                                evidence_summary="Token found in URL query string.",
                                detected_services="Auth",
                            ),
                            remediation=(
                                "**What to fix:** Move ID tokens from URL parameters to Authorization headers.\n\n"
                                "**How to fix:** Use `Authorization: Bearer <idToken>` instead of `?token=...`.\n\n"
                                "**Verify the fix:** Re-run firebase_auth scanner -- no tokens in URLs."
                            ),
                            category=self.category, page=page,
                        ))
                        break
        except Exception:
            pass
