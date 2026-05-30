# vibe_iterator/scanners/firebase_functions.py
"""Cloud Functions security scanner — unauth access, CORS, sensitive data."""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.firebase_helpers import (
    REQUEST_TIMEOUT,
    build_firebase_llm_prompt,
    detect_firebase_config,
    discover_function_urls,
    extract_firebase_config,
    find_id_tokens,
    truncate,
)

_ADMIN_FN_NAMES = [
    "admin", "deleteUser", "setRole", "createAdmin", "grantAdmin",
    "resetPassword", "exportData",
]
_SENSITIVE_BODY_PATTERNS = ["idToken", "refreshToken", "access_token",
                             "password", "secret", "traceback", "__proto__"]

_REGION_RE = re.compile(r"https?://([^/]+)\.cloudfunctions\.net")


class Scanner(BaseScanner):
    name = "firebase_functions"
    category = "API Security"
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
        page = config.target

        # Test injection: allow config to supply function URLs directly
        if hasattr(config, "_firebase_cfg") and config._firebase_cfg.get("_test_fn_urls"):
            fn_urls = list(config._firebase_cfg["_test_fn_urls"])
        else:
            fn_urls = discover_function_urls(network.get_requests())

            regions = self._extract_regions(fn_urls) or ["us-central1"]
            for region in regions[:2]:
                for name in _ADMIN_FN_NAMES:
                    url = f"https://{region}-{project_id}.cloudfunctions.net/{name}"
                    fn_urls.append(url)
            fn_urls = list(dict.fromkeys(fn_urls))

        if not fn_urls:
            return findings

        for url in fn_urls[:15]:
            try:
                self._probe_function(url, project_id, page, findings)
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

    def _extract_regions(self, urls: list[str]) -> list[str]:
        regions = []
        for url in urls:
            m = _REGION_RE.search(url)
            if m:
                parts = m.group(1).split("-")
                if len(parts) >= 3:
                    region = "-".join(parts[:-1])
                    if region not in regions:
                        regions.append(region)
        return regions

    def _probe_function(self, url: str, project_id: str, page: str,
                        findings: list[Finding]) -> None:
        body_no_auth, status_no_auth = self._http_post(url, {"probe": True}, token=None)
        if status_no_auth == 200:
            desc = (
                f"Cloud Function at '{url}' is callable without authentication. "
                "Any anonymous user can invoke this function. "
                "Functions handling sensitive operations should verify the caller's identity."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title=f"Cloud Functions: callable without authentication ({url.split('/')[-1]})",
                description=desc,
                evidence={
                    "endpoint": url,
                    "test_performed": "replay_without_auth",
                    "request": {"method": "POST", "url": url, "headers": {}, "body": '{"probe":true}'},
                    "response": {"status": status_no_auth,
                                 "body_excerpt": truncate(body_no_auth, 300)},
                    "expected_response": "401 Unauthorized",
                },
                llm_prompt=build_firebase_llm_prompt(
                    title="Cloud Functions: callable without authentication",
                    severity=Severity.HIGH, scanner=self.name,
                    page=page, category=self.category, description=desc,
                    evidence_summary=f"POST {url} (no auth) -> 200",
                    detected_services="Cloud Functions",
                ),
                remediation=(
                    "**What to fix:** Verify the caller's identity inside the function.\n\n"
                    "**How to fix:** For callable functions, use `context.auth`. For HTTPS functions:\n"
                    "```js\nconst token = req.headers.authorization?.split('Bearer ')[1];\n"
                    "if (!token) return res.status(401).send('Unauthorized');\n"
                    "await admin.auth().verifyIdToken(token);\n```\n\n"
                    "**Verify the fix:** Re-run firebase_functions scanner -- unauthenticated call should return 401."
                ),
                category=self.category, page=page,
            ))

            if body_no_auth:
                tokens = find_id_tokens(body_no_auth)
                has_sensitive = tokens or any(p in body_no_auth for p in _SENSITIVE_BODY_PATTERNS)
                if has_sensitive:
                    sev = Severity.HIGH if tokens else Severity.MEDIUM
                    desc2 = (
                        f"Cloud Function at '{url}' returns sensitive data in its response body: "
                        f"{'ID tokens were found' if tokens else 'sensitive fields detected'}. "
                        "Tokens leaked in responses can be captured by network monitoring tools."
                    )
                    findings.append(self.new_finding(
                        scanner=self.name, severity=sev,
                        title=f"Cloud Functions: sensitive data in response ({url.split('/')[-1]})",
                        description=desc2,
                        evidence={
                            "endpoint": url,
                            "test_performed": "response_analysis",
                            "request": {"method": "POST", "url": url, "headers": {}, "body": '{"probe":true}'},
                            "response": {"status": status_no_auth,
                                         "body_excerpt": truncate(body_no_auth, 300)},
                            "expected_response": "Response without tokens or internal data",
                        },
                        llm_prompt=build_firebase_llm_prompt(
                            title="Cloud Functions: sensitive data in response",
                            severity=sev, scanner=self.name,
                            page=page, category=self.category, description=desc2,
                            evidence_summary="Function response contains sensitive data.",
                            detected_services="Cloud Functions",
                        ),
                        remediation=(
                            "**What to fix:** Never return tokens, passwords, or internal data in function responses.\n\n"
                            "**How to fix:** Audit function response bodies and strip any tokens or secrets.\n\n"
                            "**Verify the fix:** Re-run firebase_functions scanner -- no tokens in response."
                        ),
                        category=self.category, page=page,
                    ))

        cors_body, cors_status, cors_headers = self._http_options(url)
        acao = cors_headers.get("Access-Control-Allow-Origin", "")
        acac = cors_headers.get("Access-Control-Allow-Credentials", "")
        if (acao == "*" or acao == "https://evil.example") and acac.lower() == "true":
            desc3 = (
                f"Cloud Function at '{url}' has a CORS misconfiguration: "
                "it allows all origins (or reflects the evil origin) and also sets "
                "Access-Control-Allow-Credentials: true. "
                "This combination lets a malicious site read the function's response using the victim's cookies."
            )
            findings.append(self.new_finding(
                scanner=self.name, severity=Severity.HIGH,
                title=f"Cloud Functions: CORS misconfiguration ({url.split('/')[-1]})",
                description=desc3,
                evidence={
                    "endpoint": url,
                    "test_performed": "cors_probe",
                    "request": {"method": "OPTIONS", "url": url,
                                "headers": {"Origin": "https://evil.example"}, "body": None},
                    "response": {"status": cors_status,
                                 "body_excerpt": f"ACAO: {acao}, ACAC: {acac}"},
                    "expected_response": "ACAO restricted to known origins or ACAC absent/false",
                },
                llm_prompt=build_firebase_llm_prompt(
                    title="Cloud Functions: CORS misconfiguration",
                    severity=Severity.HIGH, scanner=self.name,
                    page=page, category=self.category, description=desc3,
                    evidence_summary=f"OPTIONS {url} -> ACAO={acao}, ACAC={acac}",
                    detected_services="Cloud Functions",
                ),
                remediation=(
                    "**What to fix:** Restrict CORS origins and never combine wildcard with credentials.\n\n"
                    "**How to fix:** In the function:\n"
                    "```js\nconst ALLOWED = ['https://myapp.com'];\n"
                    "if (ALLOWED.includes(req.headers.origin)) {\n"
                    "  res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
                    "}\n// Do NOT set Allow-Credentials: true with a wildcard origin.\n```\n\n"
                    "**Verify the fix:** Re-run firebase_functions scanner -- CORS probe should not reflect evil origin."
                ),
                category=self.category, page=page,
            ))

    def _http_post(self, url: str, payload: dict, token: str | None) -> tuple[str, int | None]:
        import json as _json
        headers: dict = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = _json.dumps(payload).encode()
        try:
            req = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), resp.status
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code
            except Exception:
                return "", e.code
        except Exception:
            return "", None

    def _http_options(self, url: str) -> tuple[str, int | None, dict]:
        headers: dict = {"Origin": "https://evil.example",
                         "Access-Control-Request-Method": "POST"}
        try:
            req = urllib.request.Request(url, method="OPTIONS", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                resp_headers = dict(resp.headers)
                return resp.read().decode("utf-8", errors="replace"), resp.status, resp_headers
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace"), e.code, dict(e.headers)
            except Exception:
                return "", e.code, {}
        except Exception:
            return "", None, {}
