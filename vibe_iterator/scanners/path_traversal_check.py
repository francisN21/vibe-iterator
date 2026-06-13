"""Path traversal scanner - probes file/path parameters for sensitive file reads."""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_FILE_PARAMS = {"path", "file", "filename", "filepath", "template", "include", "download", "document"}
_PAYLOADS = ["../../.env", "../../../../etc/passwd"]
_MAX_ENDPOINTS = 12
_ENV_RE = re.compile(r"(?m)^[A-Z0-9_]{3,}=.+")
_PASSWD_RE = re.compile(r"(?m)^root:x:0:0:")


class Scanner(BaseScanner):
    """Tests file/path parameters for traversal-based sensitive file disclosure."""

    name = "path_traversal_check"
    category = "Access Control"
    stages = ["pre-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        target = config.target
        backend_url = getattr(config, "backend_url", None)
        backend_url = backend_url if isinstance(backend_url, str) and backend_url else None
        origin = frontend_origin(config)

        seen: set[str] = set()
        for url, param, inventory_evidence in _file_candidates(
            listeners.get("api_inventory"), network, target, backend_url,
        ):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            parsed = urlparse(url)
            key = f"{parsed.netloc}{parsed.path}:{param}"
            if key in seen:
                continue
            seen.add(key)

            for payload in _PAYLOADS:
                probe_frontend_url = _replace_param(url, param, payload)
                probe_url = rewrite_to_backend_url(probe_frontend_url, config)
                status, body = _fetch(probe_url, origin=origin)
                if status != 200:
                    continue
                sensitive = _detect_sensitive_file(body)
                if sensitive is None:
                    continue
                file_type, proof_quality = sensitive

                desc = (
                    f"The endpoint `{probe_url}` returned `{file_type}` file signatures when the "
                    f"`{param}` parameter was replaced with a traversal payload. "
                    "Attackers can use path traversal to read local configuration files, secrets, "
                    "or operating-system files that should never be web-accessible."
                )
                findings.append(self.new_finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Path traversal file read via `{param}` parameter",
                    description=desc,
                    evidence={
                        "endpoint": probe_url,
                        "test_performed": "path_traversal_sensitive_file_probe",
                        "injection_point": f"query_param:{param}",
                        "payload_used": payload,
                        "sensitive_file_type": file_type,
                        "request": {"method": "GET", "url": probe_url, "headers": {"Origin": origin} if origin else {}},
                        "response": {"status": status, "body_excerpt": truncate(body, 240)},
                        "expected_response": "Reject traversal sequences or resolve paths inside an allowlisted directory",
                        "proof_quality": proof_quality,
                        "network_events": [],
                        **inventory_evidence,
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Path traversal file read via `{param}` parameter",
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        page=probe_url,
                        category=self.category,
                        description=desc,
                        evidence_summary=f"GET {probe_url} -> sensitive {file_type} signature in response",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{param}` parameter is used to resolve files without safe path controls.\n\n"
                        "**How to fix:** Do not pass user-controlled paths directly to file APIs. "
                        "Map user-visible file ids to server-side records, normalize resolved paths, "
                        "and enforce that the final path stays inside an allowlisted base directory. "
                        "Reject `..`, encoded slashes, absolute paths, and null bytes.\n\n"
                        "**Verify the fix:** Re-run path_traversal_check; traversal payloads should return 400/403/404."
                    ),
                    category=self.category,
                    page=probe_url,
                ))
                return findings

        return findings


def _discover_file_params(network: Any, target: str, backend_url: str | None = None) -> list[tuple[str, str]]:
    discovered: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for req in network.get_requests():
        if getattr(req, "method", "GET") != "GET":
            continue
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        parsed = urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            if param.lower() not in _FILE_PARAMS:
                continue
            key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", param)
            if key in seen:
                continue
            seen.add(key)
            discovered.append((url, param))
    return discovered


def _file_candidates(
    inventory: Any,
    network: Any,
    target: str,
    backend_url: str | None = None,
) -> list[tuple[str, str, dict[str, Any]]]:
    candidates: list[tuple[str, str, dict[str, Any]]] = []
    seen: set[tuple[str, str]] = set()

    for candidate in _inventory_file_params(inventory, target, backend_url):
        url, param, _evidence = candidate
        parsed = urlparse(url)
        key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", param)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)

    for url, param in _discover_file_params(network, target, backend_url):
        parsed = urlparse(url)
        key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", param)
        if key in seen:
            continue
        seen.add(key)
        candidates.append((url, param, {}))

    return candidates


def _inventory_file_params(
    inventory: Any,
    target: str,
    backend_url: str | None = None,
) -> list[tuple[str, str, dict[str, Any]]]:
    if inventory is None:
        return []

    candidates: list[tuple[str, str, dict[str, Any]]] = []
    for endpoint in getattr(inventory, "endpoints", []):
        method = str(getattr(endpoint, "method", "")).upper()
        url = getattr(endpoint, "url", "")
        risk_tags = {str(tag).lower() for tag in getattr(endpoint, "risk_tags", [])}
        if method != "GET" or "file" not in risk_tags:
            continue
        if not isinstance(url, str) or not _is_same_app_url(url, target, backend_url):
            continue

        for parameter in getattr(endpoint, "parameters", []):
            param = str(getattr(parameter, "name", ""))
            location = str(getattr(parameter, "location", "")).lower()
            if location != "query" or param.lower() not in _FILE_PARAMS:
                continue
            candidates.append((url, param, _inventory_evidence(endpoint, method, [param])))

    return candidates


def _inventory_evidence(endpoint: Any, method: str, params: list[str]) -> dict[str, Any]:
    return {
        "inventory_source": ",".join(getattr(endpoint, "sources", [])),
        "inventory_confidence": getattr(endpoint, "confidence", "") or "",
        "inventory_endpoint": f"{method} {getattr(endpoint, 'normalized_path', getattr(endpoint, 'path', ''))}",
        "inventory_parameters_used": params,
    }


def _is_same_app_url(url: str, target: str, backend_url: str | None = None) -> bool:
    parsed = urlparse(url)
    if any(parsed.path.endswith(ext) for ext in _STATIC_EXTS):
        return False
    if any(frag in parsed.path for frag in _SKIP_FRAGMENTS):
        return False
    allowed = {urlparse(target).netloc}
    if backend_url:
        allowed.add(urlparse(backend_url).netloc)
    return parsed.netloc in allowed


def _replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def _fetch(url: str, origin: str | None = None, timeout: int = 5) -> tuple[int | None, str]:
    headers = {"User-Agent": "vibe-iterator/path-traversal-check"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1024).decode("utf-8", errors="replace")
    except Exception:
        return None, ""


def _detect_sensitive_file(body: str) -> tuple[str, str] | None:
    if not body:
        return None
    lowered = body.lstrip().lower()
    if lowered.startswith("<!doctype") or lowered.startswith("<html"):
        return None
    if _PASSWD_RE.search(body):
        return "passwd", "passwd_file_disclosed_via_traversal"
    if _ENV_RE.search(body) and any(key in body for key in ("DATABASE_URL=", "SECRET_KEY=", "API_KEY=", "TOKEN=")):
        return "env", "env_file_disclosed_via_traversal"
    return None
