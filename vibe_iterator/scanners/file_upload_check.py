"""Generic file upload scanner - probes dangerous accepted uploads."""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import add_frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_UPLOAD_PATH_HINTS = {"upload", "uploads", "avatar", "attachment", "attachments", "media", "file", "files"}
_MAX_ENDPOINTS = 10
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_SUCCESS_KEYS = {"accepted", "stored", "uploaded", "saved", "success", "ok"}
_NEGATIVE_KEYS = {"preview", "dry_run", "scan_only", "validated"}


@dataclass(frozen=True)
class UploadProbe:
    name: str
    proof_quality: str
    severity: Severity
    filename: str
    content_type: str
    content: bytes
    description: str


_PROBES = [
    UploadProbe(
        name="Executable extension",
        proof_quality="executable_extension_upload_accepted",
        severity=Severity.HIGH,
        filename="vibe-proof.php",
        content_type="text/plain",
        content=b"<?php echo 'vibe-proof'; ?>",
        description="an executable server-side extension",
    ),
    UploadProbe(
        name="Dangerous MIME",
        proof_quality="dangerous_mime_upload_accepted",
        severity=Severity.HIGH,
        filename="vibe-proof.txt",
        content_type="application/x-php",
        content=b"<?php echo 'vibe-proof'; ?>",
        description="a dangerous executable MIME type",
    ),
    UploadProbe(
        name="SVG/HTML polyglot",
        proof_quality="polyglot_svg_html_upload_accepted",
        severity=Severity.MEDIUM,
        filename="vibe-polyglot.svg",
        content_type="image/svg+xml",
        content=b"<svg xmlns='http://www.w3.org/2000/svg'><script>console.log('vibe-proof')</script></svg>",
        description="an SVG/HTML polyglot payload with script-capable content",
    ),
    UploadProbe(
        name="EICAR test string",
        proof_quality="eicar_test_string_upload_accepted",
        severity=Severity.MEDIUM,
        filename="eicar-vibe-proof.txt",
        content_type="text/plain",
        content=_EICAR,
        description="the harmless EICAR antivirus test string",
    ),
]


class Scanner(BaseScanner):
    """Tests upload endpoints for dangerous file acceptance."""

    name = "file_upload_check"
    category = "File Upload"
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

        seen: set[str] = set()
        for req in _discover_upload_endpoints(network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            endpoint = rewrite_to_backend_url(str(req.url), config)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            headers = add_frontend_origin({}, config)
            for probe in _PROBES:
                status, response_headers, response_body = _send_upload_probe(
                    endpoint,
                    probe.filename,
                    probe.content_type,
                    probe.content,
                    headers=headers,
                )
                acceptance = _has_upload_acceptance(response_body)
                if status not in {200, 201, 202} or acceptance is None:
                    continue
                accepted_path, accepted_value = acceptance
                findings.append(self._finding(
                    endpoint,
                    probe,
                    headers,
                    status,
                    response_headers,
                    response_body,
                    accepted_path,
                    accepted_value,
                    stack,
                ))

        return findings

    def _finding(
        self,
        endpoint: str,
        probe: UploadProbe,
        headers: dict[str, str],
        status: int | None,
        response_headers: dict[str, str],
        response_body: str,
        accepted_path: str,
        accepted_value: Any,
        stack: str,
    ) -> Finding:
        desc = (
            f"The upload endpoint `{endpoint}` accepted {probe.description}. "
            "Attackers can use weak upload validation to store executable content, browser-executable polyglots, "
            "or malware-like content that should be blocked before persistence."
        )
        return self.new_finding(
            scanner=self.name,
            severity=probe.severity,
            title=f"{probe.name} upload accepted",
            description=desc,
            evidence={
                "endpoint": endpoint,
                "test_performed": probe.proof_quality,
                "upload_evidence": {
                    "filename": probe.filename,
                    "content_type": probe.content_type,
                    "size": len(probe.content),
                },
                "request": {"method": "POST", "url": endpoint, "headers": headers},
                "response": {"status": status, "headers": dict(response_headers), "body_excerpt": truncate(response_body, 240)},
                "acceptance_evidence": {"json_path": accepted_path, "value": accepted_value},
                "expected_response": "Reject dangerous extensions, MIME types, polyglots, and malware test strings before storing uploads",
                "proof_quality": probe.proof_quality,
                "network_events": [],
            },
            llm_prompt=self.build_llm_prompt(
                title=f"{probe.name} upload accepted",
                severity=probe.severity,
                scanner=self.name,
                page=endpoint,
                category=self.category,
                description=desc,
                evidence_summary=f"POST {endpoint} accepted {probe.filename} ({probe.content_type}) with {accepted_path}=true",
                stack=stack,
            ),
            remediation=(
                "**What to fix:** The upload endpoint accepts dangerous file content or metadata.\n\n"
                "**How to fix:** Enforce an allowlist of extensions and MIME types, verify magic bytes/content signatures, "
                "strip active content from images where possible, scan uploads with AV, store files outside executable paths, "
                "and serve user uploads from a separate origin with safe content headers.\n\n"
                "**Verify the fix:** Re-run file_upload_check; dangerous probes should return 400/403 and must not be stored."
            ),
            category=self.category,
            page=endpoint,
        )


def _discover_upload_endpoints(network: Any, target: str, backend_url: str | None = None) -> list[Any]:
    discovered: list[Any] = []
    seen: set[str] = set()
    for req in network.get_requests():
        if str(getattr(req, "method", "GET")).upper() != "POST":
            continue
        url = str(getattr(req, "url", ""))
        if not _is_same_app_url(url, target, backend_url):
            continue
        parsed = urlparse(url)
        if not _has_upload_path_hint(parsed.path):
            continue
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if endpoint in seen:
            continue
        seen.add(endpoint)
        discovered.append(req)
    return discovered


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


def _has_upload_path_hint(path: str) -> bool:
    segments = {segment.lower() for segment in path.split("/") if segment}
    return bool(segments & _UPLOAD_PATH_HINTS)


def _send_upload_probe(
    url: str,
    filename: str,
    content_type: str,
    content: bytes,
    headers: dict[str, str] | None = None,
    timeout: int = 8,
) -> tuple[int | None, dict[str, str], str]:
    multipart_type, body = _build_multipart(filename, content_type, content)
    request_headers = dict(headers or {})
    request_headers["Content-Type"] = multipart_type
    req = urllib.request.Request(url, data=body, headers=request_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _normalize_headers(resp.headers), resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, _normalize_headers(exc.headers), exc.read(2048).decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""


def _build_multipart(filename: str, content_type: str, content: bytes) -> tuple[str, bytes]:
    boundary = f"----vibeiterator{secrets.token_hex(8)}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return f"multipart/form-data; boundary={boundary}", body


def _normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}


def _has_upload_acceptance(body: str) -> tuple[str, Any] | None:
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    return _find_acceptance(parsed)


def _find_acceptance(value: Any, path: str = "") -> tuple[str, Any] | None:
    if isinstance(value, dict):
        if any(str(key).lower() in _NEGATIVE_KEYS and child is True for key, child in value.items()):
            return None
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if lowered in _SUCCESS_KEYS and child is True:
                return child_path, child
            nested = _find_acceptance(child, child_path)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for idx, child in enumerate(value[:5]):
            nested = _find_acceptance(child, f"{path}[{idx}]")
            if nested is not None:
                return nested
    return None
