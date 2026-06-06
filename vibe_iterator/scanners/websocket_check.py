"""WebSocket scanner - probes handshake auth and Origin enforcement."""

from __future__ import annotations

import base64
import os
import socket
import ssl
import urllib.parse
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_AUTH_HEADERS = {"authorization", "cookie", "sec-websocket-protocol"}
_DROP_HEADERS = {"host", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version", "content-length"}
_MAX_ENDPOINTS = 10
_UNTRUSTED_ORIGIN = "https://evil.example"


class Scanner(BaseScanner):
    """Tests discovered WebSocket endpoints for unauthenticated and untrusted-Origin handshakes."""

    name = "websocket_check"
    category = "API Security"
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
        origin = target.rstrip("/") if isinstance(target, str) and target else None

        seen: set[str] = set()
        for url in _discover_websocket_targets(network, target, backend_url):
            if len(seen) >= _MAX_ENDPOINTS:
                break
            probe_url = _rewrite_ws_to_backend(url, config)
            if probe_url in seen:
                continue
            seen.add(probe_url)

            original = _headers_for_url(network, url)
            unauth_headers = _strip_auth_headers(original, origin=origin)
            status, response_headers = _websocket_handshake(probe_url, headers=unauth_headers)
            if status == 101:
                findings.append(self._finding(
                    probe_url,
                    "Unauthenticated WebSocket handshake accepted",
                    "unauthenticated_websocket_accepted",
                    Severity.HIGH,
                    unauth_headers,
                    status,
                    response_headers,
                    stack,
                    "The WebSocket endpoint accepted an upgrade after auth headers were removed.",
                ))

            origin_headers = _with_untrusted_origin(original)
            status, response_headers = _websocket_handshake(probe_url, headers=origin_headers)
            if status == 101:
                findings.append(self._finding(
                    probe_url,
                    "WebSocket handshake accepted untrusted Origin",
                    "untrusted_origin_websocket_accepted",
                    Severity.MEDIUM,
                    origin_headers,
                    status,
                    response_headers,
                    stack,
                    f"The WebSocket endpoint accepted an upgrade from `{_UNTRUSTED_ORIGIN}`.",
                ))

        return findings

    def _finding(
        self,
        endpoint: str,
        title: str,
        proof_quality: str,
        severity: Severity,
        headers: dict[str, str],
        status: int | None,
        response_headers: dict[str, str],
        stack: str,
        summary: str,
    ) -> Finding:
        desc = (
            f"{summary} Attackers can abuse weak WebSocket handshakes to open privileged realtime channels, "
            "bypass browser-origin trust boundaries, or receive events intended only for authenticated users."
        )
        return self.new_finding(
            scanner=self.name,
            severity=severity,
            title=title,
            description=desc,
            evidence={
                "endpoint": endpoint,
                "test_performed": proof_quality,
                "request": {"method": "GET", "url": endpoint, "headers": _redact(headers)},
                "response": {"status": status, "headers": dict(response_headers)},
                "expected_response": "Reject missing authentication and untrusted Origin WebSocket upgrades",
                "proof_quality": proof_quality,
                "network_events": [],
            },
            llm_prompt=self.build_llm_prompt(
                title=title,
                severity=severity,
                scanner=self.name,
                page=endpoint,
                category=self.category,
                description=desc,
                evidence_summary=f"WebSocket handshake to {endpoint} returned 101 with proof={proof_quality}",
                stack=stack,
            ),
            remediation=(
                "**What to fix:** The WebSocket handshake does not enforce authentication and/or trusted Origin checks.\n\n"
                "**How to fix:** Authenticate before accepting the upgrade, validate `Origin` against the app's trusted origins, "
                "bind realtime channels to the authenticated principal, and close unauthenticated sockets before subscribing them to events.\n\n"
                "**Verify the fix:** Re-run websocket_check; unauthenticated and untrusted-Origin handshakes should return 401/403."
            ),
            category=self.category,
            page=endpoint,
        )


def _discover_websocket_targets(network: Any, target: str, backend_url: str | None = None) -> list[str]:
    discovered: list[str] = []
    seen: set[str] = set()
    for req in network.get_requests():
        url = str(getattr(req, "url", ""))
        headers = dict(getattr(req, "headers", {}) or {})
        ws_url = _as_ws_url(url, headers)
        if not ws_url or not _is_same_app_ws_url(ws_url, target, backend_url):
            continue
        if ws_url in seen:
            continue
        seen.add(ws_url)
        discovered.append(ws_url)
    return discovered


def _as_ws_url(url: str, headers: dict[str, Any]) -> str | None:
    parsed = urlparse(url)
    if any(parsed.path.endswith(ext) for ext in _STATIC_EXTS):
        return None
    if any(frag in parsed.path for frag in _SKIP_FRAGMENTS):
        return None
    if parsed.scheme in {"ws", "wss"}:
        return url
    if str(headers.get("Upgrade", headers.get("upgrade", ""))).lower() == "websocket":
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return urllib.parse.urlunparse(parsed._replace(scheme=scheme))
    return None


def _is_same_app_ws_url(url: str, target: str, backend_url: str | None = None) -> bool:
    parsed = urlparse(url)
    allowed = {urlparse(target).netloc}
    if backend_url:
        allowed.add(urlparse(backend_url).netloc)
    return parsed.netloc in allowed


def _headers_for_url(network: Any, url: str) -> dict[str, str]:
    for req in network.get_requests():
        req_url = str(getattr(req, "url", ""))
        headers = dict(getattr(req, "headers", {}) or {})
        if _as_ws_url(req_url, headers) == url:
            return {str(k): str(v) for k, v in headers.items()}
    return {}


def _strip_auth_headers(headers: dict[str, Any], origin: str | None = None) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in _AUTH_HEADERS or lowered in _DROP_HEADERS or lowered == "origin":
            continue
        clean[str(key)] = str(value)
    if origin:
        clean["Origin"] = origin
    return clean


def _with_untrusted_origin(headers: dict[str, Any]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in _DROP_HEADERS or lowered == "origin":
            continue
        clean[str(key)] = str(value)
    clean["Origin"] = _UNTRUSTED_ORIGIN
    return clean


def _rewrite_ws_to_backend(url: str, config: Any) -> str:
    backend_url_raw = getattr(config, "backend_url", None)
    target_raw = getattr(config, "target", "")
    if not isinstance(backend_url_raw, str) or not isinstance(target_raw, str) or not backend_url_raw:
        return url
    parsed = urlparse(url)
    target = urlparse(target_raw)
    backend = urlparse(backend_url_raw)
    if parsed.netloc != target.netloc:
        return url
    scheme = "wss" if backend.scheme == "https" else "ws"
    return urllib.parse.urlunparse(parsed._replace(scheme=scheme, netloc=backend.netloc))


def _websocket_handshake(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 5,
) -> tuple[int | None, dict[str, str]]:
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        return None, {}
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_headers = {
        "Host": parsed.netloc,
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
    }
    request_headers.update(headers or {})
    raw = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in request_headers.items()) + "\r\n"

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if parsed.scheme == "wss":
                with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                    tls.sendall(raw.encode("ascii"))
                    response = tls.recv(4096).decode("iso-8859-1", errors="replace")
            else:
                sock.sendall(raw.encode("ascii"))
                response = sock.recv(4096).decode("iso-8859-1", errors="replace")
    except Exception:
        return None, {}
    return _parse_handshake_response(response)


def _parse_handshake_response(response: str) -> tuple[int | None, dict[str, str]]:
    lines = response.split("\r\n")
    if not lines:
        return None, {}
    parts = lines[0].split()
    try:
        status = int(parts[1])
    except Exception:
        status = None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status, headers


def _redact(headers: dict[str, str]) -> dict[str, str]:
    redacted = dict(headers)
    for key in list(redacted):
        if key.lower() in {"authorization", "cookie"}:
            redacted[key] = "<redacted>"
    return redacted
