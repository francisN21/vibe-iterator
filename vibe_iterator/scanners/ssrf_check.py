"""SSRF scanner - proves server-side URL fetches with a local callback."""

from __future__ import annotations

import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map"}
_SKIP_FRAGMENTS = ("/_next/", "/__next/", "/static/", "/assets/", "/favicon")
_SSRF_PARAMS = {
    "url", "uri", "target", "endpoint", "callback", "callback_url", "webhook",
    "webhook_url", "image", "image_url", "avatar", "avatar_url", "feed",
    "feed_url", "proxy", "remote", "resource",
}
_MAX_ENDPOINTS = 10
_CALLBACK_WAIT_SECONDS = 0.5


class Scanner(BaseScanner):
    """Tests URL-like parameters for server-side request forgery."""

    name = "ssrf_check"
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
        origin = frontend_origin(config)

        seen: set[str] = set()
        with _start_callback_server() as callback:
            for url, param in _discover_ssrf_params(network, target, backend_url):
                if len(seen) >= _MAX_ENDPOINTS:
                    break
                parsed = urlparse(url)
                key = f"{parsed.netloc}{parsed.path}:{param}"
                if key in seen:
                    continue
                seen.add(key)

                probe_frontend_url = _replace_param(url, param, callback.url)
                probe_url = rewrite_to_backend_url(probe_frontend_url, config)
                status, headers, body = _fetch_no_redirect(probe_url, origin=origin)
                if not callback.wait(_CALLBACK_WAIT_SECONDS):
                    continue

                desc = (
                    f"The endpoint `{probe_url}` fetched a scanner-controlled callback URL from the server side "
                    f"when the `{param}` parameter was replaced. Attackers can abuse SSRF to reach internal "
                    "services, cloud metadata endpoints, or private admin interfaces that are not exposed to browsers."
                )
                findings.append(self.new_finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title=f"SSRF via `{param}` URL parameter",
                    description=desc,
                    evidence={
                        "endpoint": probe_url,
                        "test_performed": "ssrf_local_callback_probe",
                        "injection_point": f"query_param:{param}",
                        "payload_used": callback.url,
                        "request": {"method": "GET", "url": probe_url, "headers": {"Origin": origin} if origin else {}},
                        "response": {
                            "status": status,
                            "headers": dict(headers),
                            "body_excerpt": truncate(body, 240),
                        },
                        "callback": {
                            "url": callback.url,
                            "received": True,
                            "received_path": callback.received_path,
                            "received_headers": callback.received_headers,
                        },
                        "expected_response": "Reject user-controlled server-side URLs or restrict them to an allowlist",
                        "proof_quality": "ssrf_callback_received",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"SSRF via `{param}` URL parameter",
                        severity=Severity.HIGH,
                        scanner=self.name,
                        page=probe_url,
                        category=self.category,
                        description=desc,
                        evidence_summary=f"GET {probe_url} caused a server-side request to {callback.url}",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{param}` parameter is accepted as a server-side fetch target.\n\n"
                        "**How to fix:** Avoid fetching arbitrary user-controlled URLs. If remote fetches are required, "
                        "use an explicit allowlist of schemes, hosts, and ports; block private, loopback, link-local, "
                        "and cloud metadata IP ranges after DNS resolution; disable redirects or re-validate every hop; "
                        "and enforce short timeouts and response-size limits.\n\n"
                        "**Verify the fix:** Re-run ssrf_check; the scanner callback should not receive any request."
                    ),
                    category=self.category,
                    page=probe_url,
                ))
                return findings

        return findings


def _discover_ssrf_params(network: Any, target: str, backend_url: str | None = None) -> list[tuple[str, str]]:
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
            if param.lower() not in _SSRF_PARAMS:
                continue
            key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", param)
            if key in seen:
                continue
            seen.add(key)
            discovered.append((url, param))
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


def _replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_no_redirect(
    url: str,
    origin: str | None = None,
    timeout: int = 5,
) -> tuple[int | None, dict[str, str], str]:
    headers = {"User-Agent": "vibe-iterator/ssrf-check"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, _normalize_headers(resp.headers), resp.read(2048).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, _normalize_headers(exc.headers), exc.read(1024).decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""


def _normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in dict(headers).items()}


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        server.received_path = self.path
        server.received_headers = dict(self.headers)
        server.event.set()
        body = b"vibe-iterator-ssrf-callback"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return None


class _CallbackServer:
    def __init__(self) -> None:
        token = f"vibe-ssrf-{uuid.uuid4().hex}"
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
        self._server.event = threading.Event()
        self._server.received_path = None
        self._server.received_headers = {}
        host, port = self._server.server_address
        self.url = f"http://{host}:{port}/{token}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def received(self) -> bool:
        return self._server.event.is_set()

    @property
    def received_path(self) -> str | None:
        return self._server.received_path

    @property
    def received_headers(self) -> dict[str, str]:
        return dict(self._server.received_headers)

    def wait(self, timeout: float = _CALLBACK_WAIT_SECONDS) -> bool:
        return self._server.event.wait(timeout)

    def __enter__(self) -> "_CallbackServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=1)


def _start_callback_server() -> _CallbackServer:
    return _CallbackServer()
