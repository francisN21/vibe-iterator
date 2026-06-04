"""Tests for XSS scanner — headers, CSP, DOM sinks."""

from __future__ import annotations

from unittest.mock import MagicMock

from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.xss_check import Scanner

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _make_config(target: str = "https://example.com", backend_url: str | None = None) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.backend_url = backend_url
    cfg.stack.backend = "nextjs"
    return cfg


def _make_req(url: str, response_headers: dict) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.response_headers = response_headers
    req.status_code = 200
    return req


def _run(
    requests: list,
    session=None,
    target: str = "https://example.com",
    backend_url: str | None = None,
) -> list:
    scanner = Scanner()
    config = _make_config(target, backend_url=backend_url)
    net = MagicMock()
    net.get_requests.return_value = requests
    return scanner.run(session=session, listeners={"network": net}, config=config)


# --------------------------------------------------------------------------- #
# Missing security headers                                                      #
# --------------------------------------------------------------------------- #

def test_missing_x_content_type_options_is_low() -> None:
    req = _make_req("https://example.com/api/data", {"content-type": "application/json"})
    findings = _run([req])
    titles = [f.title for f in findings]
    assert any("x-content-type-options" in t.lower() for t in titles)
    header_findings = [f for f in findings if "x-content-type-options" in f.title.lower()]
    assert header_findings[0].severity == Severity.LOW


def test_missing_x_frame_options_is_low() -> None:
    req = _make_req("https://example.com/", {"content-type": "text/html"})
    findings = _run([req])
    frame_findings = [f for f in findings if "x-frame-options" in f.title.lower()]
    assert len(frame_findings) >= 1
    assert frame_findings[0].severity == Severity.LOW


def test_present_headers_no_header_finding() -> None:
    req = _make_req("https://example.com/", {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    })
    findings = _run([req])
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


# --------------------------------------------------------------------------- #
# CSP checks                                                                    #
# --------------------------------------------------------------------------- #

def test_missing_csp_is_medium() -> None:
    req = _make_req("https://example.com/", {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    })
    findings = _run([req])
    csp_findings = [f for f in findings if "content security policy" in f.title.lower()]
    assert len(csp_findings) == 1
    assert csp_findings[0].severity == Severity.MEDIUM


def test_weak_csp_unsafe_inline_is_medium() -> None:
    req = _make_req("https://example.com/", {
        "content-security-policy": "script-src 'self' 'unsafe-inline'",
    })
    findings = _run([req])
    weak_findings = [f for f in findings if "unsafe-inline" in f.title.lower()]
    assert len(weak_findings) >= 1
    assert weak_findings[0].severity == Severity.MEDIUM


def test_weak_csp_unsafe_eval_is_medium() -> None:
    req = _make_req("https://example.com/", {
        "content-security-policy": "script-src 'self' 'unsafe-eval'",
    })
    findings = _run([req])
    weak_findings = [f for f in findings if "unsafe-eval" in f.title.lower()]
    assert len(weak_findings) >= 1
    assert weak_findings[0].severity == Severity.MEDIUM


def test_weak_csp_wildcard_script_src_is_medium() -> None:
    req = _make_req("https://example.com/", {
        "content-security-policy": "script-src *",
    })
    findings = _run([req])
    weak_findings = [f for f in findings if "wildcard" in f.title.lower()]
    assert len(weak_findings) >= 1


def test_no_csp_finding_when_strong_csp_present() -> None:
    req = _make_req("https://example.com/", {
        "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'",
    })
    findings = _run([req])
    csp_missing = [f for f in findings if "not set" in f.title.lower()]
    assert csp_missing == []


# --------------------------------------------------------------------------- #
# URL filtering — cross-origin requests ignored                                 #
# --------------------------------------------------------------------------- #

def test_cross_origin_requests_produce_no_header_findings() -> None:
    req = _make_req("https://other-domain.com/resource", {"content-type": "text/html"})
    findings = _run([req], target="https://example.com")
    # Cross-origin requests are filtered for header checks; no per-header findings
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    weak_csp = [f for f in findings if "weak" in f.title.lower()]
    assert header_findings == []
    assert weak_csp == []


def test_hashed_static_script_path_produces_no_header_or_csp_findings() -> None:
    req = _make_req(
        "https://example.com/8615121666b064d1/script.js",
        {"content-type": "application/javascript"},
    )

    findings = _run([req], target="https://example.com")

    assert [
        f for f in findings
        if "missing security header" in f.title.lower()
        or "content security policy" in f.title.lower()
    ] == []


# --------------------------------------------------------------------------- #
# DOM sinks (active)                                                            #
# --------------------------------------------------------------------------- #

def test_dom_sinks_detected_returns_medium() -> None:
    session = MagicMock()
    session.evaluate.return_value = '["innerHTML assignment", "eval usage"]'
    session.current_url.return_value = "https://example.com/dashboard"

    req = _make_req("https://example.com/", {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    })
    findings = _run([req], session=session)
    dom_findings = [f for f in findings if "dom xss" in f.title.lower()]
    assert len(dom_findings) == 1
    assert dom_findings[0].severity == Severity.MEDIUM


def test_no_dom_sinks_no_finding() -> None:
    session = MagicMock()
    session.evaluate.return_value = "[]"

    req = _make_req("https://example.com/", {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    })
    findings = _run([req], session=session)
    dom_findings = [f for f in findings if "dom xss" in f.title.lower()]
    assert dom_findings == []


def test_dom_check_skipped_when_session_is_none() -> None:
    req = _make_req("https://example.com/", {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    })
    findings = _run([req], session=None)
    dom_findings = [f for f in findings if "dom xss" in f.title.lower()]
    assert dom_findings == []


def test_dom_check_handles_session_exception_gracefully() -> None:
    session = MagicMock()
    session.evaluate.side_effect = RuntimeError("evaluate failed")

    req = _make_req("https://example.com/", {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    })
    findings = _run([req], session=session)
    dom_findings = [f for f in findings if "dom xss" in f.title.lower()]
    assert dom_findings == []


class _FakeReflectResponse:
    headers = {"Content-Type": "text/html; charset=utf-8"}
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        return b"<html><body>no reflection here</body></html>"


def test_backend_url_routes_reflected_xss_probe_with_frontend_origin(monkeypatch) -> None:
    req = _make_req(
        "https://app.example.com/search?q=test",
        {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "content-type": "text/html",
        },
    )
    requests_seen: list[tuple[str, dict]] = []

    def fake_urlopen(http_req, timeout=4, context=None):
        requests_seen.append((http_req.full_url, dict(http_req.header_items())))
        return _FakeReflectResponse()

    monkeypatch.setattr("vibe_iterator.scanners.xss_check.urllib.request.urlopen", fake_urlopen)

    findings = _run([req], target="https://app.example.com", backend_url="https://api.example.com")

    assert [f for f in findings if "reflected xss" in f.title.lower()] == []
    assert requests_seen
    assert all(url.startswith("https://api.example.com/search?") for url, _ in requests_seen)
    assert all(headers["Origin"] == "https://app.example.com" for _, headers in requests_seen)


def test_backend_url_direct_api_origin_is_discovered_for_reflected_xss(monkeypatch) -> None:
    req = _make_req(
        "https://api.example.com/search?q=test",
        {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "content-type": "text/html",
        },
    )
    requests_seen: list[tuple[str, dict]] = []

    def fake_urlopen(http_req, timeout=4, context=None):
        requests_seen.append((http_req.full_url, dict(http_req.header_items())))
        return _FakeReflectResponse()

    monkeypatch.setattr("vibe_iterator.scanners.xss_check.urllib.request.urlopen", fake_urlopen)

    findings = _run([req], target="https://app.example.com", backend_url="https://api.example.com")

    assert [f for f in findings if "reflected xss" in f.title.lower()] == []
    assert requests_seen
    assert all(url.startswith("https://api.example.com/search?") for url, _ in requests_seen)
    assert all(headers["Origin"] == "https://app.example.com" for _, headers in requests_seen)
