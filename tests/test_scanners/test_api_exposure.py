"""Tests for API exposure scanner — unauth access, headers, rate limiting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory
from vibe_iterator.scanners.api_exposure import Scanner
from vibe_iterator.scanners.base import Severity

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _make_config(target: str = "https://example.com", backend_url: str | None = None) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.backend_url = backend_url
    cfg.stack.backend = "supabase"
    return cfg


def _make_req(
    url: str = "https://example.com/api/data",
    method: str = "GET",
    response_headers: dict | None = None,
    auth_header: bool = False,
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.response_headers = response_headers or {"content-type": "application/json"}
    req.status_code = 200
    req.headers = {"Authorization": "Bearer token123"} if auth_header else {}
    return req


def _run(
    requests: list,
    fetch_result=None,
    target: str = "https://example.com",
    backend_url: str | None = None,
) -> list:
    scanner = Scanner()
    config = _make_config(target, backend_url=backend_url)
    net = MagicMock()
    net.get_requests.return_value = requests

    if fetch_result is not None:
        with patch(
            "vibe_iterator.scanners.api_exposure._fetch_without_auth",
            return_value=fetch_result,
        ):
            return scanner.run(session=None, listeners={"network": net}, config=config)
    return scanner.run(session=None, listeners={"network": net}, config=config)


# --------------------------------------------------------------------------- #
# Unauthenticated access                                                        #
# --------------------------------------------------------------------------- #

def test_unauth_access_200_is_high() -> None:
    req = _make_req(url="https://example.com/api/protected", auth_header=True)
    findings = _run([req], fetch_result=(200, {"content-type": "application/json"}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert len(unauth) == 1
    assert unauth[0].severity == Severity.HIGH
    assert unauth[0].evidence["proof_quality"] == "protected_path_replayed_without_auth"


def test_public_endpoint_with_incidental_auth_header_is_not_unauth_access() -> None:
    req = _make_req(url="https://example.com/api/products", auth_header=True)
    findings = _run([req], fetch_result=(200, {"content-type": "application/json"}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


def test_unauth_access_on_sensitive_path_is_critical() -> None:
    req = _make_req(url="https://example.com/api/admin", auth_header=True)
    findings = _run([req], fetch_result=(200, {"content-type": "application/json"}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert len(unauth) == 1
    assert unauth[0].severity == Severity.CRITICAL
    assert unauth[0].evidence["proof_quality"] == "protected_path_replayed_without_auth"


def test_unauth_access_401_no_finding() -> None:
    req = _make_req(auth_header=True)
    findings = _run([req], fetch_result=(401, {}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


def test_unauth_check_skipped_when_no_auth_header() -> None:
    req = _make_req(auth_header=False)
    findings = _run([req], fetch_result=(200, {}))
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


def test_unauth_fetch_failure_no_finding() -> None:
    req = _make_req(auth_header=True)
    findings = _run([req], fetch_result=None)
    unauth = [f for f in findings if "unauthenticated" in f.title.lower()]
    assert unauth == []


def test_backend_url_routes_unauth_probe_from_frontend_proxy() -> None:
    req = _make_req(
        url="https://app.example.com/api/admin",
        response_headers={
            "content-type": "application/json",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        },
        auth_header=True,
    )
    probes: list[tuple[str, str | None]] = []

    def fake_fetch(url, method="GET", body=None, origin=None, timeout=5):
        probes.append((url, origin))
        return 401, {}

    with patch("vibe_iterator.scanners.api_exposure._fetch_without_auth", side_effect=fake_fetch):
        findings = _run([req], target="https://app.example.com", backend_url="https://api.example.com")

    assert [f for f in findings if "unauthenticated" in f.title.lower()] == []
    assert probes == [("https://api.example.com/api/admin", "https://app.example.com")]


def test_backend_url_direct_api_origin_is_discovered_for_unauth_probe() -> None:
    req = _make_req(
        url="https://api.example.com/api/admin",
        response_headers={
            "content-type": "application/json",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        },
        auth_header=True,
    )
    probes: list[tuple[str, str | None]] = []

    def fake_fetch(url, method="GET", body=None, origin=None, timeout=5):
        probes.append((url, origin))
        return 401, {}

    with patch("vibe_iterator.scanners.api_exposure._fetch_without_auth", side_effect=fake_fetch):
        findings = _run([req], target="https://app.example.com", backend_url="https://api.example.com")

    assert [f for f in findings if "unauthenticated" in f.title.lower()] == []
    assert probes == [("https://api.example.com/api/admin", "https://app.example.com")]


def test_api_exposure_uses_inventory_auth_endpoint(monkeypatch) -> None:
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/account",
                origin="https://example.com",
                path="/api/account",
                normalized_path="/api/account",
                auth_observed=True,
                sources=["network"],
                risk_tags=["auth"],
                confidence="confirmed",
            )
        ],
        summary={"endpoints": 1},
        warnings=[],
    )

    monkeypatch.setattr(
        "vibe_iterator.scanners.api_exposure._fetch_without_auth",
        lambda *args, **kwargs: (200, {}),
    )
    net = MagicMock()
    net.get_requests.return_value = []

    findings = Scanner().run(
        session=None,
        listeners={"network": net, "api_inventory": inv},
        config=_make_config(),
    )

    assert any(f.evidence.get("inventory_endpoint") == "GET /api/account" for f in findings)


def test_api_exposure_uses_inventory_auth_risk_tag_as_proof(monkeypatch) -> None:
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/orders",
                origin="https://example.com",
                path="/api/orders",
                normalized_path="/api/orders",
                sources=["route_wordlist"],
                risk_tags=["auth"],
                confidence="confirmed",
            )
        ],
    )

    monkeypatch.setattr(
        "vibe_iterator.scanners.api_exposure._fetch_without_auth",
        lambda *args, **kwargs: (200, {}),
    )
    net = MagicMock()
    net.get_requests.return_value = []

    findings = Scanner().run(
        session=None,
        listeners={"network": net, "api_inventory": inv},
        config=_make_config(),
    )

    unauth = [f for f in findings if f.evidence.get("inventory_endpoint") == "GET /api/orders"]
    assert len(unauth) == 1
    assert unauth[0].evidence["proof_quality"] == "inventory_auth_endpoint_replayed_without_auth"


# --------------------------------------------------------------------------- #
# Security headers (passive)                                                   #
# --------------------------------------------------------------------------- #

def test_missing_hsts_is_medium() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    with patch("vibe_iterator.scanners.api_exposure._fetch_headers", return_value=(200, {})):
        findings = _run([req])
    hsts = [f for f in findings if "strict-transport-security" in f.title.lower()]
    assert len(hsts) == 1
    assert hsts[0].severity == Severity.MEDIUM
    assert hsts[0].evidence["proof_quality"] == "direct_header_revalidation_missing"
    assert hsts[0].evidence["confidence"] == "confirmed"


def test_missing_x_frame_options_is_low() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    with patch("vibe_iterator.scanners.api_exposure._fetch_headers", return_value=(200, {})):
        findings = _run([req])
    frame = [f for f in findings if "x-frame-options" in f.title.lower()]
    assert len(frame) == 1
    assert frame[0].severity == Severity.LOW


def test_missing_x_content_type_options_is_low() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    with patch("vibe_iterator.scanners.api_exposure._fetch_headers", return_value=(200, {})):
        findings = _run([req])
    ct = [f for f in findings if "x-content-type-options" in f.title.lower()]
    assert len(ct) == 1
    assert ct[0].severity == Severity.LOW


def test_direct_revalidation_suppresses_stale_missing_header_observation() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})
    live_headers = {
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    }

    with patch("vibe_iterator.scanners.api_exposure._fetch_headers", return_value=(200, live_headers)):
        findings = _run([req])

    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


def test_inconclusive_header_revalidation_uses_sanity_check_message() -> None:
    req = _make_req(response_headers={"content-type": "text/html"})

    with patch("vibe_iterator.scanners.api_exposure._fetch_headers", return_value=None):
        findings = _run([req])

    sanity = [f for f in findings if f.title.startswith("Sanity check:")]
    assert sanity
    assert all(f.severity == Severity.INFO for f in sanity)
    assert all(f.evidence["confidence"] == "needs_review" for f in sanity)


def test_present_security_headers_no_header_findings() -> None:
    req = _make_req(response_headers={
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    })
    findings = _run([req])
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


def test_response_headers_none_skipped() -> None:
    req = _make_req()
    req.response_headers = None
    findings = _run([req])
    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


def test_header_findings_are_deduped() -> None:
    reqs = [_make_req(response_headers={"content-type": "text/html"}) for _ in range(3)]
    findings = _run(reqs)
    hsts = [f for f in findings if "strict-transport-security" in f.title.lower()]
    assert len(hsts) == 1


def test_hashed_embed_view_path_produces_no_security_header_findings() -> None:
    req = _make_req(
        url="https://example.com/8615121666b064d1/view",
        response_headers={"content-type": "text/html"},
    )
    req.response_mime_type = "text/html"

    findings = _run([req])

    header_findings = [f for f in findings if "missing security header" in f.title.lower()]
    assert header_findings == []


# --------------------------------------------------------------------------- #
# Rate limiting on auth endpoints                                               #
# --------------------------------------------------------------------------- #

def test_auth_endpoint_repeated_post_without_429_is_medium() -> None:
    req = _make_req(
        url="https://example.com/api/login",
        method="POST",
        response_headers={"content-type": "application/json"},
    )
    findings = _run([req], fetch_result=(401, {}))
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert len(rl) == 1
    assert rl[0].severity == Severity.MEDIUM
    assert rl[0].evidence["proof_quality"] == "repeated_auth_post_without_429"
    assert rl[0].evidence["confidence"] == "confirmed"


def test_missing_rate_limit_headers_alone_do_not_create_vulnerability() -> None:
    req = _make_req(
        url="https://example.com/api/login",
        method="POST",
        response_headers={"content-type": "application/json"},
    )
    findings = _run([req], fetch_result=(429, {}))
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_get_auth_session_missing_rate_headers_is_not_bruteforce_finding() -> None:
    req = _make_req(
        url="https://example.com/api/auth/me",
        method="GET",
        response_headers={"content-type": "application/json"},
    )
    findings = _run([req])
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_auth_endpoint_with_rate_limit_header_no_finding() -> None:
    req = _make_req(
        url="https://example.com/api/login",
        response_headers={
            "content-type": "application/json",
            "x-ratelimit-limit": "60",
        },
    )
    # fetch_result=(429, {}) silences the active probe; passive check also passes → no findings
    findings = _run([req], fetch_result=(429, {}))
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_non_auth_endpoint_no_rate_limit_finding() -> None:
    req = _make_req(
        url="https://example.com/api/products",
        response_headers={"content-type": "application/json"},
    )
    findings = _run([req])
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_retry_after_header_satisfies_rate_limit() -> None:
    req = _make_req(
        url="https://example.com/auth/token",
        response_headers={
            "content-type": "application/json",
            "retry-after": "60",
        },
    )
    # fetch_result=(429, {}) silences active probe; passive check passes (Retry-After present)
    findings = _run([req], fetch_result=(429, {}))
    rl = [f for f in findings if "rate limiting" in f.title.lower()]
    assert rl == []


def test_backend_url_routes_active_rate_limit_probe_from_frontend_proxy() -> None:
    req = _make_req(
        url="https://app.example.com/api/login",
        method="POST",
        response_headers={
            "content-type": "application/json",
            "retry-after": "60",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        },
    )
    probes: list[tuple[str, str | None]] = []

    def fake_fetch(url, method="GET", body=None, origin=None, timeout=5):
        probes.append((url, origin))
        return 429, {}

    with patch("vibe_iterator.scanners.api_exposure._fetch_without_auth", side_effect=fake_fetch):
        findings = _run([req], target="https://app.example.com", backend_url="https://api.example.com")

    assert [f for f in findings if "rate limiting" in f.title.lower()] == []
    assert probes == [("https://api.example.com/api/login", "https://app.example.com")]
