"""Unit tests for rate_limit_check scanner — all HTTP mocked at function level."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.rate_limit_check import Scanner, _find_active_path


def _make_config(deep_scan: bool = False, backend_url: str | None = None) -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.stack.backend = "custom"
    cfg.rate_limit_deep_scan = deep_scan
    cfg.backend_url = backend_url
    return cfg


def _make_network(post_urls: list[str] | None = None) -> MagicMock:
    net = MagicMock()
    reqs = []
    for url in (post_urls or []):
        r = MagicMock()
        r.method = "POST"
        r.url = url
        reqs.append(r)
    net.get_requests.return_value = reqs
    return net


def _run(
    *,
    active_path: str | None = "/api/auth/login",
    burst_responses: list[tuple] | None = None,
    deep_scan: bool = False,
    network_post_urls: list[str] | None = None,
) -> list:
    """
    active_path: what _find_active_path returns (None = endpoint absent).
    burst_responses: list of (status, headers_dict, body_str) returned by _post_full,
                     one per burst attempt. Repeated as needed up to 10.
    """
    scanner = Scanner()
    config = _make_config(deep_scan=deep_scan)
    network = _make_network(network_post_urls)

    if burst_responses is None:
        burst_responses = [(401, {}, '{"error": "invalid"}')]

    # Cycle responses if fewer than 10 provided
    def _side_effect(url, origin=None):
        idx = len(call_log)
        call_log.append(url)
        r = burst_responses[min(idx, len(burst_responses) - 1)]
        return r

    call_log: list[str] = []

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value=active_path), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_side_effect):
        return scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )


# ── Finding A ────────────────────────────────────────────────────────────────

def test_no_rate_limit_finding_a_emitted():
    """10 × 401 with no shift → Finding A, MEDIUM."""
    findings = _run(burst_responses=[(401, {}, '{"error": "x"}')
                                     ] * 10)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert "No rate limiting" in f.title
    assert "Login" in f.title


def test_finding_a_evidence_structure():
    """Finding A evidence dict has required keys."""
    findings = _run(burst_responses=[(401, {}, '{}') ] * 10)
    ev = findings[0].evidence
    assert ev["attempts_sent"] == 10
    assert ev["response_codes_seen"] == [401] * 10
    assert "expected_behavior" in ev


def test_all_endpoints_404_no_findings():
    """If all path variants 404, no findings emitted."""
    findings = _run(active_path=None)
    assert findings == []


def test_find_active_path_skips_generic_auth_catchall() -> None:
    """A generic 401 unauthorized catch-all is not enough route proof."""
    with patch(
        "vibe_iterator.scanners.rate_limit_check._post_full",
        return_value=(401, {}, '{"error": "unauthorized"}'),
    ):
        assert _find_active_path("https://example.com", ["/api/auth/signup"], "https://app.example.com") is None


def test_find_active_path_accepts_auth_specific_invalid_credentials() -> None:
    """Auth-specific response text is enough to treat the route as active."""
    with patch(
        "vibe_iterator.scanners.rate_limit_check._post_full",
        return_value=(401, {}, '{"error": "invalid credentials"}'),
    ):
        assert (
            _find_active_path("https://example.com", ["/api/auth/login"], "https://app.example.com")
            == "/api/auth/login"
        )


# ── Finding B ────────────────────────────────────────────────────────────────

def test_lockout_detected_code_shift():
    """Attempts 1-4 return 401, attempt 5 returns 403 → Finding B, LOW."""
    responses = [(401, {}, '{"error": "invalid"}')
                 ] * 4 + [(403, {}, '{"error": "forbidden"}')]
    findings = _run(burst_responses=responses)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.LOW
    assert "lockout" in f.title.lower()
    assert "DoS" in f.title


def test_lockout_detected_body_signal():
    """All 401 but body contains 'locked' at attempt 6 → Finding B."""
    responses = [(401, {}, '{"error": "invalid"}')
                 ] * 5 + [(401, {}, '{"error": "account locked"}')]
    findings = _run(burst_responses=responses)
    assert len(findings) == 1
    b_findings = [f for f in findings if f.severity == Severity.LOW]
    assert len(b_findings) == 1
    assert b_findings[0].evidence["lockout_detected_at_attempt"] == 6


def test_lockout_evidence_structure():
    """Finding B evidence has all required keys."""
    responses = [(401, {}, '{"error": "x"}') ] * 4 + [(403, {}, '{"error": "locked"}')]
    findings = _run(burst_responses=responses)
    ev = findings[0].evidence
    assert "lockout_detected_at_attempt" in ev
    assert "code_before" in ev
    assert "code_after" in ev
    assert ev["code_before"] == 401
    assert ev["code_after"] == 403


# ── Finding C ────────────────────────────────────────────────────────────────

def test_rate_limited_with_retry_after_no_finding():
    """429 with Retry-After present → no findings at all."""
    responses = [(401, {}, '{"error": "x"}')
                 ] * 5 + [(429, {"retry-after": "60"}, '{"error": "rate limited"}')]
    findings = _run(burst_responses=responses)
    assert findings == []


def test_rate_limited_missing_retry_after_finding_c():
    """429 present but no Retry-After header → Finding C, INFO."""
    responses = [(401, {}, '{"error": "x"}')
                 ] * 5 + [(429, {}, '{"error": "rate limited"}')]
    findings = _run(burst_responses=responses)
    assert len(findings) == 1
    c_findings = [f for f in findings if "Retry-After" in f.title]
    assert len(c_findings) == 1
    assert c_findings[0].severity == Severity.INFO


def test_finding_c_evidence_structure():
    """Finding C evidence has response_code and endpoint keys."""
    responses = [(401, {}, '{}') ] * 5 + [(429, {}, '{}')]
    findings = _run(burst_responses=responses)
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["response_code"] == 429
    assert "endpoint" in ev
    assert "expected_behavior" in ev


# ── Deep scan ─────────────────────────────────────────────────────────────────

def test_deep_scan_probes_network_endpoints():
    """With deep_scan=True, POST endpoints from network listener are probed."""
    post_urls = [
        "http://localhost:3000/api/custom/action",
        "http://localhost:3000/api/other/submit",
    ]
    # active_path=None skips standard endpoints; deep scan picks up network ones
    probed: list[str] = []

    def _full_side(url, origin=None):
        probed.append(url)
        return (401, {}, '{"error": "x"}')

    scanner = Scanner()
    config = _make_config(deep_scan=True)
    network = _make_network(post_urls)

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value=None), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        findings = scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    # Each deep-scan endpoint probed (up to 10 burst attempts each)
    from urllib.parse import urlparse
    probed_paths_set = {urlparse(u).path for u in probed}
    assert "/api/custom/action" in probed_paths_set
    assert "/api/other/submit" in probed_paths_set
    # Both unprotected → 2 findings
    assert len(findings) == 2


def test_deep_scan_skips_already_covered_endpoints():
    """Deep scan does not double-probe an endpoint from the standard list."""
    post_urls = [
        "http://localhost:3000/api/auth/login",  # overlaps standard list
        "http://localhost:3000/api/custom/new",
    ]
    probed: list[str] = []

    def _full_side(url, origin=None):
        probed.append(url)
        return (401, {}, '{}')

    scanner = Scanner()
    config = _make_config(deep_scan=True)
    network = _make_network(post_urls)

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value="/api/auth/login"), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    login_probes = [p for p in probed if "/api/auth/login" in p]
    new_probes = [p for p in probed if "/api/custom/new" in p]
    # login probed exactly once (from standard list, 10 burst attempts)
    assert len(login_probes) == 10
    # custom/new also probed
    assert len(new_probes) == 10


def test_deep_scan_caps_at_20_endpoints():
    """Deep scan probes at most 20 additional endpoints beyond the standard list."""
    from urllib.parse import urlparse
    post_urls = [
        f"http://localhost:3000/api/ep/{i}" for i in range(25)
    ]
    probed_paths: set[str] = set()

    def _full_side(url, origin=None):
        probed_paths.add(urlparse(url).path)
        return (401, {}, '{}')

    scanner = Scanner()
    config = _make_config(deep_scan=True)
    network = _make_network(post_urls)

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               return_value=None), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    assert len(probed_paths) == 20


def test_backend_url_routes_probes_with_frontend_origin():
    """When backend_url is configured, probes hit it while Origin remains target."""
    scanner = Scanner()
    config = _make_config(backend_url="http://localhost:4001")
    network = _make_network()
    active_calls: list[tuple[str, str]] = []
    burst_calls: list[tuple[str, str]] = []

    def _active_side(base, variants, origin):
        active_calls.append((base, origin))
        return "/api/auth/login"

    def _full_side(url, origin):
        burst_calls.append((url, origin))
        return (429, {"retry-after": "60"}, '{"error": "rate limited"}')

    with patch("vibe_iterator.scanners.rate_limit_check._find_active_path",
               side_effect=_active_side), \
         patch("vibe_iterator.scanners.rate_limit_check._post_full",
               side_effect=_full_side):
        findings = scanner.run(
            session=None,
            listeners={"network": network},
            config=config,
        )

    assert findings == []
    assert active_calls[0] == ("http://localhost:4001", "http://localhost:3000")
    assert burst_calls[0] == (
        "http://localhost:4001/api/auth/login",
        "http://localhost:3000",
    )
