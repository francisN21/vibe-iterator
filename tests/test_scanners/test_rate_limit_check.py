"""Unit tests for rate_limit_check scanner — all HTTP mocked at function level."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vibe_iterator.scanners.rate_limit_check import Scanner
from vibe_iterator.scanners.base import Severity


def _make_config(deep_scan: bool = False) -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.stack.backend = "custom"
    cfg.rate_limit_deep_scan = deep_scan
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
    def _side_effect(url):
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
