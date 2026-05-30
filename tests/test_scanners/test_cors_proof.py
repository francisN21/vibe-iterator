"""CORS scanner proof tests — run against the vulnerable fixture app (real HTTP, no Selenium)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.cors_check import Scanner


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.stack.backend = "custom"
    return cfg


def _make_req(url: str) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = "GET"
    req.response_headers = {"content-type": "application/json"}
    return req


def _run(vuln_app, paths: list[str]) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = MagicMock()
    net.get_requests.return_value = [_make_req(vuln_app.base_url + p) for p in paths]
    return scanner.run(session=None, listeners={"network": net}, config=config)


# --------------------------------------------------------------------------- #
# Wildcard CORS — /api/data                                                    #
# --------------------------------------------------------------------------- #

def test_wildcard_cors_detected(vuln_app) -> None:
    findings = _run(vuln_app, ["/api/data"])
    wildcard = [f for f in findings if "wildcard" in f.title.lower()]
    assert len(wildcard) >= 1
    assert wildcard[0].severity == Severity.LOW


# --------------------------------------------------------------------------- #
# Reflected origin — /api/user                                                 #
# --------------------------------------------------------------------------- #

def test_reflected_origin_detected(vuln_app) -> None:
    findings = _run(vuln_app, ["/api/user"])
    reflected = [f for f in findings if "reflected" in f.title.lower()]
    assert len(reflected) >= 1
    assert reflected[0].severity == Severity.HIGH


# --------------------------------------------------------------------------- #
# Preflight reflects origin with credentials — /api/user                      #
# --------------------------------------------------------------------------- #

def test_preflight_reflected_origin_with_credentials(vuln_app) -> None:
    findings = _run(vuln_app, ["/api/user"])
    preflight = [f for f in findings if "preflight" in f.title.lower()]
    assert len(preflight) >= 1
    assert preflight[0].severity == Severity.HIGH


# --------------------------------------------------------------------------- #
# Clean endpoint — no CORS issues                                              #
# --------------------------------------------------------------------------- #

def test_protected_endpoint_no_cors_finding(vuln_app) -> None:
    findings = _run(vuln_app, ["/api/protected"])
    # /api/protected returns no CORS headers at all — no finding expected
    cors_findings = [f for f in findings if "cors" in f.title.lower()]
    assert cors_findings == []


# --------------------------------------------------------------------------- #
# Fallback to base_url when no requests captured                               #
# --------------------------------------------------------------------------- #

def test_scanner_uses_base_url_fallback(vuln_app) -> None:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url + "/api/data")
    net = MagicMock()
    net.get_requests.return_value = []
    findings = scanner.run(session=None, listeners={"network": net}, config=config)
    # /api/data has wildcard CORS so scanner should find it even with empty requests list
    wildcard = [f for f in findings if "wildcard" in f.title.lower()]
    assert len(wildcard) >= 1
