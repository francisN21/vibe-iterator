"""Tests for evidence collection helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from vibe_iterator.crawler.browser import BrowserSession
from vibe_iterator.evidence.collector import EvidenceCollector


def test_capture_screenshot_returns_data_uri() -> None:
    driver = MagicMock()
    driver.get_screenshot_as_png.return_value = b"png"
    collector = EvidenceCollector(BrowserSession(driver=driver))

    assert collector.capture_screenshot() == "data:image/png;base64,cG5n"


def test_capture_screenshot_returns_empty_on_failure() -> None:
    driver = MagicMock()
    driver.get_screenshot_as_png.side_effect = RuntimeError("boom")
    collector = EvidenceCollector(BrowserSession(driver=driver))

    assert collector.capture_screenshot() == ""


def test_network_window_limits_and_filters_requests() -> None:
    network = MagicMock()
    network.get_requests_for_url.return_value = [
        SimpleNamespace(
            method="GET",
            url="http://localhost/api/users",
            headers={"Authorization": "Bearer x"},
            post_data=None,
            status_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body="x" * 600,
        )
    ]

    rows = EvidenceCollector.network_window(network, url_fragment="/api", limit=1)

    assert rows == [{
        "method": "GET",
        "url": "http://localhost/api/users",
        "request_headers": {"Authorization": "Bearer x"},
        "post_data": None,
        "status_code": 200,
        "response_headers": {"Content-Type": "application/json"},
        "response_body_excerpt": "x" * 500,
    }]


def test_request_evidence_truncates_response_body() -> None:
    req = SimpleNamespace(
        method="POST",
        url="http://localhost/api/items",
        headers={str(i): str(i) for i in range(20)},
        post_data='{"name":"x"}',
        status_code=201,
        response_headers={str(i): str(i) for i in range(20)},
        response_body="y" * 501,
    )

    evidence = EvidenceCollector.request_evidence(req)

    assert len(evidence["request"]["headers"]) == 15
    assert len(evidence["response"]["headers"]) == 15
    assert evidence["response"]["body_truncated"] is True
    assert len(evidence["response"]["body_excerpt"]) == 500
