# tests/test_spider/test_dom_crawler.py
"""Tests for dom_crawler.py — mocks Selenium driver, no real browser."""
from __future__ import annotations
from unittest.mock import MagicMock, patch
from vibe_iterator.spider.dom_crawler import crawl_dom, _to_path


def _mock_session(pages: dict[str, list[str]]) -> MagicMock:
    """Build a mock BrowserSession where each page URL maps to hrefs returned.

    pages = {"http://localhost:3000/": ["http://localhost:3000/about"], ...}
    """
    visited_urls: list[str] = []

    def _get(url: str) -> None:
        visited_urls.append(url)

    def _find_elements(by, tag):
        if not visited_urls:
            return []
        last_url = visited_urls[-1]
        hrefs = pages.get(last_url, [])
        elements = []
        for href in hrefs:
            el = MagicMock()
            el.get_attribute.return_value = href
            elements.append(el)
        return elements

    driver = MagicMock()
    driver.get.side_effect = _get
    driver.find_elements.side_effect = _find_elements

    session = MagicMock()
    session.driver = driver
    return session


BASE = "http://localhost:3000"


def test_crawl_visits_seed():
    session = _mock_session({f"{BASE}/": []})
    result = crawl_dom(session, ["/"], BASE)
    assert "/" in result


def test_crawl_follows_links():
    session = _mock_session({
        f"{BASE}/": [f"{BASE}/about", f"{BASE}/contact"],
        f"{BASE}/about": [],
        f"{BASE}/contact": [],
    })
    result = crawl_dom(session, ["/"], BASE, max_pages=10)
    assert "/about" in result
    assert "/contact" in result


def test_max_pages_respected():
    pages = {f"{BASE}/": [f"{BASE}/p{i}" for i in range(10)]}
    for i in range(10):
        pages[f"{BASE}/p{i}"] = []
    session = _mock_session(pages)
    result = crawl_dom(session, ["/"], BASE, max_pages=3)
    assert len(result) <= 3


def test_external_links_not_followed():
    session = _mock_session({
        f"{BASE}/": ["https://example.com/page", f"{BASE}/local"],
        f"{BASE}/local": [],
    })
    result = crawl_dom(session, ["/"], BASE)
    assert "/local" in result
    assert not any("example.com" in p for p in result)


def test_mailto_skipped():
    assert _to_path("mailto:foo@bar.com", BASE) is None


def test_javascript_href_skipped():
    assert _to_path("javascript:void(0)", BASE) is None


def test_same_origin_absolute_href():
    assert _to_path(f"{BASE}/about", BASE) == "/about"


def test_relative_href():
    assert _to_path("/about", BASE) == "/about"


def test_depth_limit_prevents_deep_follow():
    # Depth=0 → visit seed, follow links to depth 1 only, stop before depth 2
    session = _mock_session({
        f"{BASE}/": [f"{BASE}/level1"],
        f"{BASE}/level1": [f"{BASE}/level2"],
        f"{BASE}/level2": [f"{BASE}/level3"],
        f"{BASE}/level3": [],
    })
    result = crawl_dom(session, ["/"], BASE, max_pages=10, max_depth=1)
    assert "/" in result
    assert "/level1" in result
    assert "/level2" not in result
