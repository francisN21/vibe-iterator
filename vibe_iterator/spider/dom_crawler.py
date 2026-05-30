# vibe_iterator/spider/dom_crawler.py
"""BFS DOM crawler — follows <a href> links within the same origin."""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Callable
from urllib.parse import urlparse

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By

logger = logging.getLogger(__name__)

_PAGE_LOAD_TIMEOUT = 15  # seconds
_SETTLE_DELAY = 0.3      # seconds after navigation to let async requests fire


def crawl_dom(
    session: Any,
    seeds: list[str],
    base_url: str,
    max_pages: int = 30,
    max_depth: int = 3,
    on_page: Callable[[str, int], None] | None = None,
) -> list[str]:
    """BFS DOM crawl following <a href> links within the same origin.

    Args:
        session:   BrowserSession with a .driver attribute.
        seeds:     Initial URL paths to visit (e.g. ["/", "/login"]).
        base_url:  Origin to restrict links to (e.g. "http://localhost:3000").
        max_pages: Stop after visiting this many unique pages.
        max_depth: Do not follow links discovered deeper than this level.
        on_page:   Optional callable(url, depth) called after each page visit.
                   Used by discover_runner to run js_extractor per page.

    Returns:
        Ordered list of visited paths (not full URLs).
    """
    base = base_url.rstrip("/")
    driver = session.driver
    driver.set_page_load_timeout(_PAGE_LOAD_TIMEOUT)

    visited: set[str] = set()
    ordered: list[str] = []
    queue: deque[tuple[str, int]] = deque()

    for seed in seeds:
        path = _to_path(seed, base)
        if path and path not in visited:
            visited.add(path)
            queue.append((path, 0))

    while queue and len(ordered) < max_pages:
        path, depth = queue.popleft()
        url = base + path

        try:
            driver.get(url)
            time.sleep(_SETTLE_DELAY)
        except WebDriverException as exc:
            logger.debug("dom_crawler: failed to navigate to %s: %s", url, exc)
            continue

        ordered.append(path)

        if on_page is not None:
            try:
                on_page(url, depth)
            except Exception:
                pass

        if depth >= max_depth:
            continue

        try:
            elements = driver.find_elements(By.TAG_NAME, "a")
            for el in elements:
                href = _safe_attr(el, "href")
                if not href:
                    continue
                link_path = _to_path(href, base)
                if link_path and link_path not in visited:
                    visited.add(link_path)
                    queue.append((link_path, depth + 1))
        except Exception as exc:
            logger.debug("dom_crawler: link extraction failed on %s: %s", url, exc)

    return ordered


def _to_path(href: str, base: str) -> str | None:
    """Convert an href to a same-origin path, or None if external/non-navigable."""
    href = href.strip()
    if any(href.startswith(s) for s in ("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    try:
        parsed_base = urlparse(base)
        parsed = urlparse(href)
        if not parsed.netloc:
            # Relative path — strip query and fragment
            path = parsed.path.split("?")[0].split("#")[0]
            return path or "/"
        if parsed.netloc != parsed_base.netloc:
            return None
        path = parsed.path.split("?")[0].split("#")[0]
        return path or "/"
    except Exception:
        return None


def _safe_attr(el: Any, attr: str) -> str | None:
    try:
        return el.get_attribute(attr)
    except Exception:
        return None
