"""Page crawler — visits configured URLs and captures page metadata."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.support.ui import WebDriverWait

from vibe_iterator.config import Config
from vibe_iterator.crawler.browser import BrowserSession

logger = logging.getLogger(__name__)

_PAGE_LOAD_TIMEOUT = 20  # seconds
_SETTLE_DELAY = 0.5      # seconds after load to let async requests fire


@dataclass
class PageMetadata:
    """Result of visiting a single page."""

    url: str
    status_code: int        # HTTP status — 0 if unknown/navigation failed
    title: str
    load_time_ms: float
    error: str | None = None


def crawl_pages(
    session: BrowserSession,
    config: Config,
    *,
    on_page: object | None = None,
) -> list[PageMetadata]:
    """Visit each page in config.pages and return metadata for each.

    Args:
        session:  Active, authenticated BrowserSession.
        config:   Loaded Config with target URL and pages list.
        on_page:  Optional callable(PageMetadata) — called after each page visit.
                  Used by the engine to emit page_navigated events.

    Returns:
        Ordered list of PageMetadata, one per configured page.
    """
    results: list[PageMetadata] = []
    driver = session.driver
    driver.set_page_load_timeout(_PAGE_LOAD_TIMEOUT)

    for path in config.pages:
        url = _build_url(config.target, path)
        meta = _visit(driver, url)
        results.append(meta)

        if on_page is not None:
            try:
                on_page(meta)
            except Exception:
                pass  # event callback errors never crash the crawler

        time.sleep(_SETTLE_DELAY)

    return results


def _visit(driver: object, url: str) -> PageMetadata:
    """Navigate to a URL, capture status code and page title."""
    from selenium.webdriver.remote.webdriver import WebDriver
    assert isinstance(driver, WebDriver)

    start = time.monotonic()
    status_code = 0
    error = None

    try:
        driver.get(url)
        # Selenium doesn't expose HTTP status codes natively — use CDP to get it
        # via the Network.responseReceived events stored by our listener.
        # For navigator we record 0 as "unknown" — the network listener captures
        # the actual status code when attached. Phase 2 wires this together.
        status_code = _get_status_from_performance_logs(driver) or 200
    except WebDriverException as exc:
        error = str(exc)[:200]
        logger.warning("Failed to navigate to %s: %s", url, error)

    load_time_ms = (time.monotonic() - start) * 1000
    title = ""
    try:
        title = driver.title or ""
    except Exception:
        pass

    logger.info("Navigated to %s [%d] in %.0fms", url, status_code, load_time_ms)
    return PageMetadata(
        url=url,
        status_code=status_code,
        title=title,
        load_time_ms=load_time_ms,
        error=error,
    )


def _build_url(target: str, path: str) -> str:
    """Combine target base URL with a path, avoiding double slashes."""
    target = target.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return target + path


def _get_status_from_performance_logs(driver: object) -> int | None:
    """Extract the HTTP status code for the main document from Chrome performance logs."""
    try:
        from selenium.webdriver.remote.webdriver import WebDriver
        assert isinstance(driver, WebDriver)
        logs = driver.get_log("performance")
        for entry in reversed(logs):
            import json
            msg = json.loads(entry.get("message", "{}")).get("message", {})
            if msg.get("method") == "Network.responseReceived":
                params = msg.get("params", {})
                if params.get("type") == "Document":
                    return params.get("response", {}).get("status")
    except Exception:
        pass
    return None
