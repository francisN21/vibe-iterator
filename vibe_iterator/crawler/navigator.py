"""Page crawler — visits configured URLs and captures page metadata."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from selenium.common.exceptions import WebDriverException

from vibe_iterator.config import Config
from vibe_iterator.crawler.browser import BrowserSession

if TYPE_CHECKING:
    from vibe_iterator.listeners.network import NetworkListener

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
    network_listener: Any | None = None,
) -> list[PageMetadata]:
    """Visit each page in config.pages and return metadata for each.

    Args:
        session:          Active, authenticated BrowserSession.
        config:           Loaded Config with target URL and pages list.
        on_page:          Optional callable(PageMetadata) — called after each page visit.
                          Used by the engine to emit page_navigated events.
        network_listener: Optional NetworkListener — when provided, the performance log
                          is drained once per page and shared with the listener so both
                          status-code extraction and network capture see all events.

    Returns:
        Ordered list of PageMetadata, one per configured page.
    """
    results: list[PageMetadata] = []
    driver = session.driver
    driver.set_page_load_timeout(_PAGE_LOAD_TIMEOUT)

    for path in config.pages:
        url = _build_url(config.target, path)
        meta = _visit(driver, url, network_listener=network_listener)
        results.append(meta)

        if on_page is not None:
            try:
                on_page(meta)
            except Exception:
                pass  # event callback errors never crash the crawler

        time.sleep(_SETTLE_DELAY)

    return results


def _visit(driver: object, url: str, *, network_listener: Any | None = None) -> PageMetadata:
    """Navigate to a URL, capture status code and page title."""
    from selenium.webdriver.remote.webdriver import WebDriver
    assert isinstance(driver, WebDriver)

    start = time.monotonic()
    status_code = 0
    error = None

    try:
        driver.get(url)
        # Drain the performance log once. If a NetworkListener is attached, feed it
        # the same raw entries so both status-code extraction and request capture see
        # every CDP event — avoids double-draining the ring buffer.
        raw_logs = _drain_performance_log(driver)
        if network_listener is not None:
            try:
                network_listener.process_raw_logs(raw_logs)
            except Exception:
                pass
        status_code = _extract_status_from_raw_logs(raw_logs) or 200
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


def _drain_performance_log(driver: object) -> list:
    """Fetch and return all pending Chrome performance log entries."""
    try:
        from selenium.webdriver.remote.webdriver import WebDriver
        assert isinstance(driver, WebDriver)
        return driver.get_log("performance")
    except Exception:
        return []


def _extract_status_from_raw_logs(raw_logs: list) -> int | None:
    """Return the HTTP status code of the most recent Document response in raw_logs."""
    for entry in reversed(raw_logs):
        try:
            msg = json.loads(entry.get("message", "{}")).get("message", {})
        except (json.JSONDecodeError, AttributeError):
            continue
        if msg.get("method") == "Network.responseReceived":
            params = msg.get("params", {})
            if params.get("type") == "Document":
                return params.get("response", {}).get("status")
    return None
