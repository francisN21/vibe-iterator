"""Evidence collection — screenshots, network logs, and payload/response pairs."""

from __future__ import annotations

import base64
import logging
from typing import Any

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Captures screenshots and network evidence for a Finding.

    One collector instance is typically created per Finding, or shared within
    a scanner's run() for a group of related checks.
    """

    def __init__(self, session: Any) -> None:
        from vibe_iterator.crawler.browser import BrowserSession
        assert isinstance(session, BrowserSession)
        self._session = session

    def capture_screenshot(self) -> str:
        """Take a full-page screenshot and return a base64 PNG data URI."""
        try:
            png_bytes = self._session.driver.get_screenshot_as_png()
            b64 = base64.b64encode(png_bytes).decode("ascii")
            return f"data:image/png;base64,{b64}"
        except Exception as exc:
            logger.debug("Screenshot failed (non-fatal): %s", exc)
            return ""

    def capture_element_screenshot(self, css_selector: str) -> str:
        """Screenshot a specific DOM element identified by CSS selector."""
        try:
            from selenium.webdriver.common.by import By
            element = self._session.driver.find_element(By.CSS_SELECTOR, css_selector)
            png_bytes = element.screenshot_as_png
            b64 = base64.b64encode(png_bytes).decode("ascii")
            return f"data:image/png;base64,{b64}"
        except Exception as exc:
            logger.debug("Element screenshot failed (non-fatal): %s", exc)
            return ""

    @staticmethod
    def network_window(
        network_listener: Any,
        *,
        url_fragment: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return a serializable snapshot of recent network events.

        Args:
            network_listener: NetworkListener instance.
            url_fragment:     If set, only return requests containing this string.
            limit:            Maximum number of events to include.
        """
        requests = (
            network_listener.get_requests_for_url(url_fragment)
            if url_fragment
            else network_listener.get_requests()
        )
        return [
            {
                "method": r.method,
                "url": r.url,
                "request_headers": dict(list((r.headers or {}).items())[:10]),
                "post_data": r.post_data,
                "status_code": r.status_code,
                "response_headers": dict(list((r.response_headers or {}).items())[:10]),
                "response_body_excerpt": (r.response_body or "")[:500],
            }
            for r in requests[-limit:]
        ]

    @staticmethod
    def request_evidence(request: Any) -> dict[str, Any]:
        """Convert a NetworkRequest to a structured evidence request/response dict."""
        return {
            "request": {
                "method": request.method,
                "url": request.url,
                "headers": dict(list((request.headers or {}).items())[:15]),
                "body": request.post_data,
            },
            "response": {
                "status": request.status_code,
                "headers": dict(list((request.response_headers or {}).items())[:15]),
                "body_excerpt": (request.response_body or "")[:500],
                "body_truncated": len(request.response_body or "") > 500,
            },
        }
