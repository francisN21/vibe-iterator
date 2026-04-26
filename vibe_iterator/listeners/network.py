"""CDP Network listener — captures all request/response pairs."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class NetworkRequest:
    """A captured HTTP request and its associated response (if received)."""

    request_id: str
    method: str
    url: str
    headers: dict[str, str]
    post_data: str | None
    timestamp: float

    # Populated when the response arrives
    status_code: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    response_mime_type: str | None = None
    response_timestamp: float | None = None


class NetworkListener:
    """Attaches to Chrome's CDP Network domain and records all traffic.

    Usage::

        listener = NetworkListener()
        listener.attach(session)          # call before crawling / scanning
        # ... page interactions ...
        requests = listener.get_requests()
        listener.detach()
    """

    def __init__(self) -> None:
        self._requests: dict[str, NetworkRequest] = {}
        self._lock = threading.Lock()
        self._session: Any | None = None

    def attach(self, session: Any) -> None:
        """Register CDP event handlers on the browser session."""
        from vibe_iterator.crawler.browser import BrowserSession
        assert isinstance(session, BrowserSession)
        self._session = session

        driver = session.driver

        # CDP Network.enable is called in browser.launch() — no need to call again.
        # We use Selenium's add_cdp_listener to subscribe to events.
        driver.add_cdp_listener("Network.requestWillBeSent", self._on_request)
        driver.add_cdp_listener("Network.responseReceived", self._on_response)
        driver.add_cdp_listener("Network.loadingFinished", self._on_loading_finished)

    def detach(self) -> None:
        """Remove CDP listeners. Called during cleanup."""
        if self._session is None:
            return
        try:
            driver = self._session.driver
            driver.remove_cdp_listener("Network.requestWillBeSent", self._on_request)
            driver.remove_cdp_listener("Network.responseReceived", self._on_response)
            driver.remove_cdp_listener("Network.loadingFinished", self._on_loading_finished)
        except Exception as exc:
            logger.debug("NetworkListener.detach error (non-fatal): %s", exc)
        finally:
            self._session = None

    def get_requests(self) -> list[NetworkRequest]:
        """Return a snapshot of all captured requests, ordered by timestamp."""
        with self._lock:
            return sorted(self._requests.values(), key=lambda r: r.timestamp)

    def get_requests_for_url(self, url_fragment: str) -> list[NetworkRequest]:
        """Return requests whose URL contains url_fragment."""
        return [r for r in self.get_requests() if url_fragment in r.url]

    def clear(self) -> None:
        """Discard all captured requests (e.g., between scanner runs)."""
        with self._lock:
            self._requests.clear()

    def summary(self) -> dict[str, int]:
        """Return request counts by HTTP method."""
        counts: dict[str, int] = {"total": 0, "GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0}
        for req in self.get_requests():
            counts["total"] += 1
            method = req.method.upper()
            if method in counts:
                counts[method] += 1
        return counts

    # ------------------------------------------------------------------ #
    # CDP event handlers (called on CDP event thread)                    #
    # ------------------------------------------------------------------ #

    def _on_request(self, params: dict) -> None:
        request_id = params.get("requestId", "")
        request = params.get("request", {})
        entry = NetworkRequest(
            request_id=request_id,
            method=request.get("method", "GET"),
            url=request.get("url", ""),
            headers=request.get("headers", {}),
            post_data=request.get("postData"),
            timestamp=params.get("timestamp", 0.0),
        )
        with self._lock:
            self._requests[request_id] = entry

    def _on_response(self, params: dict) -> None:
        request_id = params.get("requestId", "")
        response = params.get("response", {})
        with self._lock:
            entry = self._requests.get(request_id)
            if entry is None:
                return
            entry.status_code = response.get("status")
            entry.response_headers = response.get("headers", {})
            entry.response_mime_type = response.get("mimeType")
            entry.response_timestamp = params.get("timestamp")

    def _on_loading_finished(self, params: dict) -> None:
        """Fetch response body once the resource has fully loaded."""
        request_id = params.get("requestId", "")
        with self._lock:
            entry = self._requests.get(request_id)
            if entry is None:
                return

        if self._session is None:
            return

        try:
            result = self._session.execute_cdp(
                "Network.getResponseBody", {"requestId": request_id}
            )
            body = result.get("body", "")
            # Truncate very large bodies — scanners only need excerpts for evidence
            if len(body) > 50_000:
                body = body[:50_000] + "\n[truncated]"
            with self._lock:
                if request_id in self._requests:
                    self._requests[request_id].response_body = body
        except Exception as exc:
            logger.debug("Could not fetch body for %s: %s", request_id, exc)
