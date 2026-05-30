"""CDP Network listener — captures all request/response pairs via Chrome performance log.

Selenium 4.20+ removed add_cdp_listener. We use the performance log polling API
instead: driver.get_log("performance") returns a ring-buffered stream of CDP events
that is consumed on each call. Call flush() or get_requests() after page navigations
to drain the buffer before Chrome evicts old entries.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
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
        listener.flush()                  # drain performance log after each page
        requests = listener.get_requests()
        listener.detach()
    """

    def __init__(self) -> None:
        self._requests: dict[str, NetworkRequest] = {}
        self._lock = threading.Lock()
        self._session: Any | None = None

    def attach(self, session: Any) -> None:
        """Register the session. Network.enable is called in browser.launch()."""
        from vibe_iterator.crawler.browser import BrowserSession
        assert isinstance(session, BrowserSession)
        self._session = session

    def detach(self) -> None:
        """Flush remaining events and release the session reference."""
        if self._session is not None:
            self.flush()
        self._session = None

    def flush(self) -> None:
        """Drain Chrome's performance log and populate the request store.

        Chrome's performance log is a ring buffer consumed on each get_log() call.
        Call this after every page navigation to avoid losing events.
        """
        if self._session is None:
            return
        driver = self._session.driver
        try:
            raw_logs = driver.get_log("performance")
        except Exception as exc:
            logger.debug("performance log unavailable: %s", exc)
            return
        self.process_raw_logs(raw_logs)

    def process_raw_logs(self, raw_logs: list) -> None:
        """Process pre-fetched performance log entries.

        Used by the navigator to share a single drain of the ring buffer so that
        both status-code extraction and network event capture see the same entries.
        """
        for entry in raw_logs:
            try:
                msg = json.loads(entry["message"])["message"]
            except (KeyError, json.JSONDecodeError):
                continue
            method = msg.get("method", "")
            params = msg.get("params", {})
            if method == "Network.requestWillBeSent":
                self._on_request(params)
            elif method == "Network.responseReceived":
                self._on_response(params)
            elif method == "Network.loadingFinished":
                self._on_loading_finished(params)

    def get_requests(self) -> list[NetworkRequest]:
        """Flush, then return a snapshot of all captured requests ordered by timestamp."""
        self.flush()
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
    # CDP event handlers                                                   #
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
            if len(body) > 50_000:
                body = body[:50_000] + "\n[truncated]"
            with self._lock:
                if request_id in self._requests:
                    self._requests[request_id].response_body = body
        except Exception as exc:
            logger.debug("Could not fetch body for %s: %s", request_id, exc)
