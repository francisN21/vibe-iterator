"""Tests for the NetworkListener — uses mock CDP events, no live browser."""

from __future__ import annotations

import pytest

from vibe_iterator.listeners.network import NetworkListener, NetworkRequest


# ------------------------------------------------------------------ #
# Helpers to simulate CDP event delivery                             #
# ------------------------------------------------------------------ #

def _fire_request(listener: NetworkListener, request_id: str, method: str, url: str, post_data: str | None = None) -> None:
    listener._on_request({
        "requestId": request_id,
        "request": {
            "method": method,
            "url": url,
            "headers": {"User-Agent": "test"},
            "postData": post_data,
        },
        "timestamp": 1000.0,
    })


def _fire_response(listener: NetworkListener, request_id: str, status: int, headers: dict | None = None) -> None:
    listener._on_response({
        "requestId": request_id,
        "response": {
            "status": status,
            "headers": headers or {"Content-Type": "application/json"},
            "mimeType": "application/json",
        },
        "timestamp": 1001.0,
    })


# ------------------------------------------------------------------ #
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestNetworkListenerCapture:
    def test_captures_request(self) -> None:
        listener = NetworkListener()
        _fire_request(listener, "req1", "GET", "http://localhost:3000/api/users")

        requests = listener.get_requests()
        assert len(requests) == 1
        assert requests[0].url == "http://localhost:3000/api/users"
        assert requests[0].method == "GET"
        assert requests[0].request_id == "req1"

    def test_captures_post_data(self) -> None:
        listener = NetworkListener()
        _fire_request(listener, "req1", "POST", "http://localhost:3000/api/login", post_data='{"email":"a@b.com"}')

        assert listener.get_requests()[0].post_data == '{"email":"a@b.com"}'

    def test_associates_response_with_request(self) -> None:
        listener = NetworkListener()
        _fire_request(listener, "req1", "GET", "http://localhost:3000/api/data")
        _fire_response(listener, "req1", 200)

        req = listener.get_requests()[0]
        assert req.status_code == 200
        assert req.response_headers is not None

    def test_multiple_requests_ordered_by_timestamp(self) -> None:
        listener = NetworkListener()
        # Fire in timestamp order
        listener._on_request({"requestId": "a", "request": {"method": "GET", "url": "/a", "headers": {}}, "timestamp": 2.0})
        listener._on_request({"requestId": "b", "request": {"method": "GET", "url": "/b", "headers": {}}, "timestamp": 1.0})

        requests = listener.get_requests()
        assert requests[0].timestamp < requests[1].timestamp

    def test_response_for_unknown_request_is_ignored(self) -> None:
        listener = NetworkListener()
        _fire_response(listener, "nonexistent", 200)
        assert listener.get_requests() == []


class TestNetworkListenerFilter:
    def test_get_requests_for_url_filters_correctly(self) -> None:
        listener = NetworkListener()
        _fire_request(listener, "r1", "GET", "http://app.com/api/users")
        _fire_request(listener, "r2", "GET", "http://app.com/static/logo.png")
        _fire_request(listener, "r3", "POST", "http://app.com/api/login")

        api_requests = listener.get_requests_for_url("/api/")
        assert len(api_requests) == 2
        assert all("/api/" in r.url for r in api_requests)

    def test_summary_counts_by_method(self) -> None:
        listener = NetworkListener()
        _fire_request(listener, "r1", "GET", "/a")
        _fire_request(listener, "r2", "GET", "/b")
        _fire_request(listener, "r3", "POST", "/c")

        summary = listener.summary()
        assert summary["total"] == 3
        assert summary["GET"] == 2
        assert summary["POST"] == 1


class TestNetworkListenerClear:
    def test_clear_removes_all_requests(self) -> None:
        listener = NetworkListener()
        _fire_request(listener, "r1", "GET", "/a")
        _fire_request(listener, "r2", "GET", "/b")
        assert len(listener.get_requests()) == 2

        listener.clear()
        assert listener.get_requests() == []
