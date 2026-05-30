# tests/test_spider/test_endpoint_harvester.py
"""Tests for endpoint_harvester.py — pure data transform, no I/O."""
from __future__ import annotations

from unittest.mock import MagicMock

from vibe_iterator.listeners.network import NetworkRequest
from vibe_iterator.spider.endpoint_harvester import harvest_endpoints


def _req(url: str, method: str = "GET") -> NetworkRequest:
    return NetworkRequest(
        request_id="x", method=method, url=url,
        headers={}, post_data=None, timestamp=0.0,
    )


def _net(reqs: list) -> MagicMock:
    m = MagicMock()
    m.get_requests.return_value = reqs
    return m


def test_api_path_returned():
    result = harvest_endpoints(_net([_req("http://localhost/api/v1/users")]))
    assert "GET /api/v1/users" in result


def test_uuid_normalized():
    url = "http://localhost/api/users/123e4567-e89b-12d3-a456-426614174000"
    result = harvest_endpoints(_net([_req(url)]))
    assert "GET /api/users/{id}" in result


def test_integer_id_normalized_and_deduped():
    result = harvest_endpoints(_net([
        _req("http://localhost/api/items/42"),
        _req("http://localhost/api/items/99"),
    ]))
    assert result.count("GET /api/items/{id}") == 1


def test_non_api_path_skipped():
    result = harvest_endpoints(_net([_req("http://localhost/static/app.js")]))
    assert result == []


def test_post_method_preserved():
    result = harvest_endpoints(_net([_req("http://localhost/api/auth/login", method="POST")]))
    assert "POST /api/auth/login" in result


def test_graphql_detected():
    result = harvest_endpoints(_net([_req("http://localhost/graphql", method="POST")]))
    assert any("/graphql" in e for e in result)


def test_rest_resource_pattern_detected():
    result = harvest_endpoints(_net([_req("http://localhost/users/42")]))
    assert "GET /users/{id}" in result
