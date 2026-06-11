# tests/test_engine/test_discover_result_serialization.py
"""Tests for discovered_surface field in ScanResult and _result_dict serialization."""
from __future__ import annotations

from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory
from vibe_iterator.engine.runner import ScanResult
from vibe_iterator.history import serialize_result as _result_dict


def _base_result(**overrides) -> ScanResult:
    defaults = dict(
        scan_id="abc123", stage="pre-deploy", target="http://localhost:3000",
        status="completed", started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:01:00Z",
        findings=[], scanner_results=[], finding_marks=[],
        score=100, score_grade="A", duration_seconds=5.0,
        pages_crawled=[], requests_captured={"total": 0, "GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0},
        stack_detected="custom", stack_detection_source="auto-detect",
        second_account_used=False, scanner_overrides_applied=None,
        discovered_surface=None,
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


def test_discovered_surface_none_by_default():
    r = _base_result()
    assert r.discovered_surface is None


def test_result_dict_includes_discovered_surface_none():
    r = _base_result()
    d = _result_dict(r)
    assert "discovered_surface" in d
    assert d["discovered_surface"] is None


def test_result_dict_serializes_discovery_result():
    from vibe_iterator.engine.discover_runner import DiscoveryResult
    ds = DiscoveryResult(
        pages=["/", "/about"],
        api_endpoints=["GET /api/users"],
        discovered_at="2026-01-01T00:00:00Z",
    )
    r = _base_result(stage="discover", discovered_surface=ds)
    d = _result_dict(r)
    assert d["discovered_surface"]["pages"] == ["/", "/about"]
    assert d["discovered_surface"]["api_endpoints"] == ["GET /api/users"]
    assert d["discovered_surface"]["discovered_at"] == "2026-01-01T00:00:00Z"


def test_result_dict_serializes_discovered_surface_api_inventory():
    from vibe_iterator.engine.discover_runner import DiscoveryResult
    inventory = ApiInventory(
        generated_at="2026-01-01T00:00:00Z",
        mode="auto",
        resolved_mode="safe",
        target="https://example.test",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.test/api/users",
                origin="https://example.test",
                path="/api/users",
                normalized_path="/api/users",
                status_codes=[200],
                content_types=["application/json"],
                auth_observed=True,
                sources=["network:https://example.test/api/users"],
                risk_tags=["admin"],
            ),
        ],
        summary={"endpoints": 1, "auth_observed": 1},
        warnings=["safe mode"],
    )
    ds = DiscoveryResult(
        pages=["/"],
        api_endpoints=["GET /api/users"],
        discovered_at="2026-01-01T00:00:00Z",
        api_inventory=inventory,
    )
    r = _base_result(stage="discover", discovered_surface=ds)

    d = _result_dict(r)

    api_inventory = d["discovered_surface"]["api_inventory"]
    assert api_inventory["target"] == "https://example.test"
    assert api_inventory["summary"] == {"endpoints": 1, "auth_observed": 1}
    assert api_inventory["endpoints"][0]["method"] == "GET"
    assert api_inventory["endpoints"][0]["auth_observed"] is True
