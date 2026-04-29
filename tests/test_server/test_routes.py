"""Tests for REST API routes — start scan, results, 409 guard, config, mark."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from vibe_iterator.engine.runner import ScanResult, ScannerResult
from vibe_iterator.scanners.base import Finding, Severity
from vibe_iterator.server.app import create_app


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _make_config(target: str = "http://localhost:3000") -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.test_email = "test@example.com"
    cfg.test_password = "pass"
    cfg.test_email_2 = None
    cfg.test_password_2 = None
    cfg.pages = ["/", "/dashboard"]
    cfg.port = 3001
    cfg.second_account_configured = False
    cfg.stack.backend = "supabase"
    cfg.stack.auth = "supabase-auth"
    cfg.stack.storage = "supabase"
    cfg.stack.detection_source = "manually-configured"
    cfg.scanners_for_stage.return_value = ["data_leakage", "auth_check"]
    cfg.stages = {
        "dev": ["data_leakage", "auth_check"],
        "pre-deploy": ["data_leakage", "auth_check"],
    }
    return cfg


def _make_scan_result(status: str = "completed") -> ScanResult:
    import uuid
    from datetime import datetime, timezone
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        stage="dev",
        target="http://localhost:3000",
        status=status,
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat() if status != "running" else None,
        findings=[],
        scanner_results=[
            ScannerResult(scanner_name="data_leakage", status="passed", findings_count=0, duration_seconds=1.2),
        ],
        finding_marks=[],
        score=100,
        score_grade="A",
        duration_seconds=3.5,
        pages_crawled=[{"url": "http://localhost:3000/", "status_code": 200}],
        requests_captured={"total": 12, "GET": 10, "POST": 2, "PUT": 0, "DELETE": 0, "PATCH": 0},
        stack_detected="supabase",
        stack_detection_source="manually-configured",
        second_account_used=False,
        scanner_overrides_applied=None,
    )


async def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# --------------------------------------------------------------------------- #
# Health                                                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_health_endpoint() -> None:
    app = create_app(_make_config())
    async with await _client(app) as c:
        r = await c.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# --------------------------------------------------------------------------- #
# Config endpoint                                                              #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_config_endpoint_returns_target() -> None:
    app = create_app(_make_config(target="http://localhost:3000"))
    async with await _client(app) as c:
        r = await c.get("/api/config")
    assert r.status_code == 200
    data = r.json()
    assert data["target"] == "http://localhost:3000"
    assert "stages" in data
    assert data["second_account_configured"] is False


@pytest.mark.asyncio
async def test_config_endpoint_masks_email() -> None:
    app = create_app(_make_config())
    async with await _client(app) as c:
        r = await c.get("/api/config")
    data = r.json()
    assert "***" in data["test_email_masked"]
    assert "test@example.com" not in data["test_email_masked"]


# --------------------------------------------------------------------------- #
# Start scan                                                                   #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_start_scan_returns_started() -> None:
    app = create_app(_make_config())

    with patch("vibe_iterator.server.routes.ScanRunner") as MockRunner:
        mock_instance = MagicMock()
        mock_instance.get_result.return_value = None
        mock_instance.run = AsyncMock(return_value=_make_scan_result())
        MockRunner.return_value = mock_instance

        async with await _client(app) as c:
            r = await c.post("/api/scan/start", json={"stage": "dev"})

    assert r.status_code == 200
    assert r.json()["status"] == "started"
    assert r.json()["stage"] == "dev"


@pytest.mark.asyncio
async def test_start_scan_409_when_running() -> None:
    app = create_app(_make_config())

    mock_runner = MagicMock()
    mock_runner.get_result.return_value = _make_scan_result(status="running")
    app.state.runner = mock_runner

    async with await _client(app) as c:
        r = await c.post("/api/scan/start", json={"stage": "dev"})

    assert r.status_code == 409


@pytest.mark.asyncio
async def test_start_scan_400_unknown_stage() -> None:
    cfg = _make_config()
    cfg.scanners_for_stage.return_value = []
    app = create_app(cfg)

    async with await _client(app) as c:
        r = await c.post("/api/scan/start", json={"stage": "nonexistent"})

    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Cancel scan                                                                  #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_cancel_no_active_scan_returns_404() -> None:
    app = create_app(_make_config())
    async with await _client(app) as c:
        r = await c.delete("/api/scan/active")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_cancel_running_scan_returns_ok() -> None:
    app = create_app(_make_config())
    mock_runner = MagicMock()
    mock_runner.get_result.return_value = _make_scan_result(status="running")
    app.state.runner = mock_runner

    async with await _client(app) as c:
        r = await c.delete("/api/scan/active")

    assert r.status_code == 200
    assert r.json()["status"] == "cancellation_requested"
    mock_runner.cancel.assert_called_once()


# --------------------------------------------------------------------------- #
# Results                                                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_get_results_no_scan_returns_404() -> None:
    app = create_app(_make_config())
    async with await _client(app) as c:
        r = await c.get("/api/scan/results")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_results_returns_serialized_result() -> None:
    app = create_app(_make_config())
    mock_runner = MagicMock()
    mock_runner.get_result.return_value = _make_scan_result(status="completed")
    app.state.runner = mock_runner

    async with await _client(app) as c:
        r = await c.get("/api/scan/results")

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "completed"
    assert data["stage"] == "dev"
    assert "findings" in data
    assert "scanner_results" in data
    assert data["score"] == 100
    assert data["score_grade"] == "A"


@pytest.mark.asyncio
async def test_get_finding_not_found() -> None:
    app = create_app(_make_config())
    mock_runner = MagicMock()
    mock_runner.get_result.return_value = _make_scan_result()
    app.state.runner = mock_runner

    async with await _client(app) as c:
        r = await c.get("/api/scan/results/nonexistent-id")

    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Mark findings                                                                #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_mark_finding_updates_status() -> None:
    app = create_app(_make_config())
    result = _make_scan_result()

    # Add a finding to mark
    finding = Finding(
        id="test-finding-id", fingerprint="fp1", scanner="data_leakage",
        severity=Severity.HIGH, title="Test", description="desc",
        evidence={}, screenshots=[], llm_prompt="prompt",
        remediation="fix", category="Data Leakage",
        page="http://localhost:3000/", timestamp="2024-01-01T00:00:00Z",
    )
    result.findings.append(finding)

    mock_runner = MagicMock()
    mock_runner.get_result.return_value = result
    app.state.runner = mock_runner

    async with await _client(app) as c:
        r = await c.post("/api/scan/findings/mark", json={
            "findings": [{"finding_id": "test-finding-id", "status": "resolved", "note": None}]
        })

    assert r.status_code == 200
    assert r.json()["updated"] == 1
    assert result.findings[0].mark_status == "resolved"
    assert len(result.finding_marks) == 1
    assert result.finding_marks[0].status == "resolved"


# --------------------------------------------------------------------------- #
# Export (Phase 4 stub)                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_export_report_returns_501() -> None:
    app = create_app(_make_config())
    async with await _client(app) as c:
        r = await c.get("/api/report/export")
    assert r.status_code == 501
