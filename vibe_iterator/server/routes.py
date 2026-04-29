"""REST API routes and WebSocket endpoint for the dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request, WebSocket
from pydantic import BaseModel

from vibe_iterator.engine.runner import FindingMark, ScanResult, ScanRunner
from vibe_iterator.scanners.base import Finding, ScanEvent

logger = logging.getLogger(__name__)

router = APIRouter()

# --------------------------------------------------------------------------- #
# Static scanner metadata — avoids importing all scanner modules per request  #
# --------------------------------------------------------------------------- #

_SCANNER_META: dict[str, dict] = {
    "data_leakage":     {"requires_stack": ["any"],      "requires_second_account": False, "category": "Data Leakage",         "est_seconds": 15},
    "rls_bypass":       {"requires_stack": ["supabase"],  "requires_second_account": True,  "category": "Access Control",       "est_seconds": 30},
    "tier_escalation":  {"requires_stack": ["supabase"],  "requires_second_account": False, "category": "Access Control",       "est_seconds": 20},
    "bucket_limits":    {"requires_stack": ["supabase"],  "requires_second_account": False, "category": "Access Control",       "est_seconds": 25},
    "auth_check":       {"requires_stack": ["any"],       "requires_second_account": False, "category": "Authentication",       "est_seconds": 60},
    "client_tampering": {"requires_stack": ["any"],       "requires_second_account": False, "category": "Client-Side Tampering","est_seconds": 20},
    "sql_injection":    {"requires_stack": ["any"],       "requires_second_account": False, "category": "Injection",            "est_seconds": 60},
    "cors_check":       {"requires_stack": ["any"],       "requires_second_account": False, "category": "Misconfiguration",     "est_seconds": 15},
    "xss_check":        {"requires_stack": ["any"],       "requires_second_account": False, "category": "Injection",            "est_seconds": 30},
    "api_exposure":     {"requires_stack": ["any"],       "requires_second_account": False, "category": "API Security",         "est_seconds": 20},
}

_STAGE_LABELS = {
    "dev":         {"label": "DEV",         "tag": "Quick scan",    "icon": "⟨/⟩", "est_minutes": 2},
    "pre-deploy":  {"label": "PRE-DEPLOY",  "tag": "Recommended",   "icon": "🚀",  "est_minutes": 8},
    "post-deploy": {"label": "POST-DEPLOY", "tag": "Production",     "icon": "🌍",  "est_minutes": 5},
    "all":         {"label": "ALL",         "tag": "Full Audit",     "icon": "⊞",   "est_minutes": 15},
}


# --------------------------------------------------------------------------- #
# Request / response models                                                    #
# --------------------------------------------------------------------------- #

class StartScanRequest(BaseModel):
    stage: str
    scanner_overrides: list[str] | None = None


class MarkItem(BaseModel):
    finding_id: str
    status: str        # resolved | accepted_risk | false_positive | none
    note: str | None = None


class MarkRequest(BaseModel):
    findings: list[MarkItem]


# --------------------------------------------------------------------------- #
# Serialization helpers                                                        #
# --------------------------------------------------------------------------- #

def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "scanner": f.scanner,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "evidence": f.evidence,
        "screenshots": [{"label": s.label, "data": s.data} for s in f.screenshots],
        "llm_prompt": f.llm_prompt,
        "remediation": f.remediation,
        "category": f.category,
        "page": f.page,
        "timestamp": f.timestamp,
        "mark_status": f.mark_status,
        "mark_note": f.mark_note,
    }


def _result_dict(r: ScanResult) -> dict:
    return {
        "scan_id": r.scan_id,
        "stage": r.stage,
        "target": r.target,
        "status": r.status,
        "started_at": r.started_at,
        "completed_at": r.completed_at,
        "findings": [_finding_dict(f) for f in r.findings],
        "scanner_results": [
            {
                "scanner_name": sr.scanner_name,
                "status": sr.status,
                "findings_count": sr.findings_count,
                "duration_seconds": sr.duration_seconds,
                "skip_reason": sr.skip_reason,
            }
            for sr in r.scanner_results
        ],
        "finding_marks": [
            {"finding_id": m.finding_id, "status": m.status, "note": m.note}
            for m in r.finding_marks
        ],
        "score": r.score,
        "score_grade": r.score_grade,
        "duration_seconds": r.duration_seconds,
        "pages_crawled": r.pages_crawled,
        "requests_captured": r.requests_captured,
        "stack_detected": r.stack_detected,
        "stack_detection_source": r.stack_detection_source,
        "second_account_used": r.second_account_used,
        "scanner_overrides_applied": r.scanner_overrides_applied,
    }


# --------------------------------------------------------------------------- #
# Utility                                                                      #
# --------------------------------------------------------------------------- #

async def _check_reachable(url: str) -> bool:
    """Return True if the target host:port accepts a TCP connection."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=3)),
            timeout=4.0,
        )
        return True
    except Exception:
        return False


def _mask_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return local[:1] + "***@" + domain


def _scanner_availability(scanner_name: str, config: Any) -> dict:
    meta = _SCANNER_META.get(scanner_name, {})
    requires_stack = meta.get("requires_stack", ["any"])
    requires_second = meta.get("requires_second_account", False)

    available = True
    skip_reason: str | None = None

    if requires_stack != ["any"] and config.stack.backend not in requires_stack:
        available = False
        skip_reason = f"Requires {requires_stack[0]} stack — detected: {config.stack.backend}"
    elif requires_second and not config.second_account_configured:
        available = False
        skip_reason = "Requires second test account — not configured"

    return {
        "name": scanner_name,
        "available": available,
        "skip_reason": skip_reason,
        "category": meta.get("category", ""),
        "est_seconds": meta.get("est_seconds", 30),
    }


# --------------------------------------------------------------------------- #
# Routes                                                                       #
# --------------------------------------------------------------------------- #

@router.post("/api/scan/start")
async def start_scan(body: StartScanRequest, request: Request) -> dict:
    config = request.app.state.config
    manager = request.app.state.ws_manager

    # 409 guard — only one scan at a time
    runner: ScanRunner | None = getattr(request.app.state, "runner", None)
    if runner is not None:
        result = runner.get_result()
        if result is not None and result.status == "running":
            raise HTTPException(status_code=409, detail="A scan is already in progress.")

    # Validate stage
    if not config.scanners_for_stage(body.stage):
        raise HTTPException(status_code=400, detail=f"Unknown stage: '{body.stage}'")

    loop = asyncio.get_event_loop()

    def on_event(event: ScanEvent) -> None:
        payload = json.dumps({"type": event.type, "timestamp": event.timestamp, "data": event.data})
        asyncio.run_coroutine_threadsafe(manager.broadcast(payload), loop)

    new_runner = ScanRunner(
        config,
        on_event=on_event,
        scanner_overrides=body.scanner_overrides,
    )
    request.app.state.runner = new_runner
    manager.clear_buffer()

    task = asyncio.create_task(new_runner.run(body.stage))

    def _on_done(t: asyncio.Task) -> None:
        if not t.cancelled() and t.exception():
            logger.exception("Background scan task failed", exc_info=t.exception())

    task.add_done_callback(_on_done)
    request.app.state.scan_task = task

    return {"status": "started", "stage": body.stage, "scan_id": new_runner.get_result().scan_id if new_runner.get_result() else None}


@router.delete("/api/scan/active")
async def cancel_scan(request: Request) -> dict:
    runner: ScanRunner | None = getattr(request.app.state, "runner", None)
    if runner is None:
        raise HTTPException(status_code=404, detail="No active scan.")
    result = runner.get_result()
    if result is None or result.status != "running":
        raise HTTPException(status_code=404, detail="No running scan to cancel.")
    runner.cancel()
    return {"status": "cancellation_requested"}


@router.get("/api/scan/results")
async def get_results(request: Request) -> dict:
    runner: ScanRunner | None = getattr(request.app.state, "runner", None)
    if runner is None or runner.get_result() is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    return _result_dict(runner.get_result())


@router.get("/api/scan/results/{finding_id}")
async def get_finding(finding_id: str, request: Request) -> dict:
    runner: ScanRunner | None = getattr(request.app.state, "runner", None)
    if runner is None or runner.get_result() is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    result = runner.get_result()
    for f in result.findings:
        if f.id == finding_id:
            return _finding_dict(f)
    raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")


@router.post("/api/scan/findings/mark")
async def mark_findings(body: MarkRequest, request: Request) -> dict:
    runner: ScanRunner | None = getattr(request.app.state, "runner", None)
    if runner is None or runner.get_result() is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    result = runner.get_result()

    for item in body.findings:
        # Update or insert mark in finding_marks list
        existing = next((m for m in result.finding_marks if m.finding_id == item.finding_id), None)
        if existing:
            existing.status = item.status
            existing.note = item.note
        else:
            result.finding_marks.append(FindingMark(
                finding_id=item.finding_id,
                status=item.status,
                note=item.note,
            ))
        # Mirror on the Finding itself for convenience
        for f in result.findings:
            if f.id == item.finding_id:
                f.mark_status = item.status
                f.mark_note = item.note
                break

    return {"status": "ok", "updated": len(body.findings)}


@router.get("/api/config")
async def get_config(request: Request) -> dict:
    config = request.app.state.config
    target_reachable = await _check_reachable(config.target)

    stages_info: dict[str, dict] = {}
    for stage_name, scanner_names in config.stages.items():
        label_meta = _STAGE_LABELS.get(stage_name, {"label": stage_name.upper(), "tag": "", "icon": "⊞", "est_minutes": 5})
        scanners = [_scanner_availability(name, config) for name in scanner_names]
        skipped_count = sum(1 for s in scanners if not s["available"])
        stages_info[stage_name] = {
            **label_meta,
            "scanners": scanners,
            "skipped_count": skipped_count,
        }

    return {
        "target": config.target,
        "target_reachable": target_reachable,
        "test_email_masked": _mask_email(config.test_email),
        "pages": config.pages,
        "pages_count": len(config.pages),
        "stack": {
            "backend": config.stack.backend,
            "auth": config.stack.auth,
            "storage": config.stack.storage,
            "detection_source": config.stack.detection_source,
        },
        "second_account_configured": config.second_account_configured,
        "port": config.port,
        "stages": stages_info,
    }


@router.get("/api/report/export")
async def export_report(request: Request):
    runner = getattr(request.app.state, "runner", None)
    if runner is None or runner.get_result() is None:
        raise HTTPException(status_code=404, detail="No scan results available to export.")

    result = runner.get_result()
    if result.status == "running":
        raise HTTPException(status_code=409, detail="Scan still running — wait for completion before exporting.")

    from vibe_iterator.report.generator import generate, default_filename
    from fastapi.responses import HTMLResponse

    html = generate(result)
    filename = default_filename(result)
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------------- #
# WebSocket endpoint                                                           #
# --------------------------------------------------------------------------- #

async def websocket_endpoint(ws: WebSocket, app_state: Any) -> None:
    """Handle a single WebSocket connection lifecycle."""
    manager = app_state.ws_manager
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except Exception:
        pass
    finally:
        manager.disconnect(ws)
