"""REST API routes and WebSocket endpoint for the dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import uuid
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request, WebSocket
from pydantic import BaseModel

from vibe_iterator.engine.runner import FindingMark, ScanRunner
from vibe_iterator.history import finding_dict, serialize_result
from vibe_iterator.scanners.base import ScanEvent

logger = logging.getLogger(__name__)

router = APIRouter()

# --------------------------------------------------------------------------- #
# Static scanner metadata — avoids importing all scanner modules per request  #
# --------------------------------------------------------------------------- #

_SCANNER_META: dict[str, dict] = {
    "data_leakage": {
        "label": "Data Leakage",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Data Leakage", "est_seconds": 15,
        "description": "Finds auth tokens, UUIDs, and PII exposed in network traffic, localStorage, and API responses.",
    },
    "rls_bypass": {
        "label": "RLS Bypass",
        "requires_stack": ["supabase"], "requires_second_account": True,
        "category": "Access Control", "est_seconds": 30,
        "description": "Tests Supabase Row Level Security by querying as a second user — finds tables missing RLS rules.",
    },
    "tier_escalation": {
        "label": "Tier Escalation",
        "requires_stack": ["supabase"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 20,
        "description": "Manipulates subscription tier flags to check if premium features can be unlocked for free.",
    },
    "bucket_limits": {
        "label": "Storage Limits",
        "requires_stack": ["supabase"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 25,
        "description": "Tests Supabase storage buckets for missing file size limits, type restrictions, and public access.",
    },
    "auth_check": {
        "label": "Auth & Sessions",
        "requires_stack": ["any"], "requires_second_account": True,
        "category": "Authentication", "est_seconds": 60,
        "description": "Six-group audit: token security, session fixation, login brute-force, password reset, auth bypass, and OAuth.",
    },
    "client_tampering": {
        "label": "Client Tampering",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Client-Side Tampering", "est_seconds": 20,
        "description": "Modifies localStorage, cookies, and request bodies to test if the server enforces business rules server-side.",
    },
    "sql_injection": {
        "label": "SQL Injection",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Injection", "est_seconds": 60,
        "description": "Active injection testing across captured API endpoints — includes blind injection and PostgREST filter bypass.",
    },
    "cors_check": {
        "label": "CORS",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Misconfiguration", "est_seconds": 15,
        "description": "Probes CORS with crafted Origin headers to find overly permissive cross-origin access policies.",
    },
    "xss_check": {
        "label": "XSS",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Injection", "est_seconds": 30,
        "description": "Injects reflected, stored, and DOM-based XSS payloads into all discovered input fields and URL parameters.",
    },
    "api_exposure": {
        "label": "Unprotected APIs",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "API Security", "est_seconds": 20,
        "description": "Replays captured API requests without auth headers — finds endpoints that serve data without authentication.",
    },
    "api_key_exposure": {
        "label": "API Key Exposure",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Data Leakage", "est_seconds": 10,
        "description": "Scans network traffic, response bodies, and browser storage for leaked API keys (Stripe, AWS, GitHub, OpenAI, and more).",
    },
    "rate_limit_check": {
        "label": "Rate Limiting",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Rate Limiting", "est_seconds": 45,
        "description": "Sends 10-attempt bursts to auth endpoints — detects missing rate limits, lockout DoS, and missing Retry-After.",
    },
    "mass_assignment": {
        "label": "Mass Assignment",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 20,
        "description": "Injects extra fields into API requests to test if the server exposes unintended writable properties like role or is_admin.",
    },
    "info_disclosure": {
        "label": "Info Disclosure",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Misconfiguration", "est_seconds": 15,
        "description": "Looks for verbose error messages, stack traces, version numbers, and debug info leaked in API responses.",
    },
    "idor_check": {
        "label": "IDOR",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 25,
        "description": "Tests Insecure Direct Object Reference by replaying requests with swapped IDs to check cross-user data access.",
    },
    "http_method_tampering": {
        "label": "Method Tampering",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Misconfiguration", "est_seconds": 15,
        "description": "Sends DELETE/PUT/PATCH to endpoints expecting GET/POST — checks if method overrides bypass access controls.",
    },
    "open_redirect_check": {
        "label": "Open Redirect",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Misconfiguration", "est_seconds": 15,
        "description": "Probes redirect parameters for external Location headers that can send users to attacker-controlled sites.",
    },
    "path_traversal_check": {
        "label": "Path Traversal",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 20,
        "description": "Probes file/path parameters for traversal payloads that disclose local configuration or system files.",
    },
    "ssrf_check": {
        "label": "SSRF",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "API Security", "est_seconds": 25,
        "description": "Probes URL-like parameters with a local callback and reports only when the server fetches it.",
    },
    "csrf_check": {
        "label": "CSRF",
        "requires_stack": ["any"], "requires_second_account": False,
        "category": "API Security", "est_seconds": 25,
        "description": "Replays cookie-authenticated unsafe requests with cross-site Origin after stripping CSRF headers.",
    },
    "firebase_firestore": {
        "label": "Firestore Rules",
        "requires_stack": ["firebase"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 45,
        "description": "Tests Firestore security rules for unauthenticated reads, writes, IDOR, and mass assignment.",
    },
    "firebase_rtdb": {
        "label": "Realtime Database",
        "requires_stack": ["firebase"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 35,
        "description": "Tests Realtime Database rules for open reads, writes, deletes, and sensitive data exposure.",
    },
    "firebase_storage": {
        "label": "Storage Rules",
        "requires_stack": ["firebase"], "requires_second_account": False,
        "category": "Access Control", "est_seconds": 40,
        "description": "Tests Firebase Storage rules for public downloads, uploads, object listing, and cross-user access.",
    },
    "firebase_auth": {
        "label": "Firebase Auth",
        "requires_stack": ["firebase"], "requires_second_account": False,
        "category": "Authentication", "est_seconds": 30,
        "description": "Tests Firebase Auth configuration for anonymous signup, account enumeration, and token leakage.",
    },
    "firebase_functions": {
        "label": "Cloud Functions",
        "requires_stack": ["firebase"], "requires_second_account": False,
        "category": "API Security", "est_seconds": 35,
        "description": "Tests Firebase Cloud Functions for unauthenticated access, token leakage, and permissive CORS.",
    },
}

_STAGE_LABELS = {
    "dev":         {"label": "DEV",         "tag": "Quick scan",    "icon": "⟨/⟩", "est_minutes": 2},
    "pre-deploy":  {"label": "PRE-DEPLOY",  "tag": "Recommended",   "icon": "🚀",  "est_minutes": 8},
    "post-deploy": {"label": "POST-DEPLOY", "tag": "Production",     "icon": "🌍",  "est_minutes": 5},
    "all":         {"label": "ALL",         "tag": "Full Audit",     "icon": "⊞",   "est_minutes": 15},
    "firebase":    {"label": "FIREBASE",    "tag": "Stack-specific", "icon": "FB",  "est_minutes": 4},
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
        "label": meta.get("label", scanner_name.replace("_", " ").title()),
        "available": available,
        "skip_reason": skip_reason,
        "category": meta.get("category", ""),
        "est_seconds": meta.get("est_seconds", 30),
        "description": meta.get("description", ""),
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
    scan_task: asyncio.Task | None = getattr(request.app.state, "scan_task", None)
    if scan_task is not None and not scan_task.done():
        raise HTTPException(status_code=409, detail="A scan is already in progress.")

    # Validate stage — 'discover' is a special stage (no scanner list)
    if body.stage != "discover":
        stage_scanners = config.scanners_for_stage(body.stage)
        if not stage_scanners:
            raise HTTPException(status_code=400, detail=f"Unknown stage: '{body.stage}'")
        if body.scanner_overrides is not None:
            if not body.scanner_overrides:
                raise HTTPException(status_code=400, detail="scanner_overrides must include at least one scanner.")
            invalid = [s for s in body.scanner_overrides if s not in stage_scanners]
            if invalid:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Invalid scanner_overrides for stage '{body.stage}': {invalid}. "
                        f"Valid names: {stage_scanners}"
                    ),
                )

    loop = asyncio.get_event_loop()
    scan_id = str(uuid.uuid4())

    def on_event(event: ScanEvent) -> None:
        payload = json.dumps({"type": event.type, "timestamp": event.timestamp, "data": event.data})
        asyncio.run_coroutine_threadsafe(manager.broadcast(payload), loop)

    new_runner = ScanRunner(
        config,
        on_event=on_event,
        scanner_overrides=body.scanner_overrides,
        scan_id=scan_id,
    )
    request.app.state.runner = new_runner
    manager.clear_buffer()

    task = asyncio.create_task(new_runner.run(body.stage))

    def _on_done(t: asyncio.Task) -> None:
        if not t.cancelled() and t.exception():
            logger.exception("Background scan task failed", exc_info=t.exception())
            return
        result = new_runner.get_result()
        if result is not None:
            from vibe_iterator.history import save_result
            try:
                save_result(result, config.results_dir)
            except Exception as exc:
                logger.warning("Could not save scan result: %s", exc)

    task.add_done_callback(_on_done)
    request.app.state.scan_task = task

    return {"status": "started", "stage": body.stage, "scan_id": scan_id}


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
    return serialize_result(runner.get_result())


@router.get("/api/scan/results/{finding_id}")
async def get_finding(finding_id: str, request: Request) -> dict:
    runner: ScanRunner | None = getattr(request.app.state, "runner", None)
    if runner is None or runner.get_result() is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    result = runner.get_result()
    for f in result.findings:
        if f.id == finding_id:
            return finding_dict(f)
    raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")


@router.get("/api/history")
async def get_history(request: Request) -> list:
    from vibe_iterator.history import list_results
    config = request.app.state.config
    return list_results(config.results_dir)


@router.get("/api/history/{filename}")
async def get_historical_result(filename: str, request: Request) -> dict:
    from vibe_iterator.history import load_result
    config = request.app.state.config
    try:
        return load_result(filename, config.results_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Result not found")


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

    if result.status != "completed":
        raise HTTPException(status_code=409, detail="Only completed scans can be exported.")

    from fastapi.responses import HTMLResponse

    from vibe_iterator.report.generator import default_filename, generate

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
