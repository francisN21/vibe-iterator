"""FastAPI application — serves the dashboard, REST API, and WebSocket."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from vibe_iterator.config import Config
from vibe_iterator.server.routes import router, websocket_endpoint
from vibe_iterator.server.websocket import WebSocketManager

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(config: Config) -> FastAPI:
    """Create and configure the FastAPI app instance."""
    app = FastAPI(title="vibe-iterator", version="0.1.0", docs_url=None, redoc_url=None)

    # Shared state
    app.state.config = config
    app.state.ws_manager = WebSocketManager()
    app.state.runner = None
    app.state.scan_task = None

    # REST API routes
    app.include_router(router)

    # Mount static files (CSS, JS)
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    # WebSocket endpoint
    @app.websocket("/ws")
    async def ws_route(ws: WebSocket) -> None:
        await websocket_endpoint(ws, app.state)

    # ------------------------------------------------------------------ #
    # HTML page routes                                                     #
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home() -> str:
        index = _STATIC_DIR / "index.html"
        if index.exists():
            return index.read_text(encoding="utf-8")
        return _placeholder("Dashboard Home", "Dashboard UI loading...")

    @app.get("/scan", response_class=HTMLResponse)
    async def scan_progress() -> str:
        page = _STATIC_DIR / "scan.html"
        if page.exists():
            return page.read_text(encoding="utf-8")
        return _placeholder("Scan Progress", "Scan UI loading...")

    @app.get("/results", response_class=HTMLResponse)
    async def results_dashboard() -> str:
        page = _STATIC_DIR / "results.html"
        if page.exists():
            return page.read_text(encoding="utf-8")
        return _placeholder("Results", "Results UI loading...")

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0", "target": config.target}

    return app


def _placeholder(title: str, message: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>vibe-iterator — {title}</title>
<style>body{{background:#0a0a0f;color:#00ff41;font-family:'Courier New',monospace;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{text-align:center;border:1px solid #00ff41;padding:2rem 3rem}}
h1{{color:#00d4ff}}p{{color:#c8c8d0}}</style></head>
<body><div class="box"><h1>vibe-iterator</h1><p>{title}</p>
<p style="color:#ffb000">{message}</p></div></body></html>"""
