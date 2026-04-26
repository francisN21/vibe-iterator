"""FastAPI application — serves the dashboard and placeholder API."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from vibe_iterator.config import Config

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(config: Config) -> FastAPI:
    """Create and configure the FastAPI app instance."""
    app = FastAPI(title="vibe-iterator", version="0.1.0", docs_url=None, redoc_url=None)

    # Attach config so routes can access it
    app.state.config = config

    # Mount static files (CSS, JS, images)
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    # ------------------------------------------------------------------ #
    # Placeholder routes — replaced by full routes in Phase 3            #
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home() -> str:
        """Serve dashboard home page."""
        index = _STATIC_DIR / "index.html"
        if index.exists():
            return index.read_text(encoding="utf-8")
        return _placeholder_page(
            title="Dashboard Home",
            message="Dashboard UI coming in Phase 3.",
            target=config.target,
        )

    @app.get("/scan", response_class=HTMLResponse)
    async def scan_progress() -> str:
        """Serve scan progress page."""
        page = _STATIC_DIR / "scan.html"
        if page.exists():
            return page.read_text(encoding="utf-8")
        return _placeholder_page(title="Scan Progress", message="Scan UI coming in Phase 3.")

    @app.get("/results", response_class=HTMLResponse)
    async def results_dashboard() -> str:
        """Serve results dashboard page."""
        page = _STATIC_DIR / "results.html"
        if page.exists():
            return page.read_text(encoding="utf-8")
        return _placeholder_page(title="Results", message="Results UI coming in Phase 3.")

    @app.get("/api/health")
    async def health() -> dict:
        """Basic health check."""
        return {"status": "ok", "version": "0.1.0", "target": config.target}

    return app


def _placeholder_page(*, title: str, message: str, target: str = "") -> str:
    """Minimal placeholder HTML served before the full dashboard is built."""
    target_line = f"<p>Target: <code>{target}</code></p>" if target else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>vibe-iterator — {title}</title>
  <style>
    body {{ background: #0a0a0f; color: #00ff41; font-family: 'Courier New', monospace;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .box {{ text-align: center; border: 1px solid #00ff41; padding: 2rem 3rem; }}
    h1 {{ color: #00d4ff; margin-bottom: .5rem; }}
    p {{ color: #c8c8d0; }}
    code {{ color: #00ff41; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>vibe-iterator</h1>
    <p>{title}</p>
    {target_line}
    <p style="color:#ffb000">{message}</p>
  </div>
</body>
</html>"""
