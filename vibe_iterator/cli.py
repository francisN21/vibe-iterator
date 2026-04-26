"""CLI entry point: GUI server or headless scan."""

from __future__ import annotations

import sys
import webbrowser

import click


@click.group(invoke_without_command=True)
@click.option("--target", default=None, help="Target app URL (overrides .env)")
@click.option("--port", default=None, type=int, help="Dashboard port (default: 3001)")
@click.option("--no-browser", is_flag=True, default=False, help="Don't auto-open dashboard in browser")
@click.option("--verbose", is_flag=True, default=False, help="Stream events to stdout in GUI mode (stub, Phase 5)")
@click.version_option(version="0.1.0", prog_name="vibe-iterator")
@click.pass_context
def cli(
    ctx: click.Context,
    target: str | None,
    port: int | None,
    no_browser: bool,
    verbose: bool,
) -> None:
    """Vibe Iterator: runtime security testing for vibe-coded apps.

    Run without a subcommand to launch the GUI dashboard.
    """
    if ctx.invoked_subcommand is not None:
        ctx.ensure_object(dict)
        ctx.obj["target"] = target
        ctx.obj["port"] = port
        ctx.obj["verbose"] = verbose
        return

    _launch_gui(target=target, port=port, open_browser=not no_browser, verbose=verbose)


@cli.command()
@click.option("--stage", default="dev", type=click.Choice(["dev", "pre-deploy", "post-deploy", "all"]), help="Scan stage to run")
@click.option("--target", default=None, help="Target app URL (overrides .env)")
@click.option("--output", default=None, help="Report output path (reserved for Phase 5)")
@click.option("--verbose", is_flag=True, default=False, help="Stream all events to stdout")
@click.pass_context
def scan(
    ctx: click.Context,
    stage: str,
    target: str | None,
    output: str | None,
    verbose: bool,
    headless: bool,
) -> None:
    """Run a scan in headless CLI mode.

    Example: vibe-iterator scan --headless --stage pre-deploy
    """
    parent = ctx.obj or {}
    effective_target = target or parent.get("target")
    effective_verbose = verbose or parent.get("verbose", False)
    _run_headless(
        stage=stage,
        target=effective_target,
        output=output,
        verbose=effective_verbose,
        headless=headless,
    )


# Keep --headless as a recognized flag for users who already pass it.
scan.params.append(
    click.Option(["--headless"], is_flag=True, default=True, hidden=True, help="Deprecated flag; scan is always headless")
)


def _launch_gui(
    *,
    target: str | None,
    port: int | None,
    open_browser: bool,
    verbose: bool,
) -> None:
    """Start the FastAPI server and optionally open the dashboard."""
    try:
        from vibe_iterator.config import load_config
    except ImportError as exc:
        click.echo(f"[ERROR] Failed to import config: {exc}", err=True)
        sys.exit(1)

    try:
        config = load_config(target_override=target, port_override=port)
    except Exception as exc:
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(1)

    url = f"http://127.0.0.1:{config.port}"
    click.echo(f"[vibe-iterator] Starting dashboard on {url}")

    if open_browser:
        import threading

        def _open() -> None:
            import time

            time.sleep(1.5)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    try:
        import uvicorn

        from vibe_iterator.server.app import create_app

        app = create_app(config)
        uvicorn.run(app, host="127.0.0.1", port=config.port, log_level="warning")
    except ImportError as exc:
        click.echo(f"[ERROR] Server dependencies not installed: {exc}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\n[vibe-iterator] Server stopped.")


def _run_headless(
    *,
    stage: str,
    target: str | None,
    output: str | None,
    verbose: bool,
    headless: bool,
) -> None:
    """Execute a scan without the GUI, printing events to stdout."""
    try:
        from vibe_iterator.config import load_config
        from vibe_iterator.engine.runner import ScanRunner
    except ImportError as exc:
        click.echo(f"[ERROR] Failed to import scan dependencies: {exc}", err=True)
        sys.exit(1)

    try:
        config = load_config(target_override=target)
    except Exception as exc:
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(1)

    click.echo(f"[vibe-iterator] Stage: {stage} - Target: {config.target}")

    try:
        import asyncio

        runner = ScanRunner(config, on_event=_print_event, browser_headless=headless)
        result = asyncio.run(runner.run(stage))
    except Exception as exc:
        click.echo(f"[ERROR] Scan failed: {exc}", err=True)
        sys.exit(1)

    click.echo(
        f"[vibe-iterator] Complete: status={result.status} "
        f"findings={len(result.findings)} score={result.score or 'n/a'}"
    )
    if output:
        click.echo(f"[vibe-iterator] --output is reserved for Phase 5 report export: {output}")


def _print_event(event: object) -> None:
    """Stdout event handler for headless mode."""
    import json

    try:
        click.echo(json.dumps(event.__dict__ if hasattr(event, "__dict__") else str(event)))
    except Exception:
        click.echo(str(event))
