"""CLI entry point: GUI server or headless scan."""

from __future__ import annotations

import re
import sys
import webbrowser
from pathlib import Path

import click

from vibe_iterator.config import _DEFAULT_STAGES


_SCAN_STAGE_CHOICES = list(_DEFAULT_STAGES)


@click.group(invoke_without_command=True)
@click.option("--target", default=None, help="Target app URL (overrides .env)")
@click.option("--port", default=None, type=int, help="Dashboard port (default: 3001)")
@click.option("--no-browser", is_flag=True, default=False, help="Don't auto-open dashboard in browser")
@click.option("--verbose", is_flag=True, default=False, help="Stream events to stdout in GUI mode")
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
@click.option("--stage", default="dev", type=click.Choice(_SCAN_STAGE_CHOICES), help="Scan stage to run")
@click.option("--target", default=None, help="Target app URL (overrides .env)")
@click.option("--output", default=None, help="Write an HTML report to this path after the scan")
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


@cli.command("new-scanner")
@click.argument("name")
@click.option(
    "--category",
    default=None,
    type=click.Choice(
        [
            "injection",
            "access_control",
            "authentication",
            "client_tampering",
            "data_leakage",
            "misconfiguration",
            "api_security",
        ]
    ),
    help="Scanner category — pre-fills evidence structure and suggests stages.",
)
def new_scanner(name: str, category: str | None) -> None:
    """Generate boilerplate for a new community scanner.

    Run from the vibe-iterator project root.

    Example: vibe-iterator new-scanner stripe_check --category injection
    """
    from vibe_iterator.scaffold import (
        VALID_CATEGORIES,
        append_registry_row,
        build_registry_row,
        render_scanner,
        render_test,
    )

    if not re.match(r"^[a-z][a-z0-9_]*$", name):
        raise click.ClickException(
            f"Invalid scanner name '{name}'. "
            "Must be lowercase snake_case (e.g., stripe_check)."
        )

    root = Path.cwd()
    scanner_dir = root / "vibe_iterator" / "scanners"
    test_dir = root / "tests" / "test_scanners"

    if not scanner_dir.is_dir() or not test_dir.is_dir():
        raise click.ClickException(
            "Run this command from the vibe-iterator project root.\n"
            "Expected: vibe_iterator/scanners/ and tests/test_scanners/ in current directory."
        )

    scanner_path = scanner_dir / f"{name}.py"
    test_path = test_dir / f"test_{name}.py"

    if scanner_path.exists():
        raise click.ClickException(f"{scanner_path} already exists. Choose a different name.")
    if test_path.exists():
        raise click.ClickException(f"{test_path} already exists. Choose a different name.")

    scanner_path.write_text(render_scanner(name, category), encoding="utf-8")
    test_path.write_text(render_test(name), encoding="utf-8")

    stages = VALID_CATEGORIES[category] if category else ["pre-deploy"]
    row = build_registry_row(name, category, stages, ["any"], False)
    scanners_md = root / "docs" / "SCANNERS.md"
    if append_registry_row(str(scanners_md), row):
        click.echo(f"Updated {scanners_md.relative_to(root)}")
    else:
        click.echo(
            "[WARN] Could not update docs/SCANNERS.md — add the registry row manually.",
            err=True,
        )

    click.echo(f"Created vibe_iterator/scanners/{name}.py")
    click.echo(f"Created tests/test_scanners/test_{name}.py")
    click.echo()
    click.echo("Next:")
    click.echo(f"  1. Fill in the TODOs in vibe_iterator/scanners/{name}.py")
    click.echo(f"  2. Run: pytest tests/test_scanners/test_{name}.py -v")
    click.echo("  3. Run the full suite: pytest tests/ -q")
    click.echo("  4. Open a PR — see CONTRIBUTING.md for the checklist")


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
        log_level = "info" if verbose else "warning"
        uvicorn.run(app, host="127.0.0.1", port=config.port, log_level=log_level)
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

    # Check target reachability before starting a scan
    if not _check_target_reachable(config.target):
        click.echo(
            f"[ERROR] Target unreachable: {config.target}\n"
            "Make sure your app is running before starting a scan.",
            err=True,
        )
        sys.exit(1)

    def _event_handler(event: object) -> None:
        if verbose:
            _print_event(event)

    try:
        import asyncio

        runner = ScanRunner(config, on_event=_event_handler, browser_headless=headless)
        result = asyncio.run(runner.run(stage))
    except Exception as exc:
        click.echo(f"[ERROR] Scan failed: {exc}", err=True)
        sys.exit(1)

    from vibe_iterator.history import save_result
    try:
        saved_path = save_result(result, config.results_dir)
        click.echo(f"[vibe-iterator] Result saved to: {saved_path}")
    except Exception as exc:
        click.echo(f"[WARN] Could not save result: {exc}", err=True)

    click.echo(
        f"[vibe-iterator] Complete: status={result.status} "
        f"findings={len(result.findings)} score={result.score or 'n/a'}"
    )
    if output:
        try:
            from vibe_iterator.report.generator import generate
            generate(result, output_path=output)
            click.echo(f"[vibe-iterator] Report saved to: {output}")
        except Exception as exc:
            click.echo(f"[ERROR] Could not write report: {exc}", err=True)


def _print_event(event: object) -> None:
    """Stdout event handler for headless mode."""
    import json

    try:
        click.echo(json.dumps(event.__dict__ if hasattr(event, "__dict__") else str(event)))
    except Exception:
        click.echo(str(event))


def _check_target_reachable(target: str) -> bool:
    """Quick HTTP HEAD/GET check to verify the target is up."""
    import ssl
    import urllib.request
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(target, method="HEAD", headers={"User-Agent": "vibe-iterator/health-check"})
        with urllib.request.urlopen(req, timeout=5, context=ctx):
            return True
    except urllib.error.HTTPError:
        return True  # Any HTTP response means the server is up
    except Exception:
        return False
