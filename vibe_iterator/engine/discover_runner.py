# vibe_iterator/engine/discover_runner.py
"""Orchestrate spider components and write vibe-iterator.discovered.yaml."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from vibe_iterator.api_inventory import (
    ApiInventory,
    build_api_inventory,
    inventory_from_dict,
    inventory_to_dict,
)
from vibe_iterator.config import Config
from vibe_iterator.listeners.network import NetworkListener
from vibe_iterator.spider.dom_crawler import crawl_dom
from vibe_iterator.spider.endpoint_harvester import harvest_endpoints
from vibe_iterator.spider.js_extractor import extract_js_routes
from vibe_iterator.spider.sitemap import fetch_sitemap_routes

logger = logging.getLogger(__name__)

_SIDECAR_NAME = "vibe-iterator.discovered.yaml"


@dataclass
class DiscoveryResult:
    """Result of a spider/discovery run."""

    pages: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    discovered_at: str = ""
    api_inventory: ApiInventory | None = None


def run_discovery(
    config: Config,
    session: Any,
    network: NetworkListener,
    *,
    on_progress: Callable[[str], None] | None = None,
    yaml_dir: Path | None = None,
) -> DiscoveryResult:
    """Run all spider components and return a DiscoveryResult.

    Always writes vibe-iterator.discovered.yaml to yaml_dir (defaults to cwd),
    even when components return empty results.
    """

    def _log(msg: str) -> None:
        logger.info(msg)
        if on_progress:
            on_progress(msg)

    max_pages = config.spider_max_pages
    max_depth = config.spider_max_depth

    # 1. Sitemap (no browser needed)
    _log(f"[spider] Fetching sitemap from {config.target}...")
    sitemap_routes = fetch_sitemap_routes(config.target, max_pages=max_pages)
    _log(f"[spider] Sitemap: {len(sitemap_routes)} routes")

    # 2. DOM crawl + JS extraction per page
    seeds = list(dict.fromkeys(["/"] + sitemap_routes + config.pages))
    _log(f"[spider] DOM crawl: max_pages={max_pages}, max_depth={max_depth}, seeds={len(seeds)}")

    js_routes: list[str] = []

    def _on_page(url: str, depth: int) -> None:
        extracted = extract_js_routes(session)
        if extracted:
            js_routes.extend(extracted)
            _log(f"[spider] JS: {len(extracted)} routes on {url}")

    dom_routes = crawl_dom(
        session,
        seeds=seeds,
        base_url=config.target,
        max_pages=max_pages,
        max_depth=max_depth,
        on_page=_on_page,
    )
    _log(f"[spider] DOM: {len(dom_routes)} pages visited")

    # 3. API endpoints from captured traffic
    _log("[spider] Harvesting API endpoints from traffic...")
    api_endpoints = harvest_endpoints(network)
    _log(f"[spider] API endpoints: {len(api_endpoints)} unique")
    api_inventory = build_api_inventory(
        network,
        config.target,
        config.api_intelligence,
    )

    # 4. Merge page paths: sitemap + DOM + JS routes, deduplicated, sorted
    seen: set[str] = set()
    merged: list[str] = []
    for path in sitemap_routes + dom_routes + js_routes:
        if path not in seen:
            seen.add(path)
            merged.append(path)

    result = DiscoveryResult(
        pages=sorted(merged),
        api_endpoints=api_endpoints,
        discovered_at=datetime.now(timezone.utc).isoformat(),
        api_inventory=api_inventory,
    )

    # 5. Write sidecar (always — even when empty)
    sidecar_dir = yaml_dir or Path.cwd()
    sidecar_path = sidecar_dir / _SIDECAR_NAME
    _write_sidecar(result, sidecar_path)
    _log(f"[spider] Sidecar written: {sidecar_path}")

    return result


def _write_sidecar(result: DiscoveryResult, path: Path) -> None:
    data = {
        "pages": result.pages,
        "api_endpoints": result.api_endpoints,
        "discovered_at": result.discovered_at,
        "api_inventory": inventory_to_dict(result.api_inventory) if result.api_inventory else None,
    }
    with path.open("w", encoding="utf-8") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True)


def load_sidecar(yaml_dir: Path | None = None) -> DiscoveryResult | None:
    """Load vibe-iterator.discovered.yaml if it exists. Returns None if absent."""
    sidecar_dir = yaml_dir or Path.cwd()
    sidecar_path = sidecar_dir / _SIDECAR_NAME
    if not sidecar_path.exists():
        return None
    try:
        with sidecar_path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return DiscoveryResult(
            pages=data.get("pages", []),
            api_endpoints=data.get("api_endpoints", []),
            discovered_at=data.get("discovered_at", ""),
            api_inventory=inventory_from_dict(data.get("api_inventory")),
        )
    except Exception as exc:
        logger.warning("Could not load sidecar %s: %s", sidecar_path, exc)
        return None
