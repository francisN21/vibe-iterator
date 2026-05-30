# vibe_iterator/spider/sitemap.py
"""Discover page routes from sitemap.xml and robots.txt — no browser needed."""
from __future__ import annotations

import logging
from urllib.parse import urlparse
from xml.etree import ElementTree

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

_TIMEOUT = 5  # seconds


def fetch_sitemap_routes(base_url: str, max_pages: int = 30) -> list[str]:
    """Return deduplicated same-origin paths from sitemap.xml + robots.txt.

    Fetches /robots.txt first (Disallow: paths are included — they are often
    sensitive routes). Then fetches /sitemap.xml; follows <sitemapindex> one
    level deep. Caps results at max_pages.
    """
    base = base_url.rstrip("/")
    seen: set[str] = set()
    paths: list[str] = []

    def _add(path: str) -> bool:
        if len(paths) >= max_pages:
            return False
        path = path.rstrip("/") or "/"
        if path not in seen:
            seen.add(path)
            paths.append(path)
        return len(paths) < max_pages

    # 1. robots.txt
    extra_sitemaps: list[str] = []
    robots_body = _fetch(f"{base}/robots.txt")
    if robots_body:
        for line in robots_body.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("disallow:"):
                p = line[9:].strip().split("#")[0].strip()
                if p and p != "/":
                    if not _add(p):
                        break
            elif low.startswith("sitemap:"):
                url = line[8:].strip()
                if url:
                    extra_sitemaps.append(url)

    # 2. Sitemap(s)
    sitemap_urls = [f"{base}/sitemap.xml"] + extra_sitemaps
    visited: set[str] = set()

    for sm_url in sitemap_urls:
        if sm_url in visited or len(paths) >= max_pages:
            break
        visited.add(sm_url)
        body = _fetch(sm_url)
        if not body:
            continue
        try:
            root = ElementTree.fromstring(body)
        except ElementTree.ParseError:
            continue

        ns = _ns(root.tag)
        if "sitemapindex" in root.tag:
            for sm in root.findall(f"{{{ns}}}sitemap" if ns else "sitemap"):
                loc = sm.find(f"{{{ns}}}loc" if ns else "loc")
                if loc is not None and loc.text:
                    child = _fetch(loc.text.strip())
                    if child:
                        _parse_urlset(child, base, _add)
        else:
            _parse_urlset(body, base, _add)

    return paths


def _parse_urlset(body: str, base: str, add_fn) -> None:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return
    ns = _ns(root.tag)
    tag_url = f"{{{ns}}}url" if ns else "url"
    tag_loc = f"{{{ns}}}loc" if ns else "loc"
    parsed_base = urlparse(base)
    for url_el in root.findall(tag_url):
        loc = url_el.find(tag_loc)
        if loc is None or not loc.text:
            continue
        full_url = loc.text.strip()
        parsed = urlparse(full_url)
        if parsed.netloc and parsed.netloc != parsed_base.netloc:
            continue
        path = parsed.path or "/"
        if not add_fn(path):
            return


def _fetch(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("sitemap._fetch failed for %s: %s", url, exc)
        return None


def _ns(tag: str) -> str:
    """Extract XML namespace from '{http://...}tag'."""
    if tag.startswith("{"):
        return tag[1: tag.index("}")]
    return ""
