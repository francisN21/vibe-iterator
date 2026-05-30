# Endpoint Discovery — Plan 1: Spider Components + discover_runner

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `vibe_iterator/spider/` module (sitemap, endpoint_harvester, js_extractor, dom_crawler), the `discover_runner.py` orchestrator, and add `spider_max_pages`/`spider_max_depth` to Config — all fully tested without Selenium.

**Architecture:** Four focused spider components (no shared state, each independently importable and testable), orchestrated by `discover_runner.py` which merges results and writes `vibe-iterator.discovered.yaml`. Config gets two new optional fields. Plan 2 wires this into the engine, dashboard, and docs.

**Tech Stack:** Python 3.11+, stdlib (`urllib`, `xml.etree.ElementTree`, `http.server`, `threading`), `PyYAML`, `selenium` (imported in dom_crawler but mocked in tests), `pytest`, `unittest.mock`

**Spec:** `docs/superpowers/specs/2026-05-29-endpoint-discovery-design.md`

---

## Task 1: Module scaffold

**Files:**
- Create: `vibe_iterator/spider/__init__.py`
- Create: `tests/test_spider/__init__.py`

- [ ] **Step 1: Create the spider package**

```python
# vibe_iterator/spider/__init__.py
```

```python
# tests/test_spider/__init__.py
```

Both files are empty (just `# <filename>` comment or blank). This registers them as Python packages.

- [ ] **Step 2: Verify imports work**

Run:
```
py -c "import vibe_iterator.spider; print('ok')"
```
Expected: `ok`

- [ ] **Step 3: Commit**

```
git add vibe_iterator/spider/__init__.py tests/test_spider/__init__.py
git commit -m "feat: scaffold vibe_iterator/spider package and tests/test_spider"
```

---

## Task 2: `sitemap.py` — fetch routes from sitemap.xml and robots.txt

**Files:**
- Create: `vibe_iterator/spider/sitemap.py`
- Create: `tests/test_spider/test_sitemap.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_spider/test_sitemap.py
"""Tests for sitemap.py — stdlib HTTP fixture, no Selenium."""
from __future__ import annotations
import http.server
import threading
import pytest
from vibe_iterator.spider.sitemap import fetch_sitemap_routes


class _SitemapFixture:
    SITEMAP_XML = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>{base}/</loc></url>"
        "<url><loc>{base}/about</loc></url>"
        "<url><loc>{base}/contact</loc></url>"
        "</urlset>"
    )
    ROBOTS_TXT = "User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: {base}/sitemap.xml\n"

    def __init__(self):
        self._server = None
        self.base_url = None

    def __enter__(self):
        fixture = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/sitemap.xml":
                    body = fixture.SITEMAP_XML.format(base=fixture.base_url).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xml")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/robots.txt":
                    body = fixture.ROBOTS_TXT.format(base=fixture.base_url).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *_):
                pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        return self

    def __exit__(self, *_):
        self._server.shutdown()


def test_sitemap_paths_returned():
    with _SitemapFixture() as srv:
        paths = fetch_sitemap_routes(srv.base_url)
    assert "/" in paths
    assert "/about" in paths
    assert "/contact" in paths


def test_robots_disallow_included():
    with _SitemapFixture() as srv:
        paths = fetch_sitemap_routes(srv.base_url)
    assert "/admin" in paths
    assert "/private" in paths


def test_max_pages_cap():
    with _SitemapFixture() as srv:
        paths = fetch_sitemap_routes(srv.base_url, max_pages=2)
    assert len(paths) <= 2


def test_unreachable_host_returns_empty():
    paths = fetch_sitemap_routes("http://127.0.0.1:1")
    assert paths == []
```

- [ ] **Step 2: Run test to verify it fails**

```
py -m pytest tests/test_spider/test_sitemap.py -v
```
Expected: `ModuleNotFoundError: No module named 'vibe_iterator.spider.sitemap'`

- [ ] **Step 3: Implement `sitemap.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```
py -m pytest tests/test_spider/test_sitemap.py -v
```
Expected: 4 PASSED

- [ ] **Step 5: Commit**

```
git add vibe_iterator/spider/sitemap.py tests/test_spider/test_sitemap.py
git commit -m "feat: add sitemap.py — fetch routes from sitemap.xml and robots.txt"
```

---

## Task 3: `endpoint_harvester.py` — extract API endpoints from network traffic

**Files:**
- Create: `vibe_iterator/spider/endpoint_harvester.py`
- Create: `tests/test_spider/test_endpoint_harvester.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_spider/test_endpoint_harvester.py
"""Tests for endpoint_harvester.py — pure data transform, no I/O."""
from __future__ import annotations
from unittest.mock import MagicMock
from vibe_iterator.spider.endpoint_harvester import harvest_endpoints
from vibe_iterator.listeners.network import NetworkRequest


def _req(url: str, method: str = "GET") -> NetworkRequest:
    return NetworkRequest(
        request_id="x", method=method, url=url,
        headers={}, post_data=None, timestamp=0.0,
    )


def _net(reqs: list) -> MagicMock:
    m = MagicMock()
    m.get_requests.return_value = reqs
    return m


def test_api_path_returned():
    result = harvest_endpoints(_net([_req("http://localhost/api/v1/users")]))
    assert "GET /api/v1/users" in result


def test_uuid_normalized():
    url = "http://localhost/api/users/123e4567-e89b-12d3-a456-426614174000"
    result = harvest_endpoints(_net([_req(url)]))
    assert "GET /api/users/{id}" in result


def test_integer_id_normalized_and_deduped():
    result = harvest_endpoints(_net([
        _req("http://localhost/api/items/42"),
        _req("http://localhost/api/items/99"),
    ]))
    assert result.count("GET /api/items/{id}") == 1


def test_non_api_path_skipped():
    result = harvest_endpoints(_net([_req("http://localhost/static/app.js")]))
    assert result == []


def test_post_method_preserved():
    result = harvest_endpoints(_net([_req("http://localhost/api/auth/login", method="POST")]))
    assert "POST /api/auth/login" in result


def test_graphql_detected():
    result = harvest_endpoints(_net([_req("http://localhost/graphql", method="POST")]))
    assert any("/graphql" in e for e in result)


def test_rest_resource_pattern_detected():
    result = harvest_endpoints(_net([_req("http://localhost/users/42")]))
    assert "GET /users/{id}" in result
```

- [ ] **Step 2: Run test to verify it fails**

```
py -m pytest tests/test_spider/test_endpoint_harvester.py -v
```
Expected: `ModuleNotFoundError: No module named 'vibe_iterator.spider.endpoint_harvester'`

- [ ] **Step 3: Implement `endpoint_harvester.py`**

```python
# vibe_iterator/spider/endpoint_harvester.py
"""Collect and normalize API endpoints from captured network traffic."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from vibe_iterator.listeners.network import NetworkListener

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_INT_RE = re.compile(r"^\d+$")

_API_PREFIXES = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/")


def harvest_endpoints(network: NetworkListener) -> list[str]:
    """Return sorted, deduplicated 'METHOD /normalized/path' strings for API calls."""
    seen: set[str] = set()
    results: list[str] = []
    for req in network.get_requests():
        entry = _classify(req)
        if entry and entry not in seen:
            seen.add(entry)
            results.append(entry)
    return sorted(results)


def _classify(req) -> str | None:
    try:
        path = urlparse(req.url).path
    except Exception:
        return None
    if not _is_api_path(path):
        return None
    return f"{req.method.upper()} {_normalize_path(path)}"


def _is_api_path(path: str) -> bool:
    for prefix in _API_PREFIXES:
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return True
    # REST resource pattern: /word/id (e.g. /users/123 or /items/uuid)
    parts = [p for p in path.split("/") if p]
    if len(parts) == 2 and re.match(r"^[a-z][a-z_-]*$", parts[0], re.I):
        if _UUID_RE.fullmatch(parts[1]) or _INT_RE.fullmatch(parts[1]):
            return True
    return False


def _normalize_path(path: str) -> str:
    parts = path.split("/")
    normalized = []
    for part in parts:
        if _UUID_RE.fullmatch(part) or _INT_RE.fullmatch(part):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/".join(normalized)
```

- [ ] **Step 4: Run tests to verify they pass**

```
py -m pytest tests/test_spider/test_endpoint_harvester.py -v
```
Expected: 7 PASSED

- [ ] **Step 5: Commit**

```
git add vibe_iterator/spider/endpoint_harvester.py tests/test_spider/test_endpoint_harvester.py
git commit -m "feat: add endpoint_harvester.py — normalize API endpoints from network traffic"
```

---

## Task 4: `js_extractor.py` — extract routes from SPA frameworks via CDP

**Files:**
- Create: `vibe_iterator/spider/js_extractor.py`
- Create: `tests/test_spider/test_js_extractor.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_spider/test_js_extractor.py
"""Tests for js_extractor.py — mocks session.evaluate, no browser needed."""
from __future__ import annotations
from unittest.mock import MagicMock
from vibe_iterator.spider.js_extractor import extract_js_routes


def _session(return_value) -> MagicMock:
    s = MagicMock()
    s.evaluate.return_value = return_value
    return s


def test_routes_returned():
    result = extract_js_routes(_session(["/", "/about", "/dashboard"]))
    assert "/" in result
    assert "/about" in result
    assert "/dashboard" in result


def test_empty_list_returned_when_no_framework():
    assert extract_js_routes(_session([])) == []


def test_cdp_exception_returns_empty():
    s = MagicMock()
    s.evaluate.side_effect = RuntimeError("CDP error")
    assert extract_js_routes(s) == []


def test_none_return_is_empty():
    assert extract_js_routes(_session(None)) == []


def test_relative_path_normalized():
    result = extract_js_routes(_session(["about", "contact"]))
    assert "/about" in result
    assert "/contact" in result


def test_trailing_slash_stripped():
    result = extract_js_routes(_session(["/dashboard/"]))
    assert "/dashboard" in result
    assert "/dashboard/" not in result
```

- [ ] **Step 2: Run test to verify it fails**

```
py -m pytest tests/test_spider/test_js_extractor.py -v
```
Expected: `ModuleNotFoundError: No module named 'vibe_iterator.spider.js_extractor'`

- [ ] **Step 3: Implement `js_extractor.py`**

```python
# vibe_iterator/spider/js_extractor.py
"""Extract declared routes from SPA frameworks via CDP JS evaluation."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Probe checks Next.js, React Router v6, React Router v5 in order.
# Each block is wrapped in try/catch so an absent framework silently returns null.
_JS_PROBE = """
(function () {
  var routes = [];

  try {
    if (window.__NEXT_DATA__) {
      var nd = window.__NEXT_DATA__;
      if (nd.page) routes.push(nd.page);
      if (nd.buildManifest && nd.buildManifest.pages) {
        routes = routes.concat(Object.keys(nd.buildManifest.pages));
      }
    }
  } catch (e) {}

  try {
    if (window.__reactRouterContext && window.__reactRouterContext.router) {
      var st = window.__reactRouterContext.router.state;
      if (st && st.matches) {
        st.matches.forEach(function (m) {
          if (m.route && m.route.path) routes.push(m.route.path);
        });
      }
    }
  } catch (e) {}

  try {
    if (window.__REACT_ROUTER_ROUTES__) {
      window.__REACT_ROUTER_ROUTES__.forEach(function (r) {
        if (r.path) routes.push(r.path);
      });
    }
  } catch (e) {}

  return routes.filter(function (r, i, a) {
    return r && typeof r === "string" && a.indexOf(r) === i;
  });
})()
"""


def extract_js_routes(session: Any) -> list[str]:
    """Run the CDP JS probe on the current page and return declared route paths.

    Returns [] if no framework is detected or if the CDP call fails.
    """
    try:
        result = session.evaluate(_JS_PROBE)
        if not isinstance(result, list):
            return []
        return [_normalize(r) for r in result if isinstance(r, str) and r]
    except Exception as exc:
        logger.debug("js_extractor: CDP probe failed: %s", exc)
        return []


def _normalize(path: str) -> str:
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path
```

- [ ] **Step 4: Run tests to verify they pass**

```
py -m pytest tests/test_spider/test_js_extractor.py -v
```
Expected: 6 PASSED

- [ ] **Step 5: Commit**

```
git add vibe_iterator/spider/js_extractor.py tests/test_spider/test_js_extractor.py
git commit -m "feat: add js_extractor.py — extract SPA routes via CDP probe"
```

---

## Task 5: `dom_crawler.py` — BFS DOM crawl via Selenium

**Files:**
- Create: `vibe_iterator/spider/dom_crawler.py`
- Create: `tests/test_spider/test_dom_crawler.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_spider/test_dom_crawler.py
"""Tests for dom_crawler.py — mocks Selenium driver, no real browser."""
from __future__ import annotations
from unittest.mock import MagicMock, patch
from vibe_iterator.spider.dom_crawler import crawl_dom, _to_path


def _mock_session(pages: dict[str, list[str]]) -> MagicMock:
    """Build a mock BrowserSession where each page URL maps to hrefs returned.

    pages = {"http://localhost:3000/": ["http://localhost:3000/about"], ...}
    """
    visited_urls: list[str] = []

    def _get(url: str) -> None:
        visited_urls.append(url)

    def _find_elements(by, tag):
        if not visited_urls:
            return []
        last_url = visited_urls[-1]
        hrefs = pages.get(last_url, [])
        elements = []
        for href in hrefs:
            el = MagicMock()
            el.get_attribute.return_value = href
            elements.append(el)
        return elements

    driver = MagicMock()
    driver.get.side_effect = _get
    driver.find_elements.side_effect = _find_elements

    session = MagicMock()
    session.driver = driver
    return session


BASE = "http://localhost:3000"


def test_crawl_visits_seed():
    session = _mock_session({f"{BASE}/": []})
    result = crawl_dom(session, ["/"], BASE)
    assert "/" in result


def test_crawl_follows_links():
    session = _mock_session({
        f"{BASE}/": [f"{BASE}/about", f"{BASE}/contact"],
        f"{BASE}/about": [],
        f"{BASE}/contact": [],
    })
    result = crawl_dom(session, ["/"], BASE, max_pages=10)
    assert "/about" in result
    assert "/contact" in result


def test_max_pages_respected():
    pages = {f"{BASE}/": [f"{BASE}/p{i}" for i in range(10)]}
    for i in range(10):
        pages[f"{BASE}/p{i}"] = []
    session = _mock_session(pages)
    result = crawl_dom(session, ["/"], BASE, max_pages=3)
    assert len(result) <= 3


def test_external_links_not_followed():
    session = _mock_session({
        f"{BASE}/": ["https://example.com/page", f"{BASE}/local"],
        f"{BASE}/local": [],
    })
    result = crawl_dom(session, ["/"], BASE)
    assert "/local" in result
    assert not any("example.com" in p for p in result)


def test_mailto_skipped():
    assert _to_path("mailto:foo@bar.com", BASE) is None


def test_javascript_href_skipped():
    assert _to_path("javascript:void(0)", BASE) is None


def test_same_origin_absolute_href():
    assert _to_path(f"{BASE}/about", BASE) == "/about"


def test_relative_href():
    assert _to_path("/about", BASE) == "/about"


def test_depth_limit_prevents_deep_follow():
    # Depth=0 → visit seed, follow links to depth 1 only, stop before depth 2
    session = _mock_session({
        f"{BASE}/": [f"{BASE}/level1"],
        f"{BASE}/level1": [f"{BASE}/level2"],
        f"{BASE}/level2": [f"{BASE}/level3"],
        f"{BASE}/level3": [],
    })
    result = crawl_dom(session, ["/"], BASE, max_pages=10, max_depth=1)
    assert "/" in result
    assert "/level1" in result
    assert "/level2" not in result
```

- [ ] **Step 2: Run test to verify it fails**

```
py -m pytest tests/test_spider/test_dom_crawler.py -v
```
Expected: `ModuleNotFoundError: No module named 'vibe_iterator.spider.dom_crawler'`

- [ ] **Step 3: Implement `dom_crawler.py`**

```python
# vibe_iterator/spider/dom_crawler.py
"""BFS DOM crawler — follows <a href> links within the same origin."""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Callable
from urllib.parse import urlparse

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By

logger = logging.getLogger(__name__)

_PAGE_LOAD_TIMEOUT = 15  # seconds
_SETTLE_DELAY = 0.3      # seconds after navigation to let async requests fire


def crawl_dom(
    session: Any,
    seeds: list[str],
    base_url: str,
    max_pages: int = 30,
    max_depth: int = 3,
    on_page: Callable[[str, int], None] | None = None,
) -> list[str]:
    """BFS DOM crawl following <a href> links within the same origin.

    Args:
        session:   BrowserSession with a .driver attribute.
        seeds:     Initial URL paths to visit (e.g. ["/", "/login"]).
        base_url:  Origin to restrict links to (e.g. "http://localhost:3000").
        max_pages: Stop after visiting this many unique pages.
        max_depth: Do not follow links discovered deeper than this level.
        on_page:   Optional callable(url, depth) called after each page visit.
                   Used by discover_runner to run js_extractor per page.

    Returns:
        Ordered list of visited paths (not full URLs).
    """
    base = base_url.rstrip("/")
    driver = session.driver
    driver.set_page_load_timeout(_PAGE_LOAD_TIMEOUT)

    visited: set[str] = set()
    ordered: list[str] = []
    queue: deque[tuple[str, int]] = deque()

    for seed in seeds:
        path = _to_path(seed, base)
        if path and path not in visited:
            visited.add(path)
            queue.append((path, 0))

    while queue and len(ordered) < max_pages:
        path, depth = queue.popleft()
        url = base + path

        try:
            driver.get(url)
            time.sleep(_SETTLE_DELAY)
        except WebDriverException as exc:
            logger.debug("dom_crawler: failed to navigate to %s: %s", url, exc)
            continue

        ordered.append(path)

        if on_page is not None:
            try:
                on_page(url, depth)
            except Exception:
                pass

        if depth >= max_depth:
            continue

        try:
            elements = driver.find_elements(By.TAG_NAME, "a")
            for el in elements:
                href = _safe_attr(el, "href")
                if not href:
                    continue
                link_path = _to_path(href, base)
                if link_path and link_path not in visited:
                    visited.add(link_path)
                    queue.append((link_path, depth + 1))
        except Exception as exc:
            logger.debug("dom_crawler: link extraction failed on %s: %s", url, exc)

    return ordered


def _to_path(href: str, base: str) -> str | None:
    """Convert an href to a same-origin path, or None if external/non-navigable."""
    href = href.strip()
    if any(href.startswith(s) for s in ("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    try:
        parsed_base = urlparse(base)
        parsed = urlparse(href)
        if not parsed.netloc:
            # Relative path — strip query and fragment
            path = parsed.path.split("?")[0].split("#")[0]
            return path or "/"
        if parsed.netloc != parsed_base.netloc:
            return None
        path = parsed.path.split("?")[0].split("#")[0]
        return path or "/"
    except Exception:
        return None


def _safe_attr(el: Any, attr: str) -> str | None:
    try:
        return el.get_attribute(attr)
    except Exception:
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

```
py -m pytest tests/test_spider/test_dom_crawler.py -v
```
Expected: 9 PASSED

- [ ] **Step 5: Commit**

```
git add vibe_iterator/spider/dom_crawler.py tests/test_spider/test_dom_crawler.py
git commit -m "feat: add dom_crawler.py — BFS DOM crawl with configurable depth"
```

---

## Task 6: Config fields + `discover_runner.py` + tests

**Files:**
- Modify: `vibe_iterator/config.py` (add `spider_max_pages`, `spider_max_depth` to `Config` dataclass and `load_config`)
- Create: `vibe_iterator/engine/discover_runner.py`
- Create: `tests/test_spider/test_discover_runner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_spider/test_discover_runner.py
"""Tests for discover_runner.py — mocks all spider components, no browser."""
from __future__ import annotations
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from vibe_iterator.engine.discover_runner import run_discovery, load_sidecar, DiscoveryResult


def _cfg(max_pages: int = 30, max_depth: int = 3) -> MagicMock:
    c = MagicMock()
    c.target = "http://localhost:3000"
    c.pages = ["/", "/login"]
    c.spider_max_pages = max_pages
    c.spider_max_depth = max_depth
    return c


def _run(cfg, tmp_path: Path, sitemap=None, dom=None, js=None, api=None):
    session = MagicMock()
    network = MagicMock()
    network.get_requests.return_value = []
    with patch("vibe_iterator.engine.discover_runner.fetch_sitemap_routes",
               return_value=sitemap or []), \
         patch("vibe_iterator.engine.discover_runner.crawl_dom",
               return_value=dom or []), \
         patch("vibe_iterator.engine.discover_runner.extract_js_routes",
               return_value=js or []), \
         patch("vibe_iterator.engine.discover_runner.harvest_endpoints",
               return_value=api or []):
        return run_discovery(cfg, session, network, yaml_dir=tmp_path)


def test_sidecar_written():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _run(_cfg(), tmp_path, sitemap=["/about"], dom=["/contact"], api=["GET /api/users"])
        assert (tmp_path / "vibe-iterator.discovered.yaml").exists()


def test_pages_merged_and_sorted():
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(_cfg(), Path(tmp), sitemap=["/about"], dom=["/contact"])
        assert "/about" in result.pages
        assert "/contact" in result.pages
        assert result.pages == sorted(result.pages)


def test_api_endpoints_returned():
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(_cfg(), Path(tmp), api=["GET /api/users", "POST /api/auth/login"])
        assert "GET /api/users" in result.api_endpoints


def test_sidecar_written_when_empty():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _run(_cfg(), tmp_path)
        assert (tmp_path / "vibe-iterator.discovered.yaml").exists()


def test_load_sidecar_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _run(_cfg(), tmp_path, sitemap=["/a"], api=["GET /api/x"])
        loaded = load_sidecar(tmp_path)
        assert loaded is not None
        assert "/a" in loaded.pages
        assert "GET /api/x" in loaded.api_endpoints


def test_load_sidecar_absent_returns_none():
    with tempfile.TemporaryDirectory() as tmp:
        assert load_sidecar(Path(tmp)) is None
```

- [ ] **Step 2: Run tests to verify they fail**

```
py -m pytest tests/test_spider/test_discover_runner.py -v
```
Expected: `ModuleNotFoundError: No module named 'vibe_iterator.engine.discover_runner'`

- [ ] **Step 3: Add `spider_max_pages` and `spider_max_depth` to `Config`**

In `vibe_iterator/config.py`, find the `Config` dataclass (around line 47). Add two fields after `scanner_timeout_seconds`:

```python
    # Limits
    scanner_timeout_seconds: int = 60

    # Spider (endpoint discovery)
    spider_max_pages: int = 30
    spider_max_depth: int = 3
```

Then find `load_config()` and add the parsing block after the `scanner_timeout_seconds` block (around line 183). The full block to add:

```python
    # ------------------------------------------------------------------ #
    # Spider                                                               #
    # ------------------------------------------------------------------ #
    spider_raw = yaml_data.get("spider", {}) or {}
    try:
        spider_max_pages = int(spider_raw.get("max_pages", 30))
        spider_max_depth = int(spider_raw.get("max_depth", 3))
    except (TypeError, ValueError) as exc:
        raise ConfigError("spider.max_pages and spider.max_depth must be integers.") from exc
    if spider_max_pages < 1:
        raise ConfigError("spider.max_pages must be at least 1.")
    if spider_max_depth < 0:
        raise ConfigError("spider.max_depth must be 0 or greater.")
```

Then add `spider_max_pages=spider_max_pages, spider_max_depth=spider_max_depth,` to the `return Config(...)` call at the end of `load_config`.

The full updated `return Config(...)` block (around line 228):

```python
    return Config(
        target=target,
        test_email=test_email,
        test_password=test_password,
        test_email_2=test_email_2,
        test_password_2=test_password_2,
        supabase_url=supabase_url,
        supabase_anon_key=supabase_anon_key,
        pages=pages,
        stages=stages,
        stack=stack,
        port=port,
        scanner_timeout_seconds=scanner_timeout_seconds,
        spider_max_pages=spider_max_pages,
        spider_max_depth=spider_max_depth,
    )
```

- [ ] **Step 4: Implement `discover_runner.py`**

```python
# vibe_iterator/engine/discover_runner.py
"""Orchestrate spider components and write vibe-iterator.discovered.yaml."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

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
    seeds = list(dict.fromkeys(sitemap_routes + config.pages))
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
        )
    except Exception as exc:
        logger.warning("Could not load sidecar %s: %s", sidecar_path, exc)
        return None
```

- [ ] **Step 5: Run tests to verify they pass**

```
py -m pytest tests/test_spider/test_discover_runner.py -v
```
Expected: 6 PASSED

- [ ] **Step 6: Commit**

```
git add vibe_iterator/config.py vibe_iterator/engine/discover_runner.py tests/test_spider/test_discover_runner.py
git commit -m "feat: add discover_runner.py, DiscoveryResult, and spider_max_pages/max_depth config fields"
```

---

## Task 7: Full suite verification

**Files:** None — verification only

- [ ] **Step 1: Run all new spider tests together**

```
py -m pytest tests/test_spider/ -v
```
Expected: all PASS (sitemap: 4, endpoint_harvester: 7, js_extractor: 6, dom_crawler: 9, discover_runner: 6 = 32 tests)

- [ ] **Step 2: Run full test suite to check for regressions**

```
py -m pytest tests/ -q
```
Expected: green, no regressions (existing 298 + 32 new = ~330 passed, 1 skipped)

- [ ] **Step 3: Commit if any fixes were needed**

If tests reveal issues, fix them and commit:
```
git add -p
git commit -m "fix: resolve spider test regressions"
```

- [ ] **Step 4: Final commit**

```
git add .
git commit -m "feat: complete spider module — sitemap, dom_crawler, js_extractor, endpoint_harvester, discover_runner"
```

---

**Plan 1 complete. Plan 2 (`2026-05-29-endpoint-discovery-plan-2-engine-dashboard.md`) wires this into the engine, config loading, API, dashboard, and docs.**
