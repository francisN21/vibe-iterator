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
