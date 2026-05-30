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
