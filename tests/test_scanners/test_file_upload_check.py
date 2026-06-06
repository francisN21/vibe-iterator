"""Generic file upload scanner tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.fixtures.vulnerable_app.app import VulnerableApp
from vibe_iterator.scanners.base import Severity
from vibe_iterator.scanners.file_upload_check import (
    Scanner,
    _build_multipart,
    _discover_upload_endpoints,
    _has_upload_acceptance,
)


@pytest.fixture(scope="module")
def vuln_app():
    with VulnerableApp() as app:
        yield app


def _make_config(target: str = "http://localhost:9999", backend_url: str | None = None) -> MagicMock:
    cfg = MagicMock()
    cfg.target = target
    cfg.backend_url = backend_url
    cfg.stack.backend = "custom"
    return cfg


def _make_network(requests: list) -> MagicMock:
    net = MagicMock()
    net.get_requests.return_value = requests
    return net


def _make_req(url: str, *, method: str = "POST", headers: dict | None = None) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.status_code = 200
    req.response_body = ""
    req.post_data = None
    req.headers = headers if headers is not None else {"Content-Type": "multipart/form-data; boundary=x"}
    req.response_mime_type = "application/json"
    return req


def _run(vuln_app, network_requests) -> list:
    scanner = Scanner()
    config = _make_config(vuln_app.base_url)
    net = _make_network(network_requests)
    return scanner.run(session=None, listeners={"network": net}, config=config)


def test_file_upload_detects_executable_mime_polyglot_and_eicar_acceptance(vuln_app) -> None:
    req = _make_req(vuln_app.base_url + "/api/upload")

    findings = _run(vuln_app, [req])

    proof_qualities = {f.evidence["proof_quality"] for f in findings}
    assert proof_qualities == {
        "executable_extension_upload_accepted",
        "dangerous_mime_upload_accepted",
        "polyglot_svg_html_upload_accepted",
        "eicar_test_string_upload_accepted",
    }
    assert all(f.severity in {Severity.HIGH, Severity.MEDIUM} for f in findings)
    executable = next(f for f in findings if f.evidence["proof_quality"] == "executable_extension_upload_accepted")
    assert executable.evidence["upload_evidence"]["filename"].endswith(".php")
    assert executable.evidence["acceptance_evidence"]["json_path"] == "accepted"


def test_no_finding_for_rejected_or_preview_uploads(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/upload")
    net = _make_network([req])

    def fake_send(url, filename, content_type, content, headers=None, timeout=8):
        return 200, {"content-type": "application/json"}, '{"preview":true,"accepted":false}'

    monkeypatch.setattr("vibe_iterator.scanners.file_upload_check._send_upload_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_no_finding_for_403_upload_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config()
    req = _make_req("http://localhost:9999/api/upload")
    net = _make_network([req])

    def fake_send(url, filename, content_type, content, headers=None, timeout=8):
        return 403, {"content-type": "application/json"}, '{"error":"blocked"}'

    monkeypatch.setattr("vibe_iterator.scanners.file_upload_check._send_upload_probe", fake_send)

    assert scanner.run(session=None, listeners={"network": net}, config=config) == []


def test_backend_url_routes_file_upload_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Scanner()
    config = _make_config("http://localhost:3000", backend_url="http://localhost:4001")
    req = _make_req("http://localhost:3000/api/upload")
    net = _make_network([req])
    calls: list[tuple[str, str, str, bytes, dict | None]] = []

    def fake_send(url, filename, content_type, content, headers=None, timeout=8):
        calls.append((url, filename, content_type, content, headers))
        return 201, {"content-type": "application/json"}, '{"accepted":true,"stored":true}'

    monkeypatch.setattr("vibe_iterator.scanners.file_upload_check._send_upload_probe", fake_send)

    findings = scanner.run(session=None, listeners={"network": net}, config=config)

    assert len(findings) == 4
    assert calls
    assert calls[0][0] == "http://localhost:4001/api/upload"
    assert calls[0][4] == {"Origin": "http://localhost:3000"}


def test_discovery_filters_static_non_post_third_party_duplicates_and_unknown_paths() -> None:
    target = "http://localhost:9999"
    requests = [
        _make_req(target + "/api/upload"),
        _make_req(target + "/api/upload"),
        _make_req(target + "/api/upload", method="GET"),
        _make_req(target + "/app.js"),
        _make_req(target + "/api/profile", headers={"Content-Type": "multipart/form-data"}),
        _make_req("https://third-party.example/api/upload"),
    ]
    net = _make_network(requests)

    assert _discover_upload_endpoints(net, target) == [requests[0]]


def test_upload_helpers_and_acceptance_classifier() -> None:
    content_type, body = _build_multipart("proof.php", "application/x-php", b"<?php echo 'x'; ?>")

    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'filename="proof.php"' in body
    assert b"application/x-php" in body
    assert _has_upload_acceptance('{"accepted":true}') == ("accepted", True)
    assert _has_upload_acceptance('{"data":{"stored":true}}') == ("data.stored", True)
    assert _has_upload_acceptance('{"files":[{"uploaded":true}]}') == ("files[0].uploaded", True)
    assert _has_upload_acceptance('{"preview":true,"accepted":false}') is None
    assert _has_upload_acceptance("not json") is None


def test_scanner_metadata() -> None:
    s = Scanner()
    assert s.name == "file_upload_check"
    assert s.category == "File Upload"
    assert "pre-deploy" in s.stages
    assert s.requires_stack == ["any"]
    assert s.requires_second_account is False
