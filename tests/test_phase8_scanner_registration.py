"""Phase 8 scanner registry/config/server metadata contracts."""

from vibe_iterator.config import _DEFAULT_STAGES, _VALID_SCANNER_NAMES
from vibe_iterator.engine.runner import _SCANNER_MODULE_MAP
from vibe_iterator.server.routes import _SCANNER_META


def test_open_redirect_scanner_registered_and_exposed() -> None:
    name = "open_redirect_check"

    assert _SCANNER_MODULE_MAP[name] == "vibe_iterator.scanners.open_redirect_check"
    assert name in _VALID_SCANNER_NAMES
    assert name in _DEFAULT_STAGES["pre-deploy"]
    assert name in _DEFAULT_STAGES["all"]
    assert name not in _DEFAULT_STAGES["post-deploy"]
    assert _SCANNER_META[name]["label"] == "Open Redirect"


def test_path_traversal_scanner_registered_and_exposed() -> None:
    name = "path_traversal_check"

    assert _SCANNER_MODULE_MAP[name] == "vibe_iterator.scanners.path_traversal_check"
    assert name in _VALID_SCANNER_NAMES
    assert name in _DEFAULT_STAGES["pre-deploy"]
    assert name in _DEFAULT_STAGES["all"]
    assert name not in _DEFAULT_STAGES["post-deploy"]
    assert _SCANNER_META[name]["label"] == "Path Traversal"


def test_ssrf_scanner_registered_and_exposed() -> None:
    name = "ssrf_check"

    assert _SCANNER_MODULE_MAP[name] == "vibe_iterator.scanners.ssrf_check"
    assert name in _VALID_SCANNER_NAMES
    assert name in _DEFAULT_STAGES["pre-deploy"]
    assert name in _DEFAULT_STAGES["all"]
    assert name not in _DEFAULT_STAGES["post-deploy"]
    assert _SCANNER_META[name]["label"] == "SSRF"


def test_csrf_scanner_registered_and_exposed() -> None:
    name = "csrf_check"

    assert _SCANNER_MODULE_MAP[name] == "vibe_iterator.scanners.csrf_check"
    assert name in _VALID_SCANNER_NAMES
    assert name in _DEFAULT_STAGES["pre-deploy"]
    assert name in _DEFAULT_STAGES["all"]
    assert name not in _DEFAULT_STAGES["post-deploy"]
    assert _SCANNER_META[name]["label"] == "CSRF"
