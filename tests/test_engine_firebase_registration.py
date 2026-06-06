"""Confirm all five Firebase scanners are registered in _SCANNER_MODULE_MAP."""
from vibe_iterator.engine.runner import _SCANNER_MODULE_MAP


def test_firebase_scanners_registered() -> None:
    for name in ["firebase_firestore", "firebase_rtdb", "firebase_storage",
                 "firebase_auth", "firebase_functions"]:
        assert name in _SCANNER_MODULE_MAP, f"{name} not in _SCANNER_MODULE_MAP"
        assert _SCANNER_MODULE_MAP[name].startswith("vibe_iterator.scanners.")


def test_rate_limit_scanner_registered() -> None:
    assert _SCANNER_MODULE_MAP["rate_limit_check"] == "vibe_iterator.scanners.rate_limit_check"
