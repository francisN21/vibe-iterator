"""Static dashboard contracts that keep frontend controls aligned with config."""

from pathlib import Path

STATIC_DIR = Path("vibe_iterator/server/static")


def test_home_stage_picker_exposes_firebase_stage() -> None:
    app_js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")

    assert "key: 'firebase'" in app_js


def test_home_stage_picker_exposes_safe_live_stage() -> None:
    app_js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")

    assert "key: 'safe-live'" in app_js
    assert "label: 'SAFE LIVE'" in app_js
    assert "tag: 'Smoke-safe'" in app_js


def test_firebase_panel_visibility_uses_configured_stage_not_stack_detection_only() -> None:
    app_js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")

    assert "const hasFirebaseStage = !!(configMeta && configMeta.stages && configMeta.stages.firebase);" in app_js
    assert "panel.hidden = !hasFirebaseStage;" in app_js


def test_firebase_panel_redirect_preserves_stage_query() -> None:
    app_js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")

    assert "window.location.href = '/scan?stage=firebase';" in app_js
