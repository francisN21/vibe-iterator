"""Guard against common UTF-8 mojibake in user-facing docs and UI files."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
USER_FACING_GLOBS = [
    "README.md",
    "docs/*.md",
    ".env.example",
    "vibe-iterator.config.yaml.example",
    "vibe_iterator/server/static/*.html",
    "vibe_iterator/server/static/js/*.js",
    "vibe_iterator/server/static/css/*.css",
    "vibe_iterator/report/templates/*.j2",
]
MOJIBAKE_MARKERS = ("â", "ð", "Ã", "Â", "\ufffd")


def test_user_facing_files_do_not_contain_common_mojibake() -> None:
    offenders: list[str] = []
    for pattern in USER_FACING_GLOBS:
        for path in ROOT.glob(pattern):
            text = path.read_text(encoding="utf-8")
            if any(marker in text for marker in MOJIBAKE_MARKERS):
                offenders.append(str(path.relative_to(ROOT)))

    assert offenders == []
