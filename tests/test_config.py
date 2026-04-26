"""Tests for configuration loading priority."""

from __future__ import annotations

from vibe_iterator.config import load_config


def test_target_priority_cli_then_env_then_yaml(monkeypatch) -> None:
    """Target resolution should match CONFIG.md: CLI > env > YAML."""
    from pathlib import Path

    yaml_path = Path("tests/.tmp-vibe-iterator.config.yaml")
    env_path = Path("tests/.tmp-missing.env")
    yaml_path.write_text("target: http://yaml.example\n", encoding="utf-8")

    try:
        monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "test@example.com")
        monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "password")
        monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://env.example")

        env_wins = load_config(yaml_path=yaml_path, env_path=env_path)
        cli_wins = load_config(
            target_override="http://cli.example",
            yaml_path=yaml_path,
            env_path=env_path,
        )

        assert env_wins.target == "http://env.example"
        assert cli_wins.target == "http://cli.example"
    finally:
        yaml_path.unlink(missing_ok=True)
