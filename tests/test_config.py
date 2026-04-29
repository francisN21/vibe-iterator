"""Tests for configuration loading, stage profiles, and priority resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibe_iterator.config import load_config, _DEFAULT_STAGES, _VALID_SCANNER_NAMES


# --------------------------------------------------------------------------- #
# Priority resolution                                                          #
# --------------------------------------------------------------------------- #

def test_target_priority_cli_then_env_then_yaml(monkeypatch) -> None:
    """Target resolution should match CONFIG.md: CLI > env > YAML."""
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


def test_port_override(monkeypatch) -> None:
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")
    cfg = load_config(port_override=9999)
    assert cfg.port == 9999


def test_missing_required_fields_raises(monkeypatch) -> None:
    from vibe_iterator.config import ConfigError
    monkeypatch.delenv("VIBE_ITERATOR_TEST_EMAIL", raising=False)
    monkeypatch.delenv("VIBE_ITERATOR_TEST_PASSWORD", raising=False)
    monkeypatch.delenv("VIBE_ITERATOR_TARGET", raising=False)
    with pytest.raises(ConfigError):
        load_config()


# --------------------------------------------------------------------------- #
# Stage profiles                                                               #
# --------------------------------------------------------------------------- #

def test_dev_stage_has_correct_scanners() -> None:
    expected = {"data_leakage", "auth_check", "client_tampering"}
    assert set(_DEFAULT_STAGES["dev"]) == expected


def test_pre_deploy_includes_supabase_scanners() -> None:
    pre = set(_DEFAULT_STAGES["pre-deploy"])
    assert "rls_bypass" in pre
    assert "tier_escalation" in pre
    assert "bucket_limits" in pre
    assert "sql_injection" in pre
    assert "xss_check" in pre
    assert "api_exposure" in pre


def test_post_deploy_includes_cors() -> None:
    assert "cors_check" in _DEFAULT_STAGES["post-deploy"]


def test_all_stage_contains_every_scanner() -> None:
    all_scanners = set(_DEFAULT_STAGES["all"])
    assert all_scanners == _VALID_SCANNER_NAMES


def test_dev_is_subset_of_pre_deploy() -> None:
    dev = set(_DEFAULT_STAGES["dev"])
    pre = set(_DEFAULT_STAGES["pre-deploy"])
    assert dev.issubset(pre)


def test_scanners_for_stage_returns_list(monkeypatch) -> None:
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")
    cfg = load_config()
    assert isinstance(cfg.scanners_for_stage("dev"), list)
    assert len(cfg.scanners_for_stage("dev")) > 0
    assert cfg.scanners_for_stage("nonexistent") == []


# --------------------------------------------------------------------------- #
# YAML config override                                                         #
# --------------------------------------------------------------------------- #

def test_yaml_stage_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")

    yaml_file = tmp_path / "vibe-iterator.config.yaml"
    yaml_file.write_text(
        "stages:\n  dev:\n    scanners: [data_leakage, auth_check]\n",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path=yaml_file)
    assert cfg.stages["dev"] == ["data_leakage", "auth_check"]


def test_yaml_invalid_scanner_raises(monkeypatch, tmp_path) -> None:
    from vibe_iterator.config import ConfigError
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")

    yaml_file = tmp_path / "vibe-iterator.config.yaml"
    yaml_file.write_text(
        "stages:\n  dev:\n    scanners: [not_a_real_scanner]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="Unknown scanner"):
        load_config(yaml_path=yaml_file)


# --------------------------------------------------------------------------- #
# Stack config                                                                 #
# --------------------------------------------------------------------------- #

def test_stack_from_yaml(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")

    yaml_file = tmp_path / "vibe-iterator.config.yaml"
    yaml_file.write_text(
        "stack:\n  backend: supabase\n  auth: supabase-auth\n  storage: supabase\n",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path=yaml_file)
    assert cfg.stack.backend == "supabase"
    assert cfg.stack.detection_source == "manually-configured"


def test_second_account_configured_true(monkeypatch) -> None:
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL_2", "t2@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD_2", "pw2")
    cfg = load_config()
    assert cfg.second_account_configured is True


def test_second_account_configured_false_when_partial(monkeypatch) -> None:
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "t@e.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    monkeypatch.setenv("VIBE_ITERATOR_TARGET", "http://localhost:3000")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL_2", "t2@e.com")
    monkeypatch.delenv("VIBE_ITERATOR_TEST_PASSWORD_2", raising=False)
    import warnings
    with warnings.catch_warnings(record=True):
        cfg = load_config()
    assert cfg.second_account_configured is False
