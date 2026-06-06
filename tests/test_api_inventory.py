from __future__ import annotations

from vibe_iterator.api_inventory import ApiIntelligenceConfig, resolve_mode


def test_auto_resolves_public_domain_to_safe() -> None:
    cfg = ApiIntelligenceConfig(mode="auto")
    assert resolve_mode("https://example.com", cfg) == "safe"


def test_auto_resolves_localhost_to_aggressive() -> None:
    cfg = ApiIntelligenceConfig(mode="auto")
    assert resolve_mode("http://localhost:3000", cfg) == "aggressive"


def test_auto_resolves_loopback_and_private_ip_to_aggressive() -> None:
    cfg = ApiIntelligenceConfig(mode="auto")
    assert resolve_mode("http://127.0.0.1:3000", cfg) == "aggressive"
    assert resolve_mode("http://10.14.0.2:3000", cfg) == "aggressive"
    assert resolve_mode("http://192.168.1.10:3000", cfg) == "aggressive"


def test_auto_resolves_local_hostname_to_aggressive() -> None:
    cfg = ApiIntelligenceConfig(mode="auto")
    assert resolve_mode("http://my-app.local:3000", cfg) == "aggressive"


def test_user_mode_override_wins_over_auto() -> None:
    assert resolve_mode("https://example.com", ApiIntelligenceConfig(mode="aggressive")) == "aggressive"
    assert resolve_mode("http://localhost:3000", ApiIntelligenceConfig(mode="safe")) == "safe"
    assert resolve_mode("http://localhost:3000", ApiIntelligenceConfig(mode="off")) == "off"
