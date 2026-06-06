"""API intelligence configuration and mode resolution."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

_MODES = {"auto", "safe", "aggressive", "off"}


@dataclass
class ApiIntelligenceConfig:
    mode: str = "auto"
    max_route_candidates: int = 200
    max_methods_per_route: int = 6
    max_hidden_params_per_endpoint: int = 20
    request_timeout_seconds: int = 3
    total_timeout_seconds: int = 45
    route_wordlist: str = "builtin"
    param_wordlist: str = "builtin"

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise ValueError(f"api_intelligence.mode must be one of {sorted(_MODES)}")


def resolve_mode(target: str, config: ApiIntelligenceConfig) -> str:
    if config.mode != "auto":
        return config.mode

    host = (urlparse(target).hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return "aggressive"

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private:
            return "aggressive"
    except ValueError:
        pass

    return "safe"
