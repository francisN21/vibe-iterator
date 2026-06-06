"""API intelligence configuration and mode resolution."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
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


@dataclass(frozen=True)
class ApiParameter:
    name: str
    location: str
    observed_values: list[str] = field(default_factory=list)
    source: str = "observed"
    confidence: str = "confirmed"
    sensitive_hint: bool = False


@dataclass(frozen=True)
class ApiEndpoint:
    method: str
    url: str
    origin: str
    path: str
    normalized_path: str
    status_codes: list[int] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    request_content_types: list[str] = field(default_factory=list)
    auth_observed: bool = False
    response_auth_required_hint: bool = False
    parameters: list[ApiParameter] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    confidence: str = "confirmed"


@dataclass(frozen=True)
class ApiInventory:
    generated_at: str
    mode: str
    resolved_mode: str
    target: str
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


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


def parameter_to_dict(parameter: ApiParameter) -> dict[str, Any]:
    return {
        "name": parameter.name,
        "location": parameter.location,
        "observed_values": list(parameter.observed_values),
        "source": parameter.source,
        "confidence": parameter.confidence,
        "sensitive_hint": parameter.sensitive_hint,
    }


def parameter_from_dict(data: dict[str, Any]) -> ApiParameter:
    observed_values = data.get("observed_values", [])
    if isinstance(observed_values, list):
        values = [str(value) for value in observed_values]
    elif observed_values is None:
        values = []
    else:
        values = [str(observed_values)]

    return ApiParameter(
        name=str(data.get("name", "")),
        location=str(data.get("location", "")),
        observed_values=values,
        source=str(data.get("source", "observed")),
        confidence=str(data.get("confidence", "confirmed")),
        sensitive_hint=_as_bool(data.get("sensitive_hint", False)),
    )


def endpoint_to_dict(endpoint: ApiEndpoint) -> dict[str, Any]:
    return {
        "method": endpoint.method,
        "url": endpoint.url,
        "origin": endpoint.origin,
        "path": endpoint.path,
        "normalized_path": endpoint.normalized_path,
        "status_codes": list(endpoint.status_codes),
        "content_types": list(endpoint.content_types),
        "request_content_types": list(endpoint.request_content_types),
        "auth_observed": endpoint.auth_observed,
        "response_auth_required_hint": endpoint.response_auth_required_hint,
        "parameters": [parameter_to_dict(parameter) for parameter in endpoint.parameters],
        "sources": list(endpoint.sources),
        "risk_tags": list(endpoint.risk_tags),
        "confidence": endpoint.confidence,
    }


def endpoint_from_dict(data: dict[str, Any]) -> ApiEndpoint:
    path = str(data.get("path", ""))
    return ApiEndpoint(
        method=str(data.get("method", "GET")),
        url=str(data.get("url", "")),
        origin=str(data.get("origin", "")),
        path=path,
        normalized_path=str(data.get("normalized_path", path)),
        status_codes=_status_codes_from_dict(data.get("status_codes", [])),
        content_types=_string_list(data.get("content_types", [])),
        request_content_types=_string_list(data.get("request_content_types", [])),
        auth_observed=_as_bool(data.get("auth_observed", False)),
        response_auth_required_hint=_as_bool(data.get("response_auth_required_hint", False)),
        parameters=[parameter_from_dict(parameter) for parameter in data.get("parameters", [])],
        sources=_string_list(data.get("sources", [])),
        risk_tags=_string_list(data.get("risk_tags", [])),
        confidence=str(data.get("confidence", "confirmed")),
    )


def inventory_to_dict(inventory: ApiInventory) -> dict[str, Any]:
    return {
        "generated_at": inventory.generated_at,
        "mode": inventory.mode,
        "resolved_mode": inventory.resolved_mode,
        "target": inventory.target,
        "endpoints": [endpoint_to_dict(endpoint) for endpoint in inventory.endpoints],
        "summary": dict(inventory.summary),
        "warnings": list(inventory.warnings),
    }


def inventory_from_dict(data: dict[str, Any] | None) -> ApiInventory | None:
    if data is None:
        return None

    return ApiInventory(
        generated_at=str(data.get("generated_at", "")),
        mode=str(data.get("mode", "")),
        resolved_mode=str(data.get("resolved_mode", "")),
        target=str(data.get("target", "")),
        endpoints=[endpoint_from_dict(endpoint) for endpoint in data.get("endpoints", [])],
        summary={str(key): int(value) for key, value in data.get("summary", {}).items()},
        warnings=_string_list(data.get("warnings", [])),
    )


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _status_codes_from_dict(value: Any) -> list[int]:
    status_codes = []
    for status_code in value if isinstance(value, list) else []:
        try:
            status_codes.append(int(status_code))
        except (TypeError, ValueError):
            continue
    return status_codes


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
        return False
    if value in {1, 1.0}:
        return True
    if value in {0, 0.0, None}:
        return False
    return False
