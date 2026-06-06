"""API intelligence configuration and mode resolution."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlparse

_MODES = {"auto", "safe", "aggressive", "off"}
_ID_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$"
)
_API_PREFIXES = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/")
_AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key"}
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_PARAM_NAMES = {"role", "admin", "isadmin", "permissions", "tenant_id", "org_id", "user_id"}
_RISK_KEYWORDS = {
    "graphql": ("graphql",),
    "upload": ("upload", "uploads"),
    "webhook": ("webhook", "webhooks"),
    "admin": ("admin",),
    "redirect": ("redirect", "return_url", "next_url", "callback_url"),
    "file": ("file", "filename", "path", "download"),
    "ssrf": ("url", "uri", "endpoint", "host", "callback", "webhook"),
}


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


def build_inventory_from_network(
    network: Any,
    target: str,
    mode: str,
    resolved_mode: str,
) -> ApiInventory:
    endpoints_by_key: dict[tuple[str, str, str], ApiEndpoint] = {}

    get_requests = getattr(network, "get_requests", None)
    requests = get_requests() if callable(get_requests) else []
    for req in requests:
        endpoint = endpoint_from_request(req, target)
        if endpoint is None:
            continue

        key = (endpoint.origin, endpoint.method, endpoint.normalized_path)
        if key in endpoints_by_key:
            endpoints_by_key[key] = merge_endpoints(endpoints_by_key[key], endpoint)
        else:
            endpoints_by_key[key] = endpoint

    endpoints = sorted(endpoints_by_key.values(), key=lambda endpoint: (endpoint.normalized_path, endpoint.method))
    return ApiInventory(
        generated_at=datetime.now(UTC).isoformat(),
        mode=mode,
        resolved_mode=resolved_mode,
        target=target,
        endpoints=endpoints,
        summary=_inventory_summary(endpoints),
        warnings=aggressive_warnings(resolved_mode),
    )


def aggressive_warnings(resolved_mode: str) -> list[str]:
    if resolved_mode == "aggressive":
        return ["Aggressive API intelligence may send additional probing requests."]
    return []


def endpoint_from_request(req: Any, target: str) -> ApiEndpoint | None:
    url = getattr(req, "url", "")
    if not isinstance(url, str):
        return None

    parsed = urlparse(url)
    path = parsed.path or "/"
    if not _is_api_path(path):
        return None

    method = getattr(req, "method", "GET")
    method = method.upper() if isinstance(method, str) else "GET"
    headers = _dict_attr(req, "headers")
    response_headers = _dict_attr(req, "response_headers")
    parameters = _extract_parameters(req)

    status_codes = []
    status_code = getattr(req, "status_code", None)
    if isinstance(status_code, int):
        status_codes.append(status_code)

    content_types = []
    response_content_type = _content_type(response_headers)
    if response_content_type:
        content_types.append(response_content_type)

    request_content_types = []
    request_content_type = _content_type(headers)
    if request_content_type:
        request_content_types.append(request_content_type)

    auth_observed = any(name.lower() in _AUTH_HEADER_NAMES for name in headers)
    risk_tags = _risk_tags(path, method, parameters)

    return ApiEndpoint(
        method=method,
        url=url,
        origin=_origin_for_target(url),
        path=path,
        normalized_path=_normalize_path(path),
        status_codes=status_codes,
        content_types=content_types,
        request_content_types=request_content_types,
        auth_observed=auth_observed,
        response_auth_required_hint=bool(status_codes and status_codes[0] in {401, 403}),
        parameters=parameters,
        sources=[f"network:{url}"],
        risk_tags=risk_tags,
        confidence="confirmed",
    )


def merge_endpoints(existing: ApiEndpoint, incoming: ApiEndpoint) -> ApiEndpoint:
    parameters = _merge_parameters(existing.parameters, incoming.parameters)
    risk_tags = _unique_sorted([*existing.risk_tags, *incoming.risk_tags])

    return ApiEndpoint(
        method=existing.method,
        url=existing.url,
        origin=existing.origin,
        path=existing.path,
        normalized_path=existing.normalized_path,
        status_codes=_unique_sorted_int([*existing.status_codes, *incoming.status_codes]),
        content_types=_unique_preserve([*existing.content_types, *incoming.content_types]),
        request_content_types=_unique_preserve([*existing.request_content_types, *incoming.request_content_types]),
        auth_observed=existing.auth_observed or incoming.auth_observed,
        response_auth_required_hint=existing.response_auth_required_hint or incoming.response_auth_required_hint,
        parameters=parameters,
        sources=_unique_preserve([*existing.sources, *incoming.sources]),
        risk_tags=risk_tags,
        confidence=existing.confidence,
    )


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


def _origin_for_target(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _normalize_path(path: str) -> str:
    normalized_segments = []
    for segment in path.split("/"):
        normalized_segments.append("{id}" if _ID_SEGMENT_RE.match(segment) else segment)
    return "/".join(normalized_segments)


def _is_api_path(path: str) -> bool:
    normalized = path.lower()
    return any(normalized == prefix.rstrip("/") or normalized.startswith(prefix) for prefix in _API_PREFIXES)


def _extract_parameters(req: Any) -> list[ApiParameter]:
    url = getattr(req, "url", "")
    parsed = urlparse(url if isinstance(url, str) else "")
    parameters: dict[tuple[str, str], ApiParameter] = {}

    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        _add_parameter(parameters, name, "query", value)

    headers = _dict_attr(req, "headers")
    post_data = getattr(req, "post_data", None)
    if not isinstance(post_data, str) or not post_data:
        return sorted(parameters.values(), key=lambda parameter: (parameter.location, parameter.name))

    content_type = _content_type(headers)
    if _is_json_body(content_type, post_data):
        try:
            body = json.loads(post_data)
        except json.JSONDecodeError:
            body = None
        if isinstance(body, dict):
            for name, value in body.items():
                _add_parameter(parameters, str(name), "body", _observed_value(value))
    elif content_type == "application/x-www-form-urlencoded":
        for name, value in parse_qsl(post_data, keep_blank_values=True):
            _add_parameter(parameters, name, "body", value)

    return sorted(parameters.values(), key=lambda parameter: (parameter.location, parameter.name))


def _risk_tags(path: str, method: str, parameters: list[ApiParameter]) -> list[str]:
    terms = [path.lower(), *(parameter.name.lower() for parameter in parameters)]
    tags = []
    if method in _STATE_METHODS:
        tags.append("state_changing")

    for tag, keywords in _RISK_KEYWORDS.items():
        if any(keyword in term for keyword in keywords for term in terms):
            tags.append(tag)

    return _unique_sorted(tags)


def _inventory_summary(endpoints: list[ApiEndpoint]) -> dict[str, int]:
    return {
        "endpoints": len(endpoints),
        "auth_observed": sum(1 for endpoint in endpoints if endpoint.auth_observed),
        "hidden_parameters": sum(
            1
            for endpoint in endpoints
            for parameter in endpoint.parameters
            if parameter.source not in {"observed", ""}
        ),
        "state_changing": sum(1 for endpoint in endpoints if "state_changing" in endpoint.risk_tags),
    }


def _merge_parameters(existing: list[ApiParameter], incoming: list[ApiParameter]) -> list[ApiParameter]:
    merged: dict[tuple[str, str], ApiParameter] = {(parameter.location, parameter.name): parameter for parameter in existing}
    for parameter in incoming:
        key = (parameter.location, parameter.name)
        if key not in merged:
            merged[key] = parameter
            continue

        current = merged[key]
        merged[key] = ApiParameter(
            name=current.name,
            location=current.location,
            observed_values=_unique_preserve([*current.observed_values, *parameter.observed_values]),
            source=current.source,
            confidence=current.confidence,
            sensitive_hint=current.sensitive_hint or parameter.sensitive_hint,
        )

    return sorted(merged.values(), key=lambda parameter: (parameter.location, parameter.name))


def _add_parameter(parameters: dict[tuple[str, str], ApiParameter], name: str, location: str, value: str) -> None:
    key = (location, name)
    sensitive_hint = name.lower() in _SENSITIVE_PARAM_NAMES
    if key in parameters:
        current = parameters[key]
        parameters[key] = ApiParameter(
            name=current.name,
            location=current.location,
            observed_values=_unique_preserve([*current.observed_values, value]),
            source=current.source,
            confidence=current.confidence,
            sensitive_hint=current.sensitive_hint or sensitive_hint,
        )
        return

    parameters[key] = ApiParameter(
        name=name,
        location=location,
        observed_values=[value] if value else [],
        source="observed",
        confidence="confirmed",
        sensitive_hint=sensitive_hint,
    )


def _dict_attr(value: Any, attr_name: str) -> dict[str, Any]:
    attr = getattr(value, attr_name, {})
    return attr if isinstance(attr, dict) else {}


def _content_type(headers: dict[str, Any]) -> str:
    for name, value in headers.items():
        if name.lower() == "content-type" and isinstance(value, str):
            return value.split(";", 1)[0].strip().lower()
    return ""


def _is_json_body(content_type: str, post_data: str) -> bool:
    stripped = post_data.lstrip()
    return (
        content_type == "application/json"
        or content_type.endswith("+json")
        or (not content_type and stripped.startswith("{"))
    )


def _observed_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, bool | int | float):
        return str(value)
    return json.dumps(value, sort_keys=True)


def _unique_preserve(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))


def _unique_sorted_int(values: list[int]) -> list[int]:
    return sorted(set(values))


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
