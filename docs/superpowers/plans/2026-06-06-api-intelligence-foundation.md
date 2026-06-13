# API Intelligence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a shared API inventory layer that discovers method-aware endpoints, finds hidden parameters, reports the API surface in results, and feeds richer targets into existing scanners.

**Architecture:** Add a focused `vibe_iterator/api_inventory.py` module for config, mode resolution, dataclasses, serialization, and inventory building. The engine builds an `ApiInventory` from network traffic and discovery data, injects it as `listeners["api_inventory"]`, and serializes it through `DiscoveryResult` and `ScanResult`. Scanners migrate incrementally and keep network-listener fallback behavior.

**Tech Stack:** Python dataclasses, urllib, YAML sidecar serialization, existing FastAPI/dashboard JSON result flow, existing scanner `listeners` contract, pytest, ruff.

---

## File Map

- Create: `vibe_iterator/api_inventory.py`
  - API intelligence config dataclass, mode resolver, endpoint/parameter/inventory dataclasses, inventory serializer/deserializer, network-to-inventory builder, sidecar-string parser, hidden-parameter inference, bounded aggressive probes.
- Modify: `vibe_iterator/config.py`
  - Parse `api_intelligence` YAML config and expose `Config.api_intelligence`.
- Modify: `vibe_iterator/engine/discover_runner.py`
  - Add `DiscoveryResult.api_inventory`, build inventory during discover, write/read structured sidecar.
- Modify: `vibe_iterator/engine/runner.py`
  - Build inventory after crawl in normal scan stages, inject `listeners["api_inventory"]`, store inventory on `ScanResult.discovered_surface`.
- Modify: `vibe_iterator/history.py`
  - Serialize structured `api_inventory` in saved JSON results.
- Modify: `vibe_iterator/server/static/js/app.js`
  - Add API Inventory rendering using existing results payload.
- Modify: `vibe_iterator/server/static/index.html`
  - Add API intelligence mode control and aggressive warning text near scan launch controls.
- Modify: `vibe_iterator/server/routes.py`
  - Accept optional `api_intelligence_mode` in scan start request and pass it to config/runtime override.
- Modify: `vibe_iterator/report/generator.py` and `vibe_iterator/report/templates/report.html.j2`
  - Include API inventory summary in exported HTML reports.
- Modify first scanner wave:
  - `vibe_iterator/scanners/mass_assignment.py`
  - `vibe_iterator/scanners/idor_check.py`
  - `vibe_iterator/scanners/api_exposure.py`
  - `vibe_iterator/scanners/rate_limit_check.py`
- Modify second scanner wave:
  - `vibe_iterator/scanners/ssrf_check.py`
  - `vibe_iterator/scanners/path_traversal_check.py`
  - `vibe_iterator/scanners/open_redirect_check.py`
  - `vibe_iterator/scanners/graphql_check.py`
- Add tests:
  - `tests/test_api_inventory.py`
  - `tests/test_engine/test_api_inventory_integration.py`
  - Extend `tests/test_config.py`
  - Extend `tests/test_spider/test_discover_runner.py`
  - Extend `tests/test_engine/test_discover_result_serialization.py`
  - Extend `tests/test_history.py`
  - Extend scanner tests for migrated scanners.

---

### Task 1: API Intelligence Config And Mode Resolver

**Files:**
- Create: `vibe_iterator/api_inventory.py`
- Modify: `vibe_iterator/config.py`
- Test: `tests/test_api_inventory.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write failing mode resolver tests**

Add to `tests/test_api_inventory.py`:

```python
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
```

- [ ] **Step 2: Run the resolver tests to verify they fail**

Run:

```powershell
python -m pytest tests/test_api_inventory.py -q
```

Expected: fail because `vibe_iterator.api_inventory` does not exist.

- [ ] **Step 3: Implement config dataclass and resolver**

Create `vibe_iterator/api_inventory.py` with:

```python
"""Shared API intelligence inventory model and builders."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
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
```

- [ ] **Step 4: Add config parsing tests**

Add to `tests/test_config.py`:

```python
def test_api_intelligence_defaults(tmp_path, monkeypatch):
    cfg_path = tmp_path / "vibe-iterator.config.yaml"
    cfg_path.write_text("target: http://localhost:3000\npages: ['/']\n", encoding="utf-8")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "a@example.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    cfg = load_config(yaml_path=cfg_path)
    assert cfg.api_intelligence.mode == "auto"
    assert cfg.api_intelligence.max_route_candidates == 200


def test_api_intelligence_yaml_overrides(tmp_path, monkeypatch):
    cfg_path = tmp_path / "vibe-iterator.config.yaml"
    cfg_path.write_text(
        """
target: http://localhost:3000
pages: ['/']
api_intelligence:
  mode: safe
  max_route_candidates: 25
  max_methods_per_route: 4
  max_hidden_params_per_endpoint: 7
  request_timeout_seconds: 2
  total_timeout_seconds: 11
  wordlists:
    routes: builtin
    params: builtin
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("VIBE_ITERATOR_TEST_EMAIL", "a@example.com")
    monkeypatch.setenv("VIBE_ITERATOR_TEST_PASSWORD", "pw")
    cfg = load_config(yaml_path=cfg_path)
    assert cfg.api_intelligence.mode == "safe"
    assert cfg.api_intelligence.max_route_candidates == 25
    assert cfg.api_intelligence.max_methods_per_route == 4
    assert cfg.api_intelligence.max_hidden_params_per_endpoint == 7
    assert cfg.api_intelligence.request_timeout_seconds == 2
    assert cfg.api_intelligence.total_timeout_seconds == 11
```

- [ ] **Step 5: Run config tests to verify they fail**

Run:

```powershell
python -m pytest tests/test_api_inventory.py tests/test_config.py::test_api_intelligence_defaults tests/test_config.py::test_api_intelligence_yaml_overrides -q
```

Expected: resolver tests pass after Step 3, config tests fail because `Config.api_intelligence` is missing.

- [ ] **Step 6: Add `api_intelligence` to `Config` and `load_config`**

Modify `vibe_iterator/config.py`:

```python
from vibe_iterator.api_inventory import ApiIntelligenceConfig
```

Add field to `Config`:

```python
api_intelligence: ApiIntelligenceConfig = field(default_factory=ApiIntelligenceConfig)
```

Add parsing before `return Config(...)`:

```python
    api_raw = yaml_data.get("api_intelligence", {})
    api_raw = api_raw if isinstance(api_raw, dict) else {}
    wordlists = api_raw.get("wordlists", {})
    wordlists = wordlists if isinstance(wordlists, dict) else {}
    try:
        api_intelligence = ApiIntelligenceConfig(
            mode=str(api_raw.get("mode", "auto")),
            max_route_candidates=int(api_raw.get("max_route_candidates", 200)),
            max_methods_per_route=int(api_raw.get("max_methods_per_route", 6)),
            max_hidden_params_per_endpoint=int(api_raw.get("max_hidden_params_per_endpoint", 20)),
            request_timeout_seconds=int(api_raw.get("request_timeout_seconds", 3)),
            total_timeout_seconds=int(api_raw.get("total_timeout_seconds", 45)),
            route_wordlist=str(wordlists.get("routes", "builtin")),
            param_wordlist=str(wordlists.get("params", "builtin")),
        )
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
```

Pass `api_intelligence=api_intelligence` into the `Config(...)` constructor.

- [ ] **Step 7: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/api_inventory.py vibe_iterator/config.py tests/test_api_inventory.py tests/test_config.py
python -m pytest tests/test_api_inventory.py tests/test_config.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/api_inventory.py vibe_iterator/config.py tests/test_api_inventory.py tests/test_config.py
git commit -m "feat: add api intelligence config"
```

---

### Task 2: Inventory Dataclasses And Serialization

**Files:**
- Modify: `vibe_iterator/api_inventory.py`
- Test: `tests/test_api_inventory.py`

- [ ] **Step 1: Write failing dataclass serialization tests**

Add to `tests/test_api_inventory.py`:

```python
from vibe_iterator.api_inventory import (
    ApiEndpoint,
    ApiIntelligenceConfig,
    ApiInventory,
    ApiParameter,
    endpoint_to_dict,
    inventory_from_dict,
    inventory_to_dict,
    parameter_to_dict,
)


def test_parameter_to_dict_keeps_source_and_confidence() -> None:
    param = ApiParameter(
        name="role",
        location="body",
        observed_values=["user"],
        source="hidden_probe",
        confidence="confirmed",
        sensitive_hint=True,
    )
    assert parameter_to_dict(param) == {
        "name": "role",
        "location": "body",
        "observed_values": ["user"],
        "source": "hidden_probe",
        "confidence": "confirmed",
        "sensitive_hint": True,
    }


def test_inventory_round_trip() -> None:
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="POST",
                url="https://example.com/api/profile",
                origin="https://example.com",
                path="/api/profile",
                normalized_path="/api/profile",
                status_codes=[200],
                content_types=["application/json"],
                request_content_types=["application/json"],
                auth_observed=True,
                response_auth_required_hint=False,
                parameters=[
                    ApiParameter("name", "body", ["Ada"], "observed", "confirmed", False),
                    ApiParameter("role", "body", [], "inferred", "needs_review", True),
                ],
                sources=["network"],
                risk_tags=["auth", "state_changing"],
                confidence="confirmed",
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 1},
        warnings=["Aggressive discovery sends extra HTTP requests."],
    )
    data = inventory_to_dict(inv)
    assert data["endpoints"][0]["parameters"][1]["name"] == "role"
    assert inventory_from_dict(data) == inv
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
python -m pytest tests/test_api_inventory.py::test_parameter_to_dict_keeps_source_and_confidence tests/test_api_inventory.py::test_inventory_round_trip -q
```

Expected: fail because dataclasses and helpers are missing.

- [ ] **Step 3: Implement dataclasses and serialization helpers**

Add to `vibe_iterator/api_inventory.py`:

```python
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
```

Add helpers:

```python
def parameter_to_dict(param: ApiParameter) -> dict:
    return {
        "name": param.name,
        "location": param.location,
        "observed_values": list(param.observed_values),
        "source": param.source,
        "confidence": param.confidence,
        "sensitive_hint": param.sensitive_hint,
    }


def parameter_from_dict(data: dict) -> ApiParameter:
    return ApiParameter(
        name=str(data.get("name", "")),
        location=str(data.get("location", "")),
        observed_values=[str(v) for v in data.get("observed_values", [])],
        source=str(data.get("source", "observed")),
        confidence=str(data.get("confidence", "confirmed")),
        sensitive_hint=bool(data.get("sensitive_hint", False)),
    )


def endpoint_to_dict(endpoint: ApiEndpoint) -> dict:
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
        "parameters": [parameter_to_dict(p) for p in endpoint.parameters],
        "sources": list(endpoint.sources),
        "risk_tags": list(endpoint.risk_tags),
        "confidence": endpoint.confidence,
    }


def endpoint_from_dict(data: dict) -> ApiEndpoint:
    return ApiEndpoint(
        method=str(data.get("method", "GET")),
        url=str(data.get("url", "")),
        origin=str(data.get("origin", "")),
        path=str(data.get("path", "")),
        normalized_path=str(data.get("normalized_path", data.get("path", ""))),
        status_codes=[int(v) for v in data.get("status_codes", [])],
        content_types=[str(v) for v in data.get("content_types", [])],
        request_content_types=[str(v) for v in data.get("request_content_types", [])],
        auth_observed=bool(data.get("auth_observed", False)),
        response_auth_required_hint=bool(data.get("response_auth_required_hint", False)),
        parameters=[parameter_from_dict(p) for p in data.get("parameters", [])],
        sources=[str(v) for v in data.get("sources", [])],
        risk_tags=[str(v) for v in data.get("risk_tags", [])],
        confidence=str(data.get("confidence", "confirmed")),
    )


def inventory_to_dict(inventory: ApiInventory) -> dict:
    return {
        "generated_at": inventory.generated_at,
        "mode": inventory.mode,
        "resolved_mode": inventory.resolved_mode,
        "target": inventory.target,
        "endpoints": [endpoint_to_dict(e) for e in inventory.endpoints],
        "summary": dict(inventory.summary),
        "warnings": list(inventory.warnings),
    }


def inventory_from_dict(data: dict | None) -> ApiInventory | None:
    if data is None:
        return None
    return ApiInventory(
        generated_at=str(data.get("generated_at", "")),
        mode=str(data.get("mode", "auto")),
        resolved_mode=str(data.get("resolved_mode", "safe")),
        target=str(data.get("target", "")),
        endpoints=[endpoint_from_dict(e) for e in data.get("endpoints", [])],
        summary={str(k): int(v) for k, v in data.get("summary", {}).items()},
        warnings=[str(v) for v in data.get("warnings", [])],
    )
```

- [ ] **Step 4: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
python -m pytest tests/test_api_inventory.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/api_inventory.py tests/test_api_inventory.py
git commit -m "feat: add api inventory model"
```

---

### Task 3: Build Inventory From Captured Network Requests

**Files:**
- Modify: `vibe_iterator/api_inventory.py`
- Test: `tests/test_api_inventory.py`

- [ ] **Step 1: Write failing builder tests**

Add to `tests/test_api_inventory.py`:

```python
from unittest.mock import MagicMock

from vibe_iterator.api_inventory import build_inventory_from_network


def _req(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    post_data: str | None = None,
    response_headers: dict | None = None,
    status_code: int = 200,
) -> MagicMock:
    req = MagicMock()
    req.url = url
    req.method = method
    req.headers = headers or {}
    req.post_data = post_data
    req.response_headers = response_headers or {"content-type": "application/json"}
    req.status_code = status_code
    return req


def test_build_inventory_extracts_query_json_and_headers() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req(
            "https://example.com/api/users/123?include=profile",
            method="POST",
            headers={"Authorization": "Bearer token", "Content-Type": "application/json"},
            post_data='{"name": "Ada", "tenant_id": "t1"}',
            status_code=200,
        )
    ]
    inv = build_inventory_from_network(
        net,
        target="https://example.com",
        mode="auto",
        resolved_mode="safe",
    )
    assert inv.summary["endpoints"] == 1
    endpoint = inv.endpoints[0]
    assert endpoint.method == "POST"
    assert endpoint.path == "/api/users/123"
    assert endpoint.normalized_path == "/api/users/{id}"
    assert endpoint.auth_observed is True
    assert "state_changing" in endpoint.risk_tags
    params = {(p.location, p.name) for p in endpoint.parameters}
    assert ("query", "include") in params
    assert ("body", "name") in params
    assert ("body", "tenant_id") in params
```

- [ ] **Step 2: Run builder test to verify it fails**

Run:

```powershell
python -m pytest tests/test_api_inventory.py::test_build_inventory_extracts_query_json_and_headers -q
```

Expected: fail because `build_inventory_from_network` is missing.

- [ ] **Step 3: Implement network builder**

Add helpers in `vibe_iterator/api_inventory.py`:

```python
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

_ID_SEGMENT_RE = re.compile(r"^\d+$|^[0-9a-f]{8}-[0-9a-f-]{27,}$", re.I)
_API_PREFIXES = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/")
_AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key"}
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_PARAM_NAMES = {"role", "admin", "isadmin", "permissions", "tenant_id", "org_id", "user_id"}


def build_inventory_from_network(network: object, target: str, mode: str, resolved_mode: str) -> ApiInventory:
    endpoints_by_key: dict[tuple[str, str], ApiEndpoint] = {}
    for req in network.get_requests():
        endpoint = endpoint_from_request(req, target)
        if endpoint is None:
            continue
        key = (endpoint.method, endpoint.normalized_path)
        existing = endpoints_by_key.get(key)
        endpoints_by_key[key] = merge_endpoints(existing, endpoint) if existing else endpoint
    endpoints = sorted(endpoints_by_key.values(), key=lambda e: (e.normalized_path, e.method))
    hidden_count = sum(1 for e in endpoints for p in e.parameters if p.source in {"inferred", "hidden_probe"})
    return ApiInventory(
        generated_at=datetime.now(timezone.utc).isoformat(),
        mode=mode,
        resolved_mode=resolved_mode,
        target=target,
        endpoints=endpoints,
        summary={
            "endpoints": len(endpoints),
            "auth_observed": sum(1 for e in endpoints if e.auth_observed),
            "hidden_parameters": hidden_count,
            "state_changing": sum(1 for e in endpoints if "state_changing" in e.risk_tags),
        },
        warnings=aggressive_warnings(resolved_mode),
    )
```

Implement `endpoint_from_request`, `merge_endpoints`, `_extract_parameters`, `_normalize_path`, `_risk_tags`, and `aggressive_warnings` in the same module. The implementation must:

- skip non-API paths using `_API_PREFIXES`
- parse query params with `parse_qs`
- parse JSON object body keys when `post_data` is JSON
- parse form body keys when content type is form URL encoded
- tag auth when request headers contain auth/cookie/api key
- tag `state_changing` for `POST`, `PUT`, `PATCH`, `DELETE`
- tag `graphql`, `upload`, `webhook`, `admin`, `redirect`, `file`, and `ssrf` using path and parameter names

- [ ] **Step 4: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
python -m pytest tests/test_api_inventory.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/api_inventory.py tests/test_api_inventory.py
git commit -m "feat: build api inventory from traffic"
```

---

### Task 4: DiscoveryResult Sidecar And History Serialization

**Files:**
- Modify: `vibe_iterator/engine/discover_runner.py`
- Modify: `vibe_iterator/history.py`
- Test: `tests/test_spider/test_discover_runner.py`
- Test: `tests/test_engine/test_discover_result_serialization.py`
- Test: `tests/test_history.py`

- [ ] **Step 1: Write failing serialization tests**

Extend `tests/test_engine/test_discover_result_serialization.py`:

```python
from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory, ApiParameter


def test_result_dict_serializes_api_inventory():
    from vibe_iterator.engine.discover_runner import DiscoveryResult
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/users/1",
                origin="https://example.com",
                path="/api/users/1",
                normalized_path="/api/users/{id}",
                status_codes=[200],
                parameters=[ApiParameter("include", "query", ["profile"], "observed", "confirmed")],
                sources=["network"],
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 0},
        warnings=[],
    )
    ds = DiscoveryResult(
        pages=["/"],
        api_endpoints=["GET /api/users/{id}"],
        discovered_at="2026-06-06T00:00:00Z",
        api_inventory=inv,
    )
    d = _result_dict(_base_result(stage="discover", discovered_surface=ds))
    assert d["discovered_surface"]["api_inventory"]["endpoints"][0]["normalized_path"] == "/api/users/{id}"
```

Extend `tests/test_spider/test_discover_runner.py`:

```python
def test_load_sidecar_round_trip_api_inventory():
    from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory
    from vibe_iterator.engine.discover_runner import DiscoveryResult, _write_sidecar, load_sidecar
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vibe-iterator.discovered.yaml"
        inv = ApiInventory(
            generated_at="2026-06-06T00:00:00Z",
            mode="auto",
            resolved_mode="safe",
            target="https://example.com",
            endpoints=[ApiEndpoint(method="GET", url="https://example.com/api/x", origin="https://example.com", path="/api/x", normalized_path="/api/x")],
            summary={"endpoints": 1},
            warnings=[],
        )
        _write_sidecar(DiscoveryResult(pages=["/"], api_endpoints=["GET /api/x"], discovered_at="now", api_inventory=inv), path)
        loaded = load_sidecar(Path(tmp))
        assert loaded is not None
        assert loaded.api_inventory is not None
        assert loaded.api_inventory.endpoints[0].path == "/api/x"
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
python -m pytest tests/test_engine/test_discover_result_serialization.py tests/test_spider/test_discover_runner.py::test_load_sidecar_round_trip_api_inventory -q
```

Expected: fail because `DiscoveryResult.api_inventory` is missing.

- [ ] **Step 3: Add inventory field and serializer integration**

Modify `DiscoveryResult`:

```python
from vibe_iterator.api_inventory import ApiInventory, inventory_from_dict, inventory_to_dict

@dataclass
class DiscoveryResult:
    pages: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    discovered_at: str = ""
    api_inventory: ApiInventory | None = None
```

Modify `_write_sidecar`:

```python
    data = {
        "pages": result.pages,
        "api_endpoints": result.api_endpoints,
        "discovered_at": result.discovered_at,
        "api_inventory": inventory_to_dict(result.api_inventory) if result.api_inventory else None,
    }
```

Modify `load_sidecar`:

```python
        return DiscoveryResult(
            pages=data.get("pages", []),
            api_endpoints=data.get("api_endpoints", []),
            discovered_at=data.get("discovered_at", ""),
            api_inventory=inventory_from_dict(data.get("api_inventory")),
        )
```

Modify `history.serialize_result`:

```python
from vibe_iterator.api_inventory import inventory_to_dict
```

In `discovered_surface` dict:

```python
"api_inventory": inventory_to_dict(result.discovered_surface.api_inventory)
if result.discovered_surface.api_inventory is not None else None,
```

- [ ] **Step 4: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/engine/discover_runner.py vibe_iterator/history.py tests/test_engine/test_discover_result_serialization.py tests/test_spider/test_discover_runner.py
python -m pytest tests/test_engine/test_discover_result_serialization.py tests/test_spider/test_discover_runner.py tests/test_history.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/engine/discover_runner.py vibe_iterator/history.py tests/test_engine/test_discover_result_serialization.py tests/test_spider/test_discover_runner.py tests/test_history.py
git commit -m "feat: serialize api inventory in discovery results"
```

---

### Task 5: Build Inventory During Discover And Normal Scans

**Files:**
- Modify: `vibe_iterator/engine/discover_runner.py`
- Modify: `vibe_iterator/engine/runner.py`
- Test: `tests/test_spider/test_discover_runner.py`
- Test: `tests/test_engine/test_api_inventory_integration.py`
- Test: `tests/test_engine/test_discover_stage_routing.py`

- [ ] **Step 1: Write failing integration tests**

Create `tests/test_engine/test_api_inventory_integration.py`:

```python
from unittest.mock import MagicMock, patch

import pytest

from vibe_iterator.api_inventory import ApiInventory
from vibe_iterator.engine.runner import ScanRunner


def _cfg() -> MagicMock:
    cfg = MagicMock()
    cfg.target = "http://localhost:3000"
    cfg.pages = ["/"]
    cfg.stack.backend = "custom"
    cfg.stack.detection_source = "configured"
    cfg.scanner_timeout_seconds = 5
    cfg.second_account_configured = False
    cfg.scanners_for_stage.return_value = ["api_exposure"]
    return cfg


@pytest.mark.asyncio
async def test_runner_injects_api_inventory_listener() -> None:
    cfg = _cfg()
    seen = {}
    scanner = MagicMock()
    scanner.name = "api_exposure"
    scanner.category = "API Security"
    scanner.requires_stack = ["any"]
    scanner.requires_second_account = False

    def run_scanner(session, listeners, config):
        seen["api_inventory"] = listeners.get("api_inventory")
        return []

    scanner.run.side_effect = run_scanner

    with patch("vibe_iterator.engine.runner._load_scanner", return_value=scanner), \
         patch("vibe_iterator.crawler.browser.launch") as launch, \
         patch("vibe_iterator.crawler.auth.login"), \
         patch("vibe_iterator.crawler.navigator.crawl_pages", return_value=[]), \
         patch("vibe_iterator.listeners.network.NetworkListener.attach"), \
         patch("vibe_iterator.listeners.console.ConsoleListener.attach"), \
         patch("vibe_iterator.listeners.storage.StorageListener.capture"), \
         patch("vibe_iterator.listeners.network.NetworkListener.summary", return_value={"total": 0}), \
         patch("vibe_iterator.listeners.network.NetworkListener.detach"), \
         patch("vibe_iterator.listeners.console.ConsoleListener.detach"):
        launch.return_value = MagicMock()
        result = await ScanRunner(cfg, on_event=lambda e: None).run("pre-deploy")

    assert isinstance(seen["api_inventory"], ApiInventory)
    assert result.discovered_surface is not None
    assert result.discovered_surface.api_inventory is seen["api_inventory"]
```

- [ ] **Step 2: Run integration test to verify it fails**

Run:

```powershell
python -m pytest tests/test_engine/test_api_inventory_integration.py -q
```

Expected: fail because runner does not build/inject inventory.

- [ ] **Step 3: Build inventory in discovery**

Modify `run_discovery`:

```python
from vibe_iterator.api_inventory import build_inventory_from_network, resolve_mode

resolved_mode = resolve_mode(config.target, config.api_intelligence)
api_inventory = build_inventory_from_network(
    network,
    target=config.target,
    mode=config.api_intelligence.mode,
    resolved_mode=resolved_mode,
)
```

Set `DiscoveryResult(api_inventory=api_inventory)`.

- [ ] **Step 4: Build inventory in normal runner**

In `ScanRunner.run`, after crawl and before scanner loading:

```python
from vibe_iterator.api_inventory import build_inventory_from_network, resolve_mode

resolved_api_mode = resolve_mode(self.config.target, self.config.api_intelligence)
api_inventory = build_inventory_from_network(
    network,
    target=self.config.target,
    mode=self.config.api_intelligence.mode,
    resolved_mode=resolved_api_mode,
)
self._result.discovered_surface = DiscoveryResult(
    pages=[p["url"] for p in self._result.pages_crawled],
    api_endpoints=[f"{e.method} {e.normalized_path}" for e in api_inventory.endpoints],
    discovered_at=api_inventory.generated_at,
    api_inventory=api_inventory,
)
```

Then modify listeners:

```python
listeners = {"network": network, "console": console, "storage": storage, "api_inventory": api_inventory}
```

- [ ] **Step 5: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/engine/discover_runner.py vibe_iterator/engine/runner.py tests/test_engine/test_api_inventory_integration.py
python -m pytest tests/test_engine/test_api_inventory_integration.py tests/test_spider/test_discover_runner.py tests/test_engine/test_discover_stage_routing.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/engine/discover_runner.py vibe_iterator/engine/runner.py tests/test_engine/test_api_inventory_integration.py tests/test_spider/test_discover_runner.py tests/test_engine/test_discover_stage_routing.py
git commit -m "feat: inject api inventory into scans"
```

---

### Task 6: Hidden Parameter Inference

**Files:**
- Modify: `vibe_iterator/api_inventory.py`
- Test: `tests/test_api_inventory.py`

- [ ] **Step 1: Write failing hidden parameter tests**

Add to `tests/test_api_inventory.py`:

```python
from vibe_iterator.api_inventory import infer_hidden_parameters


def test_infer_hidden_parameters_marks_sensitive_missing_sibling_fields() -> None:
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="PATCH",
                url="https://example.com/api/profile",
                origin="https://example.com",
                path="/api/profile",
                normalized_path="/api/profile",
                parameters=[ApiParameter("name", "body", ["Ada"], "observed", "confirmed")],
                sources=["network"],
            ),
            ApiEndpoint(
                method="POST",
                url="https://example.com/api/admin/users",
                origin="https://example.com",
                path="/api/admin/users",
                normalized_path="/api/admin/users",
                parameters=[ApiParameter("role", "body", ["admin"], "observed", "confirmed")],
                sources=["network"],
                risk_tags=["admin"],
            ),
        ],
        summary={},
        warnings=[],
    )
    updated = infer_hidden_parameters(inv, max_hidden_params_per_endpoint=5)
    profile = next(e for e in updated.endpoints if e.path == "/api/profile")
    inferred = [p for p in profile.parameters if p.source == "inferred"]
    assert any(p.name == "role" and p.sensitive_hint for p in inferred)
    assert updated.summary["hidden_parameters"] >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
python -m pytest tests/test_api_inventory.py::test_infer_hidden_parameters_marks_sensitive_missing_sibling_fields -q
```

Expected: fail because `infer_hidden_parameters` is missing.

- [ ] **Step 3: Implement inference**

Add:

```python
_HIDDEN_PARAM_CANDIDATES = (
    "role", "admin", "isAdmin", "permissions", "tenant_id", "org_id", "user_id",
    "include", "expand", "fields", "select", "debug", "trace", "verbose",
    "next", "return_to", "redirect", "url", "callback_url", "path", "file", "filename",
)


def infer_hidden_parameters(inventory: ApiInventory, max_hidden_params_per_endpoint: int = 20) -> ApiInventory:
    observed_names = {p.name for e in inventory.endpoints for p in e.parameters}
    candidate_names = list(dict.fromkeys([*observed_names, *_HIDDEN_PARAM_CANDIDATES]))
    updated: list[ApiEndpoint] = []
    for endpoint in inventory.endpoints:
        existing = {(p.location, p.name.lower()) for p in endpoint.parameters}
        inferred: list[ApiParameter] = []
        for name in candidate_names:
            if len(inferred) >= max_hidden_params_per_endpoint:
                break
            location = "body" if endpoint.method in _STATE_METHODS else "query"
            if (location, name.lower()) in existing:
                continue
            if not _candidate_matches_endpoint(name, endpoint):
                continue
            inferred.append(ApiParameter(
                name=name,
                location=location,
                observed_values=[],
                source="inferred",
                confidence="needs_review",
                sensitive_hint=name.lower() in _SENSITIVE_PARAM_NAMES,
            ))
        updated.append(replace(endpoint, parameters=[*endpoint.parameters, *inferred]))
    return replace(inventory, endpoints=updated, summary=_inventory_summary(updated))
```

Implement `_candidate_matches_endpoint` so sensitive authz fields match state-changing authenticated/admin/profile/user endpoints, redirect names match redirect-like endpoints, URL names match URL-like endpoints, and file names match file/upload/download endpoints.

- [ ] **Step 4: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
python -m pytest tests/test_api_inventory.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/api_inventory.py tests/test_api_inventory.py
git commit -m "feat: infer hidden api parameters"
```

---

### Task 7: Bounded Aggressive Route And Parameter Probing

**Files:**
- Modify: `vibe_iterator/api_inventory.py`
- Test: `tests/test_api_inventory.py`

- [ ] **Step 1: Write failing aggressive probe tests**

Add:

```python
from vibe_iterator.api_inventory import expand_aggressive_inventory


def test_aggressive_expansion_skipped_in_safe_mode(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr("vibe_iterator.api_inventory._probe_endpoint", lambda *args, **kwargs: calls.append(args) or None)
    inv = ApiInventory("now", "auto", "safe", "https://example.com", [], {}, [])
    expanded = expand_aggressive_inventory(inv, ApiIntelligenceConfig(mode="auto", max_route_candidates=10))
    assert expanded.endpoints == []
    assert calls == []


def test_aggressive_expansion_adds_confirmed_local_candidate(monkeypatch) -> None:
    def fake_probe(url, method, origin, timeout):
        if url.endswith("/api/auth/login") and method == "POST":
            return 401, {"content-type": "application/json"}
        return None
    monkeypatch.setattr("vibe_iterator.api_inventory._probe_endpoint", fake_probe)
    inv = ApiInventory("now", "auto", "aggressive", "http://localhost:3000", [], {}, [])
    expanded = expand_aggressive_inventory(
        inv,
        ApiIntelligenceConfig(mode="auto", max_route_candidates=5, max_methods_per_route=2),
    )
    assert any(e.method == "POST" and e.path == "/api/auth/login" for e in expanded.endpoints)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
python -m pytest tests/test_api_inventory.py::test_aggressive_expansion_skipped_in_safe_mode tests/test_api_inventory.py::test_aggressive_expansion_adds_confirmed_local_candidate -q
```

Expected: fail because `expand_aggressive_inventory` is missing.

- [ ] **Step 3: Implement bounded aggressive expansion**

Add:

```python
_BUILTIN_ROUTES = (
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/signup",
    "/api/auth/forgot-password",
    "/api/users",
    "/api/admin/users",
    "/api/settings",
    "/api/billing",
    "/graphql",
)
_METHOD_MATRIX = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


def expand_aggressive_inventory(inventory: ApiInventory, config: ApiIntelligenceConfig) -> ApiInventory:
    if inventory.resolved_mode != "aggressive":
        return inventory
    candidates = _candidate_routes(inventory)[:config.max_route_candidates]
    endpoints = list(inventory.endpoints)
    seen = {(e.method, e.normalized_path) for e in endpoints}
    origin = _origin_for_target(inventory.target)
    for route in candidates:
        for method in _METHOD_MATRIX[:config.max_methods_per_route]:
            result = _probe_endpoint(inventory.target.rstrip("/") + route, method, origin, config.request_timeout_seconds)
            if result is None:
                continue
            status, headers = result
            if status in {404, 405, 501}:
                continue
            endpoint = endpoint_from_probe(inventory.target, route, method, status, headers)
            key = (endpoint.method, endpoint.normalized_path)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(endpoint)
    endpoints = sorted(endpoints, key=lambda e: (e.normalized_path, e.method))
    return replace(inventory, endpoints=endpoints, summary=_inventory_summary(endpoints), warnings=aggressive_warnings("aggressive"))
```

Implement `_probe_endpoint` with `urllib.request.Request`, lowercased response headers, timeout, HTTPError handling, and `None` on network errors.

- [ ] **Step 4: Wire aggressive expansion into builders**

After `build_inventory_from_network` creates the inventory:

```python
if resolved_mode == "aggressive":
    inventory = expand_aggressive_inventory(inventory, config)
```

Use a new `build_api_inventory(network, target, config)` wrapper to avoid changing many call sites:

```python
def build_api_inventory(network: object, target: str, config: ApiIntelligenceConfig) -> ApiInventory:
    resolved = resolve_mode(target, config)
    inventory = build_inventory_from_network(network, target, config.mode, resolved)
    inventory = infer_hidden_parameters(inventory, config.max_hidden_params_per_endpoint)
    return expand_aggressive_inventory(inventory, config)
```

- [ ] **Step 5: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/api_inventory.py tests/test_api_inventory.py
python -m pytest tests/test_api_inventory.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/api_inventory.py tests/test_api_inventory.py
git commit -m "feat: add bounded aggressive api discovery"
```

---

### Task 8: Dashboard Toggle, Warning, And Inventory Report Panel

**Files:**
- Modify: `vibe_iterator/server/routes.py`
- Modify: `vibe_iterator/server/static/index.html`
- Modify: `vibe_iterator/server/static/js/app.js`
- Modify: `vibe_iterator/server/static/css/dashboard.css`
- Test: `tests/test_server/test_routes.py`

- [ ] **Step 1: Write failing route override test**

Add to `tests/test_server/test_routes.py`:

```python
def test_scan_start_accepts_api_intelligence_mode_override(monkeypatch):
    captured = {}

    class DummyRunner:
        def __init__(self, config, on_event, scanner_overrides=None, browser_headless=False):
            captured["mode"] = config.api_intelligence.mode
        async def run(self, stage):
            return None

    monkeypatch.setattr("vibe_iterator.server.routes.ScanRunner", DummyRunner)
    response = client.post("/api/scan/start", json={"stage": "pre-deploy", "api_intelligence_mode": "safe"})
    assert response.status_code == 200
    assert captured["mode"] == "safe"
```

- [ ] **Step 2: Run route test to verify failure**

Run:

```powershell
python -m pytest tests/test_server/test_routes.py::test_scan_start_accepts_api_intelligence_mode_override -q
```

Expected: fail because request body ignores `api_intelligence_mode`.

- [ ] **Step 3: Implement backend override**

In `vibe_iterator/server/routes.py`, read `api_intelligence_mode` from JSON and validate one of `auto`, `safe`, `aggressive`, `off`. Clone or mutate config before runner creation:

```python
mode = body.get("api_intelligence_mode")
if mode is not None:
    if mode not in {"auto", "safe", "aggressive", "off"}:
        raise HTTPException(status_code=400, detail="Invalid api_intelligence_mode")
    config.api_intelligence.mode = mode
```

- [ ] **Step 4: Add frontend toggle and warning**

In `index.html`, add a segmented control near scanner advanced controls:

```html
<div class="api-intel-control">
  <label for="api-intel-mode">API Intelligence</label>
  <select id="api-intel-mode">
    <option value="auto">Auto</option>
    <option value="safe">Safe</option>
    <option value="aggressive">Aggressive</option>
    <option value="off">Off</option>
  </select>
  <p id="api-intel-warning" class="warning-text" hidden>
    Aggressive API discovery sends extra HTTP requests beyond normal browsing. It may trigger logs, rate limits,
    analytics events, emails, audit alerts, or WAF rules. Use it only on localhost, staging, or targets you are
    authorized to test.
  </p>
</div>
```

In `app.js`, include mode in scan start body:

```javascript
const apiMode = document.getElementById('api-intel-mode')?.value || 'auto';
body: JSON.stringify({ stage: _selectedStage, scanner_overrides: overrides, api_intelligence_mode: apiMode }),
```

Show warning when `aggressive` is selected.

- [ ] **Step 5: Render inventory panel**

Modify `renderDiscoverySurface(r)` in `app.js`:

```javascript
const inv = ds.api_inventory || null;
if (inv) {
  const summary = inv.summary || {};
  // Render mode, endpoint count, auth count, hidden parameter count, warnings, and endpoint rows.
}
```

Add markup target to `results.html` if needed:

```html
<div id="api-inventory-panel" class="panel"></div>
```

- [ ] **Step 6: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/server/routes.py tests/test_server/test_routes.py
python -m pytest tests/test_server/test_routes.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/server/routes.py vibe_iterator/server/static/index.html vibe_iterator/server/static/js/app.js vibe_iterator/server/static/css/dashboard.css vibe_iterator/server/static/results.html tests/test_server/test_routes.py
git commit -m "feat: expose api intelligence controls"
```

---

### Task 9: Exported HTML Report Inventory

**Files:**
- Modify: `vibe_iterator/report/generator.py`
- Modify: `vibe_iterator/report/templates/report.html.j2`
- Test: `tests/test_report/test_generator.py`

- [ ] **Step 1: Write failing report test**

Add:

```python
def test_report_includes_api_inventory_summary(sample_result):
    from vibe_iterator.api_inventory import ApiEndpoint, ApiInventory
    from vibe_iterator.engine.discover_runner import DiscoveryResult
    sample_result.discovered_surface = DiscoveryResult(
        pages=["/"],
        api_endpoints=["GET /api/users"],
        discovered_at="now",
        api_inventory=ApiInventory(
            generated_at="now",
            mode="auto",
            resolved_mode="safe",
            target="https://example.com",
            endpoints=[ApiEndpoint(method="GET", url="https://example.com/api/users", origin="https://example.com", path="/api/users", normalized_path="/api/users")],
            summary={"endpoints": 1, "hidden_parameters": 0},
            warnings=[],
        ),
    )
    html = generate(sample_result)
    assert "API Inventory" in html
    assert "/api/users" in html
```

- [ ] **Step 2: Run report test to verify failure**

Run:

```powershell
python -m pytest tests/test_report/test_generator.py::test_report_includes_api_inventory_summary -q
```

Expected: fail because report template does not render inventory.

- [ ] **Step 3: Pass inventory into template**

In `generator.py`, add:

```python
"api_inventory": (
    inventory_to_dict(result.discovered_surface.api_inventory)
    if result.discovered_surface and result.discovered_surface.api_inventory else None
),
```

In `report.html.j2`, add a section:

```jinja2
{% if api_inventory %}
<section>
  <h2>API Inventory</h2>
  <p>Mode: {{ api_inventory.resolved_mode }} · Endpoints: {{ api_inventory.summary.endpoints }}</p>
  {% if api_inventory.warnings %}
  <div class="warning">{{ api_inventory.warnings | join(" ") }}</div>
  {% endif %}
  <table>
    <thead><tr><th>Method</th><th>Path</th><th>Source</th><th>Confidence</th><th>Tags</th></tr></thead>
    <tbody>
    {% for endpoint in api_inventory.endpoints %}
      <tr>
        <td>{{ endpoint.method }}</td>
        <td>{{ endpoint.normalized_path }}</td>
        <td>{{ endpoint.sources | join(", ") }}</td>
        <td>{{ endpoint.confidence }}</td>
        <td>{{ endpoint.risk_tags | join(", ") }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</section>
{% endif %}
```

- [ ] **Step 4: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/report/generator.py tests/test_report/test_generator.py
python -m pytest tests/test_report/test_generator.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/report/generator.py vibe_iterator/report/templates/report.html.j2 tests/test_report/test_generator.py
git commit -m "feat: include api inventory in reports"
```

---

### Task 10: First Scanner Migration - Mass Assignment And IDOR

**Files:**
- Modify: `vibe_iterator/scanners/mass_assignment.py`
- Modify: `vibe_iterator/scanners/idor_check.py`
- Test: `tests/test_scanners/test_mass_assignment.py`
- Test: `tests/test_scanners/test_idor_check.py`

- [ ] **Step 1: Write failing mass assignment inventory test**

Add:

```python
def test_mass_assignment_uses_inventory_hidden_body_parameter(monkeypatch):
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="PATCH",
                url="https://example.com/api/profile",
                origin="https://example.com",
                path="/api/profile",
                normalized_path="/api/profile",
                parameters=[ApiParameter("role", "body", [], "inferred", "needs_review", True)],
                sources=["network"],
                risk_tags=["state_changing", "auth"],
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 1},
        warnings=[],
    )
    # Existing _send_probe helper should be patched to return accepted role evidence.
    monkeypatch.setattr("vibe_iterator.scanners.mass_assignment._send_probe", lambda *args, **kwargs: (200, {}, '{"role":"admin"}'))
    findings = Scanner().run(session=None, listeners={"network": _make_network([]), "api_inventory": inv}, config=_make_config())
    assert any(f.evidence.get("inventory_source") for f in findings)
```

- [ ] **Step 2: Write failing IDOR inventory test**

Add:

```python
def test_idor_uses_inventory_normalized_id_path(monkeypatch):
    inv = ApiInventory(
        generated_at="now",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/users/123",
                origin="https://example.com",
                path="/api/users/123",
                normalized_path="/api/users/{id}",
                auth_observed=True,
                sources=["network"],
                risk_tags=["auth"],
            )
        ],
        summary={"endpoints": 1},
        warnings=[],
    )
    monkeypatch.setattr("vibe_iterator.scanners.idor_check._fetch", lambda *args, **kwargs: (200, {}, '{"id":124,"email":"other@example.com"}'))
    findings = Scanner().run(session=None, listeners={"network": _make_network([]), "api_inventory": inv}, config=_make_config())
    assert any(f.evidence.get("inventory_endpoint") == "GET /api/users/{id}" for f in findings)
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```powershell
python -m pytest tests/test_scanners/test_mass_assignment.py::test_mass_assignment_uses_inventory_hidden_body_parameter tests/test_scanners/test_idor_check.py::test_idor_uses_inventory_normalized_id_path -q
```

Expected: fail because scanners ignore `api_inventory`.

- [ ] **Step 4: Implement scanner migration**

For each scanner:

- read `inventory = listeners.get("api_inventory")`
- collect inventory candidates first
- append existing network candidates second
- dedupe by method + URL
- add evidence fields:

```python
"inventory_source": ",".join(endpoint.sources),
"inventory_confidence": endpoint.confidence,
"inventory_endpoint": f"{endpoint.method} {endpoint.normalized_path}",
"inventory_parameters_used": [param.name for param in selected_params],
```

Keep old network-only tests passing.

- [ ] **Step 5: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/scanners/mass_assignment.py vibe_iterator/scanners/idor_check.py tests/test_scanners/test_mass_assignment.py tests/test_scanners/test_idor_check.py
python -m pytest tests/test_scanners/test_mass_assignment.py tests/test_scanners/test_idor_check.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/scanners/mass_assignment.py vibe_iterator/scanners/idor_check.py tests/test_scanners/test_mass_assignment.py tests/test_scanners/test_idor_check.py
git commit -m "feat: feed api inventory to access-control scanners"
```

---

### Task 11: First Scanner Migration - API Exposure And Rate Limit

**Files:**
- Modify: `vibe_iterator/scanners/api_exposure.py`
- Modify: `vibe_iterator/scanners/rate_limit_check.py`
- Test: `tests/test_scanners/test_api_exposure.py`
- Test: `tests/test_scanners/test_rate_limit_check.py`

- [ ] **Step 1: Write failing API exposure inventory test**

Add:

```python
def test_api_exposure_uses_inventory_auth_endpoint(monkeypatch):
    inv = ApiInventory(
        "now", "auto", "safe", "https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/account",
                origin="https://example.com",
                path="/api/account",
                normalized_path="/api/account",
                auth_observed=True,
                sources=["network"],
                risk_tags=["auth"],
            )
        ],
        summary={"endpoints": 1},
        warnings=[],
    )
    monkeypatch.setattr("vibe_iterator.scanners.api_exposure._fetch_without_auth", lambda *args, **kwargs: (200, {}))
    findings = Scanner().run(session=None, listeners={"network": _make_network([]), "api_inventory": inv}, config=_make_config())
    assert any(f.evidence.get("inventory_endpoint") == "GET /api/account" for f in findings)
```

- [ ] **Step 2: Write failing rate limit inventory test**

Add:

```python
def test_rate_limit_uses_inventory_auth_post_endpoint(monkeypatch):
    inv = ApiInventory(
        "now", "auto", "safe", "https://example.com",
        endpoints=[
            ApiEndpoint(
                method="POST",
                url="https://example.com/api/auth/login",
                origin="https://example.com",
                path="/api/auth/login",
                normalized_path="/api/auth/login",
                sources=["route_wordlist"],
                risk_tags=["auth", "state_changing"],
                confidence="confirmed",
            )
        ],
        summary={"endpoints": 1},
        warnings=[],
    )
    monkeypatch.setattr("vibe_iterator.scanners.rate_limit_check._post_full", lambda *args, **kwargs: (401, {}, '{"error":"invalid credentials"}'))
    findings = Scanner().run(session=None, listeners={"network": _make_network([]), "api_inventory": inv}, config=_make_config())
    assert any(f.evidence.get("inventory_endpoint") == "POST /api/auth/login" for f in findings)
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```powershell
python -m pytest tests/test_scanners/test_api_exposure.py::test_api_exposure_uses_inventory_auth_endpoint tests/test_scanners/test_rate_limit_check.py::test_rate_limit_uses_inventory_auth_post_endpoint -q
```

Expected: fail because scanners ignore `api_inventory`.

- [ ] **Step 4: Implement scanner migration**

API exposure:

- convert inventory auth endpoints into replay candidates
- preserve `_unauth_access_proof_quality` or add equivalent proof for `auth` risk tag
- add inventory evidence fields

Rate limit:

- use inventory POST endpoints with `auth` and `state_changing` tags before built-in path variants
- avoid duplicating network-discovered paths
- add inventory evidence fields to `_finding_a`, `_finding_b`, and `_finding_c`

- [ ] **Step 5: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/scanners/api_exposure.py vibe_iterator/scanners/rate_limit_check.py tests/test_scanners/test_api_exposure.py tests/test_scanners/test_rate_limit_check.py
python -m pytest tests/test_scanners/test_api_exposure.py tests/test_scanners/test_api_exposure_proof.py tests/test_scanners/test_rate_limit_check.py tests/test_scanners/test_rate_limit_check_proof.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/scanners/api_exposure.py vibe_iterator/scanners/rate_limit_check.py tests/test_scanners/test_api_exposure.py tests/test_scanners/test_rate_limit_check.py
git commit -m "feat: feed api inventory to api scanners"
```

---

### Task 12: URL And GraphQL Scanner Inventory Migration

**Files:**
- Modify: `vibe_iterator/scanners/ssrf_check.py`
- Modify: `vibe_iterator/scanners/path_traversal_check.py`
- Modify: `vibe_iterator/scanners/open_redirect_check.py`
- Modify: `vibe_iterator/scanners/graphql_check.py`
- Test: corresponding scanner tests.

- [ ] **Step 1: Add failing tests for inventory parameter targeting**

For each scanner test file, add one test that:

- creates `ApiInventory`
- includes one endpoint with matching `risk_tags`
- includes one matching `ApiParameter` with `source="inferred"` or `source="hidden_probe"`
- provides empty network requests
- patches the scanner probe helper to return proof
- asserts finding evidence includes `inventory_source`, `inventory_endpoint`, and `inventory_parameters_used`

Use this shape in each file:

```python
def test_scanner_uses_inventory_parameter(monkeypatch):
    inv = ApiInventory(
        "now", "auto", "safe", "https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/fetch",
                origin="https://example.com",
                path="/api/fetch",
                normalized_path="/api/fetch",
                parameters=[ApiParameter("url", "query", [], "inferred", "needs_review", False)],
                sources=["network"],
                risk_tags=["ssrf"],
            )
        ],
        summary={"endpoints": 1, "hidden_parameters": 1},
        warnings=[],
    )
    # Patch module-specific probe helper to return proof.
    findings = Scanner().run(session=None, listeners={"network": _make_network([]), "api_inventory": inv}, config=_make_config())
    assert any(f.evidence.get("inventory_parameters_used") == ["url"] for f in findings)
```

Use scanner-specific parameter and risk tag:

- SSRF: `url`, `ssrf`
- path traversal: `path`, `file`
- open redirect: `next`, `redirect`
- GraphQL: no parameter needed, endpoint `POST /graphql`, tag `graphql`

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
python -m pytest tests/test_scanners/test_ssrf_check.py tests/test_scanners/test_path_traversal_check.py tests/test_scanners/test_open_redirect_check.py tests/test_scanners/test_graphql_check.py -q
```

Expected: new tests fail because scanners ignore inventory.

- [ ] **Step 3: Implement scanner migrations**

For each scanner:

- build inventory candidates first
- append existing network-discovered candidates
- dedupe by URL + parameter
- preserve all current false-positive filters
- add inventory evidence fields

- [ ] **Step 4: Verify and commit**

Run:

```powershell
python -m ruff check vibe_iterator/scanners/ssrf_check.py vibe_iterator/scanners/path_traversal_check.py vibe_iterator/scanners/open_redirect_check.py vibe_iterator/scanners/graphql_check.py tests/test_scanners/test_ssrf_check.py tests/test_scanners/test_path_traversal_check.py tests/test_scanners/test_open_redirect_check.py tests/test_scanners/test_graphql_check.py
python -m pytest tests/test_scanners/test_ssrf_check.py tests/test_scanners/test_path_traversal_check.py tests/test_scanners/test_open_redirect_check.py tests/test_scanners/test_graphql_check.py -q
```

Expected: all pass.

Commit:

```powershell
git add -- vibe_iterator/scanners/ssrf_check.py vibe_iterator/scanners/path_traversal_check.py vibe_iterator/scanners/open_redirect_check.py vibe_iterator/scanners/graphql_check.py tests/test_scanners/test_ssrf_check.py tests/test_scanners/test_path_traversal_check.py tests/test_scanners/test_open_redirect_check.py tests/test_scanners/test_graphql_check.py
git commit -m "feat: feed api inventory to parameter scanners"
```

---

### Task 13: Documentation And Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/CONFIG.md`
- Modify: `docs/SCANNERS.md`
- Modify: `.env.example` if config examples are present there.

- [ ] **Step 1: Update user docs**

Add API Intelligence documentation:

- mode policy: auto, safe, aggressive, off
- public targets default to safe
- local targets default to aggressive
- warning text for aggressive mode
- inventory report fields
- scanner integration summary

- [ ] **Step 2: Run docs encoding and scanner exposure tests**

Run:

```powershell
python -m pytest tests/test_docs/test_encoding.py tests/test_scanner_exposure_matrix.py -q
python scripts/check_scanner_exposure.py
```

Expected: docs encoding passes; scanner exposure gate reports no registry/preset/UI gaps.

- [ ] **Step 3: Run full verification**

Run:

```powershell
python -m ruff check vibe_iterator tests
python -m pytest -q
python scripts/check_scanner_exposure.py
```

Expected:

- ruff passes
- pytest passes
- scanner exposure reports no gaps

- [ ] **Step 4: Commit docs and final verification**

Commit:

```powershell
git add -- README.md docs/CONFIG.md docs/SCANNERS.md .env.example
git commit -m "docs: document api intelligence foundation"
```

If `.env.example` did not change, omit it from `git add`.

---

## Completion Audit

Before marking the goal complete, verify each requirement:

- endpoint inventory model exists in `vibe_iterator/api_inventory.py`
- method-aware discovery differentiates method + normalized path
- hidden parameter discovery infers or probes parameters and records source/confidence
- dashboard/results render API inventory
- exported reports include API inventory
- runner injects `listeners["api_inventory"]`
- migrated scanners use inventory with network fallback
- safe/aggressive/off/auto mode policy is implemented
- public targets resolve safe; localhost/private/.local resolve aggressive
- user can toggle mode
- aggressive warning appears in UI and report/results warnings
- full test suite passes
- scanner exposure gate passes

Only call `update_goal(status="complete")` after the audit is proven by current files and command output.
