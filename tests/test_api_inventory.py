from __future__ import annotations

from unittest.mock import MagicMock
from urllib.error import HTTPError

import vibe_iterator.api_inventory as api_inventory
from vibe_iterator.api_inventory import (
    ApiEndpoint,
    ApiIntelligenceConfig,
    ApiInventory,
    ApiParameter,
    build_inventory_from_network,
    endpoint_from_dict,
    endpoint_to_dict,
    infer_hidden_parameters,
    inventory_from_dict,
    inventory_to_dict,
    parameter_from_dict,
    parameter_to_dict,
    resolve_mode,
)


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
    assert endpoint_to_dict(inv.endpoints[0]) == data["endpoints"][0]
    assert inventory_from_dict(data) == inv


def test_inventory_from_dict_none_returns_none() -> None:
    assert inventory_from_dict(None) is None


def test_infer_hidden_parameters_adds_sensitive_observed_candidates_to_matching_endpoints() -> None:
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
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
                parameters=[ApiParameter("name", "body", ["Ada"])],
                risk_tags=["state_changing"],
            ),
            ApiEndpoint(
                method="POST",
                url="https://example.com/api/admin/users",
                origin="https://example.com",
                path="/api/admin/users",
                normalized_path="/api/admin/users",
                parameters=[ApiParameter("role", "body", ["admin"], sensitive_hint=True)],
                risk_tags=["admin", "state_changing"],
            ),
        ],
        summary={"endpoints": 2, "hidden_parameters": 0},
    )

    inferred = infer_hidden_parameters(inv, max_hidden_params_per_endpoint=5)

    profile = next(endpoint for endpoint in inferred.endpoints if endpoint.path == "/api/profile")
    role = next(parameter for parameter in profile.parameters if parameter.name == "role")
    assert role.location == "body"
    assert role.observed_values == []
    assert role.source == "inferred"
    assert role.confidence == "needs_review"
    assert role.sensitive_hint is True
    assert sum(parameter.source == "inferred" for parameter in profile.parameters) <= 5
    assert inferred.summary["hidden_parameters"] > inv.summary["hidden_parameters"]
    assert inferred.summary["hidden_parameters"] == sum(
        1
        for endpoint in inferred.endpoints
        for parameter in endpoint.parameters
        if parameter.source == "inferred"
    )


def test_infer_hidden_parameters_skips_names_already_present_on_endpoint() -> None:
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="POST",
                url="https://example.com/api/reports",
                origin="https://example.com",
                path="/api/reports",
                normalized_path="/api/reports",
                parameters=[ApiParameter("include", "query", ["owner"])],
                risk_tags=["state_changing"],
            ),
        ],
        summary={"endpoints": 1, "hidden_parameters": 0},
    )

    inferred = infer_hidden_parameters(inv, max_hidden_params_per_endpoint=10)

    endpoint = inferred.endpoints[0]
    assert [parameter.name.lower() for parameter in endpoint.parameters].count("include") == 1


def test_infer_hidden_parameters_does_not_add_generic_candidates_without_signal() -> None:
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/profile",
                origin="https://example.com",
                path="/api/profile",
                normalized_path="/api/profile",
                parameters=[],
            ),
        ],
        summary={"endpoints": 1, "hidden_parameters": 0},
    )

    inferred = infer_hidden_parameters(inv, max_hidden_params_per_endpoint=10)

    assert inferred.endpoints[0].parameters == []
    assert inferred.summary["hidden_parameters"] == 0


def test_string_boolean_false_values_deserialize_to_false() -> None:
    param = parameter_from_dict({"sensitive_hint": "false"})
    endpoint = endpoint_from_dict(
        {
            "auth_observed": "0",
            "response_auth_required_hint": "no",
        }
    )

    assert param.sensitive_hint is False
    assert endpoint.auth_observed is False
    assert endpoint.response_auth_required_hint is False


def test_string_boolean_true_values_deserialize_to_true() -> None:
    endpoint = endpoint_from_dict({"auth_observed": "yes"})

    assert endpoint.auth_observed is True


def test_endpoint_from_dict_defaults_method_and_normalized_path() -> None:
    endpoint = endpoint_from_dict({"path": "/api/users"})

    assert endpoint.method == "GET"
    assert endpoint.normalized_path == "/api/users"


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


def test_build_inventory_extracts_form_body_with_lowercase_content_type() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req(
            "https://example.com/rest/login",
            method="PATCH",
            headers={"content-type": "application/x-www-form-urlencoded"},
            post_data="email=ada%40example.com&role=user",
            response_headers={"Content-Type": "text/plain; charset=utf-8"},
            status_code=204,
        )
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    endpoint = inv.endpoints[0]
    assert endpoint.request_content_types == ["application/x-www-form-urlencoded"]
    assert endpoint.content_types == ["text/plain"]
    assert endpoint.status_codes == [204]
    params = {(p.location, p.name, p.sensitive_hint) for p in endpoint.parameters}
    assert ("body", "email", False) in params
    assert ("body", "role", True) in params


def test_build_inventory_merges_duplicate_endpoints() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req(
            "https://example.com/api/users/123?include=profile",
            headers={"Cookie": "sid=abc"},
            response_headers={"content-type": "application/json"},
            status_code=200,
        ),
        _req(
            "https://example.com/api/users/456?expand=org",
            headers={"X-API-Key": "secret"},
            response_headers={"content-type": "application/problem+json"},
            status_code=404,
        ),
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    assert inv.summary["endpoints"] == 1
    endpoint = inv.endpoints[0]
    assert endpoint.normalized_path == "/api/users/{id}"
    assert endpoint.status_codes == [200, 404]
    assert endpoint.content_types == ["application/json", "application/problem+json"]
    assert endpoint.auth_observed is True
    assert endpoint.sources == [
        "network:https://example.com/api/users/123?include=profile",
        "network:https://example.com/api/users/456?expand=org",
    ]
    assert {(p.location, p.name) for p in endpoint.parameters} == {
        ("query", "expand"),
        ("query", "include"),
    }


def test_build_inventory_skips_non_api_static_paths() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req("https://example.com/static/app.js"),
        _req("https://example.com/favicon.ico"),
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    assert inv.endpoints == []
    assert inv.summary["endpoints"] == 0


def test_build_inventory_warns_for_aggressive_mode() -> None:
    net = MagicMock()
    net.get_requests.return_value = []

    inv = build_inventory_from_network(net, "http://localhost:3000", "auto", "aggressive")

    assert inv.warnings == ["Aggressive API intelligence may send additional probing requests."]


def test_aggressive_expansion_skipped_in_safe_mode(monkeypatch) -> None:
    calls = []

    def _fake_probe(*args):
        calls.append(args)
        return (200, {"content-type": "application/json"})

    monkeypatch.setattr(api_inventory, "_probe_endpoint", _fake_probe, raising=False)
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="safe",
        target="https://example.com",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="https://example.com/api/users",
                origin="https://example.com",
                path="/api/users",
                normalized_path="/api/users",
            )
        ],
        summary={"endpoints": 1},
    )

    expanded = api_inventory.expand_aggressive_inventory(inv, ApiIntelligenceConfig(mode="safe"))

    assert expanded is inv
    assert calls == []


def test_aggressive_expansion_adds_confirmed_local_candidate(monkeypatch) -> None:
    calls = []

    def _fake_probe(url, method, origin, timeout):
        calls.append((url, method, origin, timeout))
        if url == "http://localhost:3000/api/auth/login" and method == "POST":
            return (401, {"content-type": "application/json"})
        return None

    monkeypatch.setattr(api_inventory, "_probe_endpoint", _fake_probe)
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="aggressive",
        target="http://localhost:3000",
        endpoints=[],
        summary={"endpoints": 0},
    )

    expanded = api_inventory.expand_aggressive_inventory(inv, ApiIntelligenceConfig())

    assert ("http://localhost:3000/api/auth/login", "POST", "http://localhost:3000", 3) in calls
    login = next(endpoint for endpoint in expanded.endpoints if endpoint.path == "/api/auth/login")
    assert login.method == "POST"
    assert login.status_codes == [401]
    assert login.content_types == ["application/json"]
    assert login.confidence == "confirmed"
    assert login.sources == ["probe:POST http://localhost:3000/api/auth/login"]
    assert login.response_auth_required_hint is True


def test_aggressive_expansion_honors_route_and_method_caps(monkeypatch) -> None:
    calls = []

    def _fake_probe(url, method, origin, timeout):
        calls.append((url, method, origin, timeout))
        return None

    monkeypatch.setattr(api_inventory, "_probe_endpoint", _fake_probe)
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="aggressive",
        target="http://localhost:3000",
        endpoints=[
            ApiEndpoint(
                method="GET",
                url="http://localhost:3000/api/projects",
                origin="http://localhost:3000",
                path="/api/projects",
                normalized_path="/api/projects",
            ),
            ApiEndpoint(
                method="GET",
                url="http://localhost:3000/api/teams",
                origin="http://localhost:3000",
                path="/api/teams",
                normalized_path="/api/teams",
            ),
        ],
        summary={"endpoints": 2},
    )

    api_inventory.expand_aggressive_inventory(
        inv,
        ApiIntelligenceConfig(
            mode="aggressive",
            max_route_candidates=1,
            max_methods_per_route=2,
            request_timeout_seconds=7,
        ),
    )

    assert calls == [
        ("http://localhost:3000/api/projects", "GET", "http://localhost:3000", 7),
        ("http://localhost:3000/api/projects", "POST", "http://localhost:3000", 7),
    ]


def test_aggressive_expansion_honors_total_timeout_budget(monkeypatch) -> None:
    calls = []

    def _fake_probe(url, method, origin, timeout):
        calls.append((url, method, origin, timeout))
        return None

    monkeypatch.setattr(api_inventory, "_probe_endpoint", _fake_probe)
    inv = ApiInventory(
        generated_at="2026-06-06T00:00:00Z",
        mode="auto",
        resolved_mode="aggressive",
        target="http://localhost:3000",
        endpoints=[],
        summary={"endpoints": 0},
    )

    api_inventory.expand_aggressive_inventory(
        inv,
        ApiIntelligenceConfig(mode="aggressive", total_timeout_seconds=0),
    )

    assert calls == []


def test_probe_endpoint_does_not_follow_redirects(monkeypatch) -> None:
    opener = MagicMock()
    opener.open.side_effect = HTTPError(
        "http://localhost:3000/api/redirect",
        302,
        "Found",
        {"Location": "http://127.0.0.1:4000/api/escaped"},
        None,
    )
    monkeypatch.setattr(api_inventory, "_NO_REDIRECT_OPENER", opener)

    result = api_inventory._probe_endpoint(
        "http://localhost:3000/api/redirect",
        "GET",
        "http://localhost:3000",
        1,
    )

    assert result == (302, {"location": "http://127.0.0.1:4000/api/escaped"})
    opener.open.assert_called_once()


def test_build_inventory_tags_risk_categories() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req("https://example.com/graphql", method="POST"),
        _req("https://example.com/api/admin/webhooks"),
        _req(
            "https://example.com/api/files/upload?redirect_url=https%3A%2F%2Fevil.test",
            method="POST",
            headers={"Content-Type": "application/json"},
            post_data='{"file_url": "https://metadata.local/latest"}',
        ),
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")
    tags = {tag for endpoint in inv.endpoints for tag in endpoint.risk_tags}

    assert {"graphql", "admin", "webhook", "upload", "redirect", "file", "ssrf"} <= tags


def test_build_inventory_file_risk_tag_is_token_aware() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req("https://example.com/api/profile"),
        _req("https://example.com/api/files/download?path=avatar.png"),
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    by_path = {endpoint.path: endpoint for endpoint in inv.endpoints}
    assert "file" not in by_path["/api/profile"].risk_tags
    assert "file" in by_path["/api/files/download"].risk_tags


def test_build_inventory_includes_api_requests_from_different_origin() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req("https://api.example.com/api/users/123"),
        _req("https://project.supabase.co/rest/v1/items"),
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    assert inv.target == "https://example.com"
    assert [(endpoint.origin, endpoint.path) for endpoint in inv.endpoints] == [
        ("https://api.example.com", "/api/users/123"),
        ("https://project.supabase.co", "/rest/v1/items"),
    ]


def test_build_inventory_keeps_same_path_different_origins_separate() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req("https://app.example.com/api/users/1"),
        _req("https://api.example.com/api/users/2"),
    ]

    inv = build_inventory_from_network(net, "https://app.example.com", "auto", "safe")

    assert inv.summary["endpoints"] == 2
    assert {endpoint.origin for endpoint in inv.endpoints} == {
        "https://app.example.com",
        "https://api.example.com",
    }
    assert {endpoint.normalized_path for endpoint in inv.endpoints} == {"/api/users/{id}"}


def test_build_inventory_extracts_json_body_without_content_type() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req(
            "https://example.com/api/profile",
            method="POST",
            headers={},
            post_data='{"display_name": "Ada", "org_id": "o1"}',
        )
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    params = {(p.location, p.name) for p in inv.endpoints[0].parameters}
    assert ("body", "display_name") in params
    assert ("body", "org_id") in params


def test_build_inventory_extracts_json_body_from_problem_json_content_type() -> None:
    net = MagicMock()
    net.get_requests.return_value = [
        _req(
            "https://example.com/api/errors",
            method="POST",
            headers={"Content-Type": "application/problem+json"},
            post_data='{"type": "validation", "detail": "bad input"}',
        )
    ]

    inv = build_inventory_from_network(net, "https://example.com", "auto", "safe")

    params = {(p.location, p.name) for p in inv.endpoints[0].parameters}
    assert ("body", "type") in params
    assert ("body", "detail") in params
