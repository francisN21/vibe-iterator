from __future__ import annotations

from unittest.mock import MagicMock

from vibe_iterator.api_inventory import (
    ApiEndpoint,
    ApiIntelligenceConfig,
    ApiInventory,
    ApiParameter,
    build_inventory_from_network,
    endpoint_from_dict,
    endpoint_to_dict,
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
