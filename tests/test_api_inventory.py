from __future__ import annotations

from vibe_iterator.api_inventory import (
    ApiEndpoint,
    ApiIntelligenceConfig,
    ApiInventory,
    ApiParameter,
    endpoint_from_dict,
    endpoint_to_dict,
    inventory_from_dict,
    inventory_to_dict,
    parameter_from_dict,
    parameter_to_dict,
    resolve_mode,
)


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
