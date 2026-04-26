"""Load, validate, and expose the merged configuration from .env and YAML."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

# Default stage → scanner mapping (mirrors vibe-iterator.config.yaml)
_DEFAULT_STAGES: dict[str, list[str]] = {
    "dev": ["data_leakage", "auth_check", "client_tampering"],
    "pre-deploy": [
        "data_leakage", "auth_check", "client_tampering",
        "rls_bypass", "tier_escalation", "bucket_limits",
        "sql_injection", "xss_check", "api_exposure",
    ],
    "post-deploy": [
        "cors_check", "data_leakage", "auth_check",
        "api_exposure", "bucket_limits", "sql_injection",
    ],
    "all": [
        "data_leakage", "rls_bypass", "tier_escalation", "bucket_limits",
        "auth_check", "client_tampering", "sql_injection",
        "cors_check", "xss_check", "api_exposure",
    ],
}

_DEFAULT_PAGES: list[str] = ["/", "/login", "/dashboard", "/profile"]

_VALID_SCANNER_NAMES: frozenset[str] = frozenset(_DEFAULT_STAGES["all"])


@dataclass
class StackConfig:
    """Technology stack settings."""

    backend: str = "custom"        # supabase | firebase | custom
    auth: str = "custom"           # supabase-auth | firebase-auth | custom
    storage: str = "custom"        # supabase | firebase | s3 | custom
    detection_source: str = "auto-detect"  # auto-detect | manually-configured


@dataclass
class Config:
    """Merged runtime configuration. Passed to engine and all scanners."""

    # Target
    target: str

    # Auth
    test_email: str
    test_password: str
    test_email_2: str | None
    test_password_2: str | None

    # Supabase specifics (optional)
    supabase_url: str | None
    supabase_anon_key: str | None

    # Scan scope
    pages: list[str]
    stages: dict[str, list[str]]

    # Stack
    stack: StackConfig

    # Server
    port: int

    # Limits
    scanner_timeout_seconds: int = 60

    @property
    def second_account_configured(self) -> bool:
        """True when both second-account credentials are present."""
        return bool(self.test_email_2 and self.test_password_2)

    def scanners_for_stage(self, stage: str) -> list[str]:
        """Return the ordered scanner list for a stage."""
        return self.stages.get(stage, [])


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


def load_config(
    *,
    target_override: str | None = None,
    port_override: int | None = None,
    yaml_path: str | Path | None = None,
    env_path: str | Path | None = None,
) -> Config:
    """Load config from .env and optional YAML, applying CLI overrides last.

    Priority (highest → lowest):
      1. CLI overrides (target_override, port_override)
      2. vibe-iterator.config.yaml
      3. .env / environment variables
      4. Built-in defaults
    """
    # Load .env (silently skipped if file not found — env vars may already be set)
    load_dotenv(env_path or Path.cwd() / ".env", override=False)

    # ------------------------------------------------------------------ #
    # Parse YAML (optional)                                               #
    # ------------------------------------------------------------------ #
    yaml_data: dict = {}
    yaml_file = Path(yaml_path) if yaml_path else Path.cwd() / "vibe-iterator.config.yaml"
    if yaml_file.exists():
        with yaml_file.open() as fh:
            raw = yaml.safe_load(fh) or {}
        yaml_data = raw if isinstance(raw, dict) else {}

    # ------------------------------------------------------------------ #
    # Required fields                                                     #
    # ------------------------------------------------------------------ #
    test_email = os.getenv("VIBE_ITERATOR_TEST_EMAIL", "")
    test_password = os.getenv("VIBE_ITERATOR_TEST_PASSWORD", "")
    target_from_env = os.getenv("VIBE_ITERATOR_TARGET", "")
    target_from_yaml = str(yaml_data.get("target", "")).strip()

    # Resolve target: CLI > YAML > env
    target = (
        target_override
        or target_from_yaml
        or target_from_env
    ).rstrip("/")

    missing: list[str] = []
    if not test_email:
        missing.append("VIBE_ITERATOR_TEST_EMAIL")
    if not test_password:
        missing.append("VIBE_ITERATOR_TEST_PASSWORD")
    if not target:
        missing.append("VIBE_ITERATOR_TARGET (or --target flag)")
    if missing:
        raise ConfigError(
            "Missing required configuration:\n"
            + "\n".join(f"  • {m}" for m in missing)
            + "\n\nSet these in your .env file (see .env.example)."
        )

    # ------------------------------------------------------------------ #
    # Optional fields                                                     #
    # ------------------------------------------------------------------ #
    test_email_2 = os.getenv("VIBE_ITERATOR_TEST_EMAIL_2") or None
    test_password_2 = os.getenv("VIBE_ITERATOR_TEST_PASSWORD_2") or None

    # Warn if second account is partially configured
    if bool(test_email_2) != bool(test_password_2):
        import warnings
        warnings.warn(
            "Second test account partially configured — "
            "set both VIBE_ITERATOR_TEST_EMAIL_2 and VIBE_ITERATOR_TEST_PASSWORD_2 "
            "to enable cross-user checks.",
            stacklevel=2,
        )
        test_email_2 = None
        test_password_2 = None

    supabase_url = os.getenv("VIBE_ITERATOR_SUPABASE_URL") or None
    supabase_anon_key = os.getenv("VIBE_ITERATOR_SUPABASE_ANON_KEY") or None

    # ------------------------------------------------------------------ #
    # Port                                                                #
    # ------------------------------------------------------------------ #
    port_env = os.getenv("VIBE_ITERATOR_PORT")
    port = port_override or (int(port_env) if port_env else 3001)

    # ------------------------------------------------------------------ #
    # Pages                                                               #
    # ------------------------------------------------------------------ #
    pages_raw = yaml_data.get("pages", _DEFAULT_PAGES)
    if not isinstance(pages_raw, list) or not pages_raw:
        import warnings
        warnings.warn(
            "No pages configured in vibe-iterator.config.yaml — using defaults.",
            stacklevel=2,
        )
        pages_raw = _DEFAULT_PAGES
    pages: list[str] = [str(p) for p in pages_raw]

    # ------------------------------------------------------------------ #
    # Stages                                                              #
    # ------------------------------------------------------------------ #
    stages_raw = yaml_data.get("stages", {})
    stages: dict[str, list[str]] = dict(_DEFAULT_STAGES)
    for stage_name, stage_cfg in stages_raw.items():
        if isinstance(stage_cfg, dict) and "scanners" in stage_cfg:
            scanner_list = stage_cfg["scanners"]
            invalid = [s for s in scanner_list if s not in _VALID_SCANNER_NAMES]
            if invalid:
                raise ConfigError(
                    f"Unknown scanner(s) in stage '{stage_name}': {invalid}\n"
                    f"Valid scanners: {sorted(_VALID_SCANNER_NAMES)}"
                )
            stages[stage_name] = scanner_list

    # ------------------------------------------------------------------ #
    # Stack                                                               #
    # ------------------------------------------------------------------ #
    stack_raw = yaml_data.get("stack", {})
    if stack_raw:
        stack = StackConfig(
            backend=stack_raw.get("backend", "custom"),
            auth=stack_raw.get("auth", "custom"),
            storage=stack_raw.get("storage", "custom"),
            detection_source="manually-configured",
        )
    else:
        stack = StackConfig()

    return Config(
        target=target,
        test_email=test_email,
        test_password=test_password,
        test_email_2=test_email_2,
        test_password_2=test_password_2,
        supabase_url=supabase_url,
        supabase_anon_key=supabase_anon_key,
        pages=pages,
        stages=stages,
        stack=stack,
        port=port,
    )
