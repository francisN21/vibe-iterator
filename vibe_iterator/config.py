"""Load, validate, and expose the merged configuration from .env and YAML."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

# Default stage → scanner mapping (mirrors vibe-iterator.config.yaml)
_FIREBASE_SCANNERS: list[str] = [
    "firebase_firestore",
    "firebase_rtdb",
    "firebase_storage",
    "firebase_auth",
    "firebase_functions",
]

_SAFE_LIVE_SCANNERS: list[str] = [
    "data_leakage",
    "api_key_exposure",
    "cors_check",
    "info_disclosure",
    "open_redirect_check",
    "websocket_check",
]

_DEFAULT_STAGES: dict[str, list[str]] = {
    "dev": ["data_leakage", "auth_check", "client_tampering", "firebase_auth"],
    "safe-live": list(_SAFE_LIVE_SCANNERS),
    "pre-deploy": [
        "data_leakage", "auth_check", "client_tampering",
        "rls_bypass", "tier_escalation", "bucket_limits",
        "sql_injection", "xss_check", "api_exposure",
        "mass_assignment", "info_disclosure", "idor_check",
        "http_method_tampering", "rate_limit_check", "open_redirect_check",
        "path_traversal_check", "ssrf_check", "csrf_check", "graphql_check", "webhook_check",
        "websocket_check", "unsafe_payload_check", "file_upload_check",
        *_FIREBASE_SCANNERS,
    ],
    "post-deploy": [
        "cors_check", "data_leakage", "auth_check",
        "api_exposure", "api_key_exposure", "bucket_limits",
        "sql_injection", "mass_assignment", "info_disclosure",
        "idor_check", "http_method_tampering", "rate_limit_check",
        *_FIREBASE_SCANNERS,
    ],
    "all": [
        "data_leakage", "rls_bypass", "tier_escalation", "bucket_limits",
        "auth_check", "client_tampering", "sql_injection",
        "cors_check", "xss_check", "api_exposure", "api_key_exposure",
        "mass_assignment", "info_disclosure", "idor_check",
        "http_method_tampering", "rate_limit_check", "open_redirect_check",
        "path_traversal_check", "ssrf_check", "csrf_check", "graphql_check", "webhook_check",
        "websocket_check", "unsafe_payload_check", "file_upload_check",
        *_FIREBASE_SCANNERS,
    ],
    "firebase": list(_FIREBASE_SCANNERS),
}

_DEFAULT_PAGES: list[str] = ["/", "/login", "/dashboard", "/profile"]

_VALID_SCANNER_NAMES: frozenset[str] = frozenset(
    scanner
    for scanner_list in _DEFAULT_STAGES.values()
    for scanner in scanner_list
)


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

    # Spider (endpoint discovery)
    spider_max_pages: int = 30
    spider_max_depth: int = 3

    # Rate limit scanner
    rate_limit_deep_scan: bool = False

    # Optional separate backend API URL (when frontend and backend run on different ports)
    backend_url: str | None = None

    # History
    results_dir: Path = field(default_factory=lambda: Path.cwd() / "vibe-iterator-results")

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
      2. .env / environment variables
      3. vibe-iterator.config.yaml
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

    # Resolve target: CLI > env > YAML
    target = (
        target_override
        or target_from_env
        or target_from_yaml
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
    # Limits                                                              #
    # ------------------------------------------------------------------ #
    scanner_timeout_raw = yaml_data.get("scanner_timeout_seconds", 60)
    try:
        scanner_timeout_seconds = int(scanner_timeout_raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError("scanner_timeout_seconds must be an integer.") from exc
    if scanner_timeout_seconds <= 0:
        raise ConfigError("scanner_timeout_seconds must be greater than 0.")

    # ------------------------------------------------------------------ #
    # Spider                                                               #
    # ------------------------------------------------------------------ #
    spider_raw = yaml_data.get("spider", {}) or {}
    try:
        spider_max_pages = int(spider_raw.get("max_pages", 30))
        spider_max_depth = int(spider_raw.get("max_depth", 3))
    except (TypeError, ValueError) as exc:
        raise ConfigError("spider.max_pages and spider.max_depth must be integers.") from exc
    if spider_max_pages < 1:
        raise ConfigError("spider.max_pages must be at least 1.")
    if spider_max_depth < 0:
        raise ConfigError("spider.max_depth must be 0 or greater.")

    # ------------------------------------------------------------------ #
    # Rate limit scanner                                                   #
    # ------------------------------------------------------------------ #
    rate_limit_deep_scan = bool(yaml_data.get("rate_limit_deep_scan", False))
    backend_url = (os.getenv("VIBE_ITERATOR_BACKEND_URL") or "").rstrip("/") or None

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

    # Merge sidecar discovered pages (vibe-iterator.discovered.yaml beside config)
    _sidecar_path = yaml_file.parent / "vibe-iterator.discovered.yaml"
    if _sidecar_path.exists():
        try:
            with _sidecar_path.open(encoding="utf-8") as _fh:
                _sidecar_data = yaml.safe_load(_fh) or {}
            _sidecar_pages = _sidecar_data.get("pages", [])
            if isinstance(_sidecar_pages, list):
                _existing = set(pages)
                for _p in _sidecar_pages:
                    _p = str(_p)
                    if _p not in _existing:
                        pages.append(_p)
                        _existing.add(_p)
        except Exception:
            pass  # sidecar load failure is non-fatal

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

    results_dir = yaml_file.parent / "vibe-iterator-results"

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
        scanner_timeout_seconds=scanner_timeout_seconds,
        spider_max_pages=spider_max_pages,
        spider_max_depth=spider_max_depth,
        rate_limit_deep_scan=rate_limit_deep_scan,
        backend_url=backend_url,
        results_dir=results_dir,
    )
