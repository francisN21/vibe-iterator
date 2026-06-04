"""Helpers for routing runtime scanner probes against configured app origins."""

from __future__ import annotations

from typing import Any


def rewrite_to_backend_url(url: str, config: Any) -> str:
    """Rewrite a frontend-captured URL to backend_url when both origins are configured."""
    backend_url_raw = getattr(config, "backend_url", None)
    target_raw = getattr(config, "target", "")
    if not isinstance(backend_url_raw, str) or not isinstance(target_raw, str):
        return url

    backend_url = backend_url_raw.rstrip("/")
    target = target_raw.rstrip("/")
    if not backend_url or not target or not url.startswith(target):
        return url

    suffix = url[len(target):]
    if not suffix.startswith("/"):
        return url
    return backend_url + suffix


def frontend_origin(config: Any) -> str | None:
    """Return target origin for backend probes, or None when no backend_url is configured."""
    backend_url = getattr(config, "backend_url", None)
    target = getattr(config, "target", "")
    if isinstance(backend_url, str) and backend_url and isinstance(target, str) and target:
        return target.rstrip("/")
    return None


def add_frontend_origin(headers: dict, config: Any) -> dict:
    """Copy headers and add Origin when probing a separate backend_url."""
    updated = dict(headers)
    origin = frontend_origin(config)
    if origin:
        updated["Origin"] = origin
    return updated
