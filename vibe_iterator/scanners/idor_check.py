"""IDOR check scanner - tests numeric-ID URL parameters for insecure direct object reference."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.scanners.request_targets import add_frontend_origin, rewrite_to_backend_url
from vibe_iterator.utils.supabase_helpers import truncate

# Matches paths like /api/users/42 or /api/items/7 - captures the numeric segment.
_NUMERIC_ID_RE = re.compile(r"^(https?://[^/]+)(.*/)(\d+)(/.*)?$")

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".jpg", ".gif", ".map"}
_GENERIC_RESPONSE_KEYS = {"ok", "success", "status", "message", "error", "errors"}
_ID_KEYS = {"id", "item_id", "user_id", "resource_id", "record_id", "profile_id", "account_id"}


def _is_static(url: str) -> bool:
    return any(url.endswith(ext) for ext in _STATIC_EXTS)


@dataclass(frozen=True)
class _IdorCandidate:
    original_url: str
    base: str
    prefix: str
    numeric_id: int
    suffix: str
    pattern_key: str
    auth_headers: dict[str, Any]
    original_body: str = ""
    inventory_source: str | None = None
    inventory_confidence: str | None = None
    inventory_endpoint: str | None = None


class Scanner(BaseScanner):
    """Detects IDOR by probing adjacent numeric IDs on discovered API endpoints."""

    name = "idor_check"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["any"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend if hasattr(config, "stack") else "unknown"
        network = listeners["network"]
        inventory = listeners.get("api_inventory")

        tested_patterns: set[str] = set()

        for candidate in [*_inventory_candidates(inventory, config), *_network_candidates(network, config)]:
            if candidate.pattern_key in tested_patterns:
                continue
            tested_patterns.add(candidate.pattern_key)

            probe_ids = [candidate.numeric_id + 1, candidate.numeric_id + 2]
            if candidate.numeric_id > 1:
                probe_ids.append(candidate.numeric_id - 1)

            for probe_id in probe_ids:
                probe_url = rewrite_to_backend_url(
                    f"{candidate.base}{candidate.prefix}{probe_id}{candidate.suffix}",
                    config,
                )
                resp_body, status = _fetch(probe_url, candidate.auth_headers)

                if status != 200 or not resp_body:
                    continue

                if resp_body.strip() == candidate.original_body.strip():
                    continue

                try:
                    data = json.loads(resp_body)
                    if not isinstance(data, dict) or not data:
                        continue
                except (json.JSONDecodeError, ValueError):
                    continue

                proof_quality = _idor_proof_quality(data, probe_id)
                if proof_quality is None:
                    continue

                desc = (
                    f"Accessing `{probe_url}` (ID={probe_id}) with the same auth credentials "
                    f"as `{candidate.original_url}` (ID={candidate.numeric_id}) returned HTTP 200 with data. "
                    "The server does not validate that the requested resource belongs to the authenticated user. "
                    "Any user can enumerate other users' records by changing the ID in the URL."
                )
                evidence = {
                    "original_url": candidate.original_url,
                    "original_id": candidate.numeric_id,
                    "probed_url": probe_url,
                    "probed_id": probe_id,
                    "request": {"method": "GET", "url": probe_url, "headers": candidate.auth_headers},
                    "response": {"status": status, "body_excerpt": truncate(resp_body, 300)},
                    "proof_quality": proof_quality,
                    "payload_used": str(probe_id),
                    "payload_type": "idor_id_enumeration",
                    "injection_point": "url_path:numeric_id",
                    "network_events": [],
                }
                if candidate.inventory_endpoint:
                    evidence.update({
                        "inventory_source": candidate.inventory_source or "",
                        "inventory_confidence": candidate.inventory_confidence or "",
                        "inventory_endpoint": candidate.inventory_endpoint,
                    })

                findings.append(self.new_finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title=(
                        f"IDOR: resource {candidate.prefix}{{id}} accessible across users "
                        f"(tested ID={probe_id})"
                    ),
                    description=desc,
                    evidence=evidence,
                    llm_prompt=self.build_llm_prompt(
                        title=f"IDOR: {candidate.prefix}{{id}} accessible across users",
                        severity=Severity.HIGH,
                        scanner=self.name,
                        page=probe_url,
                        category=self.category,
                        description=desc,
                        evidence_summary=(
                            f"Original: GET {candidate.original_url} (ID={candidate.numeric_id})\n"
                            f"Probed:   GET {probe_url} (ID={probe_id}) -> HTTP {status} with data\n"
                            "Conclusion: any authenticated user can access any resource by ID."
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The endpoint `{candidate.prefix}{{id}}` does not verify "
                        "resource ownership.\n\n"
                        "**How to fix:** Before returning a resource, check that it belongs to the "
                        "authenticated user:\n"
                        "```js\n"
                        "const item = await db.items.findUnique({ where: { id, userId: session.user.id } });\n"
                        "if (!item) return res.status(403).json({ error: 'Forbidden' });\n"
                        "```\n"
                        "For Supabase: use RLS policy `USING (auth.uid() = user_id)`.\n\n"
                        "**Verify the fix:** Re-run idor_check - probed ID must return 403 or 404."
                    ),
                    category=self.category,
                    page=probe_url,
                ))
                break

        return findings


def _inventory_candidates(inventory: Any, config: Any) -> list[_IdorCandidate]:
    if inventory is None:
        return []

    candidates: list[_IdorCandidate] = []
    for endpoint in getattr(inventory, "endpoints", []):
        method = str(getattr(endpoint, "method", "")).upper()
        url = getattr(endpoint, "url", "")
        if method != "GET":
            continue
        if not isinstance(url, str) or _is_static(url):
            continue

        candidate = _candidate_from_url(
            url=url,
            auth_headers=add_frontend_origin({}, config),
            original_body="",
            inventory_source=",".join(getattr(endpoint, "sources", [])),
            inventory_confidence=getattr(endpoint, "confidence", ""),
            inventory_endpoint=f"{method} {getattr(endpoint, 'normalized_path', getattr(endpoint, 'path', url))}",
        )
        if candidate is not None:
            candidates.append(candidate)

    return candidates


def _network_candidates(network: Any, config: Any) -> list[_IdorCandidate]:
    candidates: list[_IdorCandidate] = []
    for req in network.get_requests():
        if req.method != "GET":
            continue
        if _is_static(req.url):
            continue

        auth_header: dict[str, Any] = {}
        orig_headers = req.headers or {}
        if isinstance(orig_headers, dict):
            for key, value in orig_headers.items():
                if key.lower() in ("authorization", "cookie", "x-api-key"):
                    auth_header[key] = value

        candidate = _candidate_from_url(
            url=req.url,
            auth_headers=add_frontend_origin(auth_header, config),
            original_body=req.response_body or "",
        )
        if candidate is not None:
            candidates.append(candidate)

    return candidates


def _candidate_from_url(
    *,
    url: str,
    auth_headers: dict[str, Any],
    original_body: str,
    inventory_source: str | None = None,
    inventory_confidence: str | None = None,
    inventory_endpoint: str | None = None,
) -> _IdorCandidate | None:
    m = _NUMERIC_ID_RE.match(url)
    if not m:
        return None

    base, prefix, numeric_id_str, suffix = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    return _IdorCandidate(
        original_url=url,
        base=base,
        prefix=prefix,
        numeric_id=int(numeric_id_str),
        suffix=suffix,
        pattern_key=f"{base}{prefix}*{suffix}",
        auth_headers=auth_headers,
        original_body=original_body,
        inventory_source=inventory_source,
        inventory_confidence=inventory_confidence,
        inventory_endpoint=inventory_endpoint,
    )


def _fetch(url: str, headers: dict, timeout: int = 5) -> tuple[str, int | None]:
    """Probe a URL with the given headers.

    TLS verification is intentionally left enabled (default ssl context).
    For targets that use self-signed certs, add the CA to the system trust
    store rather than disabling verification globally.
    """
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(20_000).decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        return "", e.code
    except Exception:
        return "", None


def _idor_proof_quality(data: dict, probe_id: int) -> str | None:
    """Classify whether a JSON response is strong enough IDOR evidence."""
    for key in _ID_KEYS:
        if key in data and str(data[key]) == str(probe_id):
            return f"response_{key}_matches_probed_id"

    keys = {str(key).lower() for key in data}
    if keys and keys.issubset(_GENERIC_RESPONSE_KEYS):
        return None

    return "resource_like_json_response_for_probed_id"
