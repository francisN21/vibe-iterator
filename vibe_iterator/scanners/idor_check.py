"""IDOR check scanner — tests numeric-ID URL parameters for insecure direct object reference."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

# Matches paths like /api/users/42 or /api/items/7 — captures the numeric segment
_NUMERIC_ID_RE = re.compile(r"^(https?://[^/]+)(.*/)(\d+)(/.*)?$")

_STATIC_EXTS = {".js", ".css", ".png", ".svg", ".ico", ".woff", ".jpg", ".gif", ".map"}


def _is_static(url: str) -> bool:
    return any(url.endswith(ext) for ext in _STATIC_EXTS)


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

        tested_patterns: set[str] = set()

        for req in network.get_requests():
            if req.method != "GET":
                continue
            if _is_static(req.url):
                continue
            m = _NUMERIC_ID_RE.match(req.url)
            if not m:
                continue

            base, prefix, numeric_id_str, suffix = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            pattern_key = f"{base}{prefix}*{suffix}"
            if pattern_key in tested_patterns:
                continue
            tested_patterns.add(pattern_key)

            numeric_id = int(numeric_id_str)
            # Probe: try id+1 and id+2 (or id-1 if id > 1)
            probe_ids = [numeric_id + 1, numeric_id + 2]
            if numeric_id > 1:
                probe_ids.append(numeric_id - 1)

            # Extract auth token from original request headers
            auth_header = {}
            orig_headers = req.headers or {}
            if isinstance(orig_headers, dict):
                for k, v in orig_headers.items():
                    if k.lower() in ("authorization", "cookie", "x-api-key"):
                        auth_header[k] = v

            original_body = req.response_body or ""

            for probe_id in probe_ids:
                probe_url = f"{base}{prefix}{probe_id}{suffix}"
                resp_body, status = _fetch(probe_url, auth_header)

                if status != 200 or not resp_body:
                    continue

                # Verify it's not the same response as the original
                if resp_body.strip() == original_body.strip():
                    continue

                try:
                    data = json.loads(resp_body)
                    if not isinstance(data, dict) or not data:
                        continue
                except (json.JSONDecodeError, ValueError):
                    # Non-JSON 200 is still suspicious
                    pass

                desc = (
                    f"Accessing `{probe_url}` (ID={probe_id}) with the same auth credentials "
                    f"as `{req.url}` (ID={numeric_id}) returned HTTP 200 with data. "
                    "The server does not validate that the requested resource belongs to the authenticated user. "
                    "Any user can enumerate other users' records by changing the ID in the URL."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title=f"IDOR: resource {prefix}{{id}} accessible across users (tested ID={probe_id})",
                    description=desc,
                    evidence={
                        "original_url": req.url,
                        "original_id": numeric_id,
                        "probed_url": probe_url,
                        "probed_id": probe_id,
                        "request": {"method": "GET", "url": probe_url, "headers": auth_header},
                        "response": {"status": status, "body_excerpt": truncate(resp_body, 300)},
                        "payload_used": str(probe_id),
                        "payload_type": "idor_id_enumeration",
                        "injection_point": "url_path:numeric_id",
                        "network_events": [],
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"IDOR: {prefix}{{id}} accessible across users",
                        severity=Severity.HIGH, scanner=self.name,
                        page=probe_url, category=self.category, description=desc,
                        evidence_summary=(
                            f"Original: GET {req.url} (ID={numeric_id})\n"
                            f"Probed:   GET {probe_url} (ID={probe_id}) → HTTP {status} with data\n"
                            f"Conclusion: any authenticated user can access any resource by ID."
                        ),
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The endpoint `{prefix}{{id}}` does not verify resource ownership.\n\n"
                        "**How to fix:** Before returning a resource, check that it belongs to the authenticated user:\n"
                        "```js\n"
                        "const item = await db.items.findUnique({ where: { id, userId: session.user.id } });\n"
                        "if (!item) return res.status(403).json({ error: 'Forbidden' });\n"
                        "```\n"
                        "For Supabase: use RLS policy `USING (auth.uid() = user_id)`.\n\n"
                        "**Verify the fix:** Re-run idor_check — probed ID must return 403 or 404."
                    ),
                    category=self.category, page=probe_url,
                ))
                break  # one finding per path pattern is enough

        return findings


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
