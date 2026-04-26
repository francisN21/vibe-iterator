"""Bucket limits scanner — tests storage upload limit enforcement."""

from __future__ import annotations

import io
import json
from typing import Any

from vibe_iterator.scanners.base import BaseScanner, Finding, Severity
from vibe_iterator.utils.supabase_helpers import truncate

_MB = 1024 * 1024
# File sizes to test: just above common free-tier limits
_TEST_SIZES_MB = [6, 26, 51]
_BLOCKED_TYPES = ["application/x-executable", "text/html", "application/javascript"]


class Scanner(BaseScanner):
    """Tests whether Supabase storage bucket upload limits are enforced server-side."""

    name = "bucket_limits"
    category = "Access Control"
    stages = ["pre-deploy", "post-deploy"]
    requires_stack = ["supabase"]
    requires_second_account = False

    def run(self, session: Any, listeners: dict, config: Any) -> list[Finding]:
        findings: list[Finding] = []
        stack = config.stack.backend

        base_url = (config.supabase_url or "").rstrip("/")
        anon_key = config.supabase_anon_key or ""
        if not base_url or not anon_key:
            return findings

        # Discover buckets from network traffic
        buckets = _discover_buckets(listeners["network"])
        if not buckets:
            return findings

        # Get session token for authenticated uploads
        token = None
        try:
            from vibe_iterator.utils.supabase_helpers import extract_session_token
            token = session.evaluate(extract_session_token())
        except Exception:
            pass

        for bucket in buckets[:3]:
            self._check_size_limits(bucket, base_url, anon_key, token, config, findings, stack)
            self._check_type_restrictions(bucket, base_url, anon_key, token, config, findings, stack)

        return findings

    def _check_size_limits(
        self, bucket: str, base_url: str, anon_key: str, token: str | None,
        config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Attempt uploads that exceed common plan size limits."""
        import urllib.request
        import urllib.error

        auth_header = f"Bearer {token}" if token else f"Bearer {anon_key}"

        for size_mb in _TEST_SIZES_MB:
            filename = f"vibe_test_{size_mb}mb.bin"
            url = f"{base_url}/storage/v1/object/{bucket}/{filename}"
            data = b"\x00" * (size_mb * _MB)

            try:
                req = urllib.request.Request(
                    url, data=data, method="POST",
                    headers={
                        "Authorization": auth_header,
                        "apikey": anon_key,
                        "Content-Type": "application/octet-stream",
                        "x-upsert": "true",
                    },
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
                body = ""
            except Exception:
                continue

            if status in (200, 201):
                # Upload succeeded — server did not enforce size limit
                desc = (
                    f"A {size_mb} MB file was successfully uploaded to the `{bucket}` storage bucket. "
                    "Your plan's storage limits are not being enforced server-side. "
                    "Attackers could fill your storage quota, causing denial of service or unexpected costs."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.HIGH,
                    title=f"Storage bucket `{bucket}` accepts oversized uploads ({size_mb} MB)",
                    description=desc,
                    evidence={
                        "action_attempted": f"Upload {size_mb} MB file to bucket '{bucket}'",
                        "auth_context": "authenticated as primary test account",
                        "request": {"method": "POST", "url": url, "headers": {"Authorization": "Bearer [token]"}, "body": f"[{size_mb} MB binary data]"},
                        "response": {"status": status, "body_excerpt": truncate(body, 200)},
                        "expected_response": "413 Payload Too Large or 400 Bad Request",
                        "actual_response": f"{status} — upload accepted",
                        "second_account_used": False,
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Storage bucket `{bucket}` accepts oversized uploads ({size_mb} MB)",
                        severity=Severity.HIGH, scanner=self.name,
                        page=config.target, category=self.category, description=desc,
                        evidence_summary=f"POST {url}\n{size_mb} MB file accepted with status {status}.",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{bucket}` bucket has no server-side file size limit.\n\n"
                        "**How to fix:** In Supabase dashboard → Storage → {bucket} → Edit bucket, "
                        "set the 'File size limit' to your desired maximum (e.g., 5 MB). "
                        "Also enforce limits in your upload API route with: "
                        "`if (file.size > MAX_SIZE) return res.status(413).json({ error: 'File too large' });`\n\n"
                        "**Verify the fix:** Re-run bucket_limits scanner — oversized upload should return 413."
                    ),
                    category=self.category, page=config.target,
                ))
                break  # one finding per bucket for size

            # Clean up test file if it was uploaded
            try:
                del_req = urllib.request.Request(
                    url, method="DELETE",
                    headers={"Authorization": auth_header, "apikey": anon_key},
                )
                urllib.request.urlopen(del_req, timeout=5)
            except Exception:
                pass

    def _check_type_restrictions(
        self, bucket: str, base_url: str, anon_key: str, token: str | None,
        config: Any, findings: list[Finding], stack: str
    ) -> None:
        """Attempt to upload potentially dangerous file types."""
        import urllib.request
        import urllib.error

        auth_header = f"Bearer {token}" if token else f"Bearer {anon_key}"

        for content_type in _BLOCKED_TYPES:
            ext = content_type.split("/")[-1]
            filename = f"vibe_test.{ext}"
            url = f"{base_url}/storage/v1/object/{bucket}/{filename}"
            data = b"<script>alert(1)</script>" if "html" in content_type else b"\x7fELF"

            try:
                req = urllib.request.Request(
                    url, data=data, method="POST",
                    headers={
                        "Authorization": auth_header,
                        "apikey": anon_key,
                        "Content-Type": content_type,
                        "x-upsert": "true",
                    },
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                status = e.code
                body = ""
            except Exception:
                continue

            if status in (200, 201):
                desc = (
                    f"A file with content-type `{content_type}` was accepted by the `{bucket}` storage bucket. "
                    "If this bucket serves files publicly, an attacker could upload malicious HTML or scripts "
                    "that execute in the context of users who access the stored URL. "
                    "This can lead to stored XSS or phishing attacks."
                )
                findings.append(self.new_finding(
                    scanner=self.name, severity=Severity.MEDIUM,
                    title=f"Bucket `{bucket}` accepts potentially dangerous file type: {content_type}",
                    description=desc,
                    evidence={
                        "action_attempted": f"Upload {content_type} file to bucket '{bucket}'",
                        "auth_context": "authenticated as primary test account",
                        "request": {"method": "POST", "url": url, "headers": {"Content-Type": content_type}, "body": data.decode("utf-8", errors="replace")},
                        "response": {"status": status, "body_excerpt": truncate(body, 200)},
                        "expected_response": "400 Bad Request — file type not allowed",
                        "actual_response": f"{status} — upload accepted",
                        "second_account_used": False,
                    },
                    llm_prompt=self.build_llm_prompt(
                        title=f"Bucket `{bucket}` accepts dangerous file type: {content_type}",
                        severity=Severity.MEDIUM, scanner=self.name,
                        page=config.target, category=self.category, description=desc,
                        evidence_summary=f"Uploaded {content_type} to {url} — status {status}.",
                        stack=stack,
                    ),
                    remediation=(
                        f"**What to fix:** The `{bucket}` bucket does not restrict file types.\n\n"
                        "**How to fix:** In Supabase dashboard → Storage → {bucket} → Edit bucket, "
                        "set 'Allowed MIME types' to only what your app needs (e.g., `image/jpeg,image/png,image/gif`). "
                        "Also validate MIME types server-side — do not trust the client-supplied Content-Type.\n\n"
                        "**Verify the fix:** Re-run bucket_limits scanner."
                    ),
                    category=self.category, page=config.target,
                ))

                # Clean up
                try:
                    del_req = urllib.request.Request(
                        url, method="DELETE",
                        headers={"Authorization": auth_header, "apikey": anon_key},
                    )
                    urllib.request.urlopen(del_req, timeout=5)
                except Exception:
                    pass


def _discover_buckets(network: Any) -> list[str]:
    """Extract Supabase storage bucket names from captured network requests."""
    import re
    buckets: list[str] = []
    seen: set[str] = set()
    pattern = re.compile(r"/storage/v1/object/([^/?]+)")
    for req in network.get_requests():
        m = pattern.search(req.url)
        if m:
            bucket = m.group(1)
            if bucket not in seen:
                seen.add(bucket)
                buckets.append(bucket)
    return buckets
