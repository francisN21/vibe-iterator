"""Generate structured LLM fix prompts for each Finding."""

from __future__ import annotations

from vibe_iterator.scanners.base import Finding


def build_prompt(finding: Finding, *, stack: str = "unknown") -> str:
    """Generate a copy-paste LLM prompt for a Finding.

    Follows the mandatory template from SCANNERS.md. Keeps output under
    ~800 tokens so it fits any AI assistant context window.
    """
    evidence_summary = _format_evidence(finding)

    return (
        f"You are a security expert helping me fix a vulnerability in my web application.\n\n"
        f"VULNERABILITY: {finding.title}\n"
        f"SEVERITY: {finding.severity.value.upper()}\n"
        f"SCANNER: {finding.scanner}\n"
        f"PAGE: {finding.page}\n"
        f"CATEGORY: {finding.category}\n\n"
        f"WHAT WAS FOUND:\n{finding.description}\n\n"
        f"EVIDENCE:\n{evidence_summary}\n\n"
        f"YOUR TASK:\n"
        f"Fix the vulnerability described above in my codebase.\n\n"
        f"1. Explain what the root cause is\n"
        f"2. Show me the specific code change needed (with before/after if possible)\n"
        f"3. If this involves {stack}-specific config (RLS policies, storage rules, auth settings), "
        f"show me the exact config change\n"
        f"4. Confirm what I should test after applying the fix to verify it's resolved\n\n"
        f"My stack: {stack}"
    )


def _format_evidence(finding: Finding) -> str:
    """Produce a compact, readable evidence summary from the Finding's evidence dict."""
    ev = finding.evidence
    lines: list[str] = []

    # Request / response pair (most scanner categories have this)
    req = ev.get("request")
    resp = ev.get("response")
    if req and isinstance(req, dict):
        lines.append(f"Request: {req.get('method', 'GET')} {req.get('url', '')}")
        if req.get("body"):
            body = str(req["body"])[:200]
            lines.append(f"  Body: {body}")
    if resp and isinstance(resp, dict):
        lines.append(f"Response: {resp.get('status', '?')} — {str(resp.get('body_excerpt', ''))[:200]}")

    # Injection-specific
    if ev.get("payload_used"):
        lines.append(f"Payload: {ev['payload_used']}")
    if ev.get("injection_point"):
        lines.append(f"Injection point: {ev['injection_point']}")

    # Access control
    if ev.get("action_attempted"):
        lines.append(f"Action attempted: {ev['action_attempted']}")
    if ev.get("expected_response") and ev.get("actual_response"):
        lines.append(f"Expected: {ev['expected_response']}")
        lines.append(f"Actual:   {ev['actual_response']}")

    # Auth check
    if ev.get("check_name"):
        lines.append(f"Check: {ev['check_name']}")
    if ev.get("observed_value"):
        lines.append(f"Observed: {ev['observed_value']}")
    if ev.get("expected_behavior"):
        lines.append(f"Expected: {ev['expected_behavior']}")

    # Tampering
    if ev.get("storage_key"):
        lines.append(f"Storage key: {ev['storage_key']}")
        lines.append(f"  Original:  {ev.get('original_value', '?')}")
        lines.append(f"  Tampered:  {ev.get('tampered_value', '?')}")

    # Data leakage
    if ev.get("leak_type"):
        lines.append(f"Leak type: {ev['leak_type']}")
        lines.append(f"Location:  {ev.get('leak_location', '?')}")
        lines.append(f"Excerpt:   {ev.get('leaked_value_excerpt', '?')}")

    # CORS
    if ev.get("test_origin_sent"):
        lines.append(f"Test origin: {ev['test_origin_sent']}")
        headers = ev.get("response_headers", {})
        acao = headers.get("Access-Control-Allow-Origin", "not set")
        lines.append(f"ACAO header: {acao}")

    if not lines:
        lines.append("See full evidence in the scan results.")

    return "\n".join(lines)
