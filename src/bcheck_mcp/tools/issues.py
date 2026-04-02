"""MCP tool: get_scan_issues — async-native."""

from __future__ import annotations

from bcheck_mcp.burp.client import BurpAPIError, BurpClient
from bcheck_mcp.config import get_settings


def _make_client() -> BurpClient:
    s = get_settings()
    return BurpClient(base_url=s.burp_api_url, api_key=s.burp_api_key)


async def get_scan_issues(
    task_id: int,
    severity_filter: str | None = None,
    vuln_type_filter: str | None = None,
) -> dict:
    client = _make_client()
    try:
        raw = await client.get_scan_issues(task_id)
    except BurpAPIError as e:
        return {"error": str(e), "task_id": task_id}

    events = raw.get("issue_events", [])
    issues = []

    for event in events:
        issue = event.get("issue", event)
        severity = issue.get("severity", "").lower()
        type_name = issue.get("type_name", "")

        if severity_filter and severity != severity_filter.lower():
            continue
        if vuln_type_filter and vuln_type_filter.lower() not in type_name.lower():
            continue

        issues.append({
            "serial_number": issue.get("serial_number", ""),
            "type_name": type_name,
            "severity": severity,
            "confidence": issue.get("confidence", ""),
            "url": f"{issue.get('origin', '')}{issue.get('path', '')}",
            "detail": issue.get("detail", ""),
            "remediation": issue.get("remediation_background", ""),
        })

    return {
        "task_id": task_id,
        "total_count": len(issues),
        "issues": issues,
        "mock": raw.get("_mock", False),
    }
