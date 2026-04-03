"""MCP tools: create_scan and get_scan_status — async-native."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from bcheck_mcp.burp.client import BurpAPIError, BurpClient
from bcheck_mcp.config import get_settings

# Inline scan configuration that disables all Burp built-in audit checks
# and runs only extension/BCheck checks. Sent as CustomConfiguration so no
# named config needs to exist in the Burp UI.
_BCHECK_ONLY_CONFIG: dict = {
    "type": "CustomConfiguration",
    "config": json.dumps({
        "scanner": {
            "audit_checks": {
                "burp_built_in_checks_enabled": False,
                "extension_checks_enabled": True,
            }
        }
    }),
}


def _make_client() -> BurpClient:
    s = get_settings()
    return BurpClient(base_url=s.burp_api_url, api_key=s.burp_api_key)


async def create_scan(
    target_url: str,
    scan_configurations: list[str] | None = None,
    resource_pool: str = "Default resource pool",
    application_logins: list[dict] | None = None,
    bcheck_only: bool = True,
) -> dict:
    settings = get_settings()

    if not settings.is_target_allowed(target_url):
        return {
            "error": (
                f"Target '{target_url}' is not in the allowed_targets whitelist. "
                f"Add it to ALLOWED_TARGETS env var."
            ),
            "allowed_targets": settings.allowed_targets,
        }

    # Build configuration dicts for the Burp API
    if scan_configurations is not None:
        # Caller provided explicit named configurations — pass them through
        config_dicts: list[dict] | None = [
            {"type": "NamedConfiguration", "name": n} for n in scan_configurations
        ]
    elif bcheck_only:
        # Use inline CustomConfiguration: disables built-in checks, runs BChecks only.
        # No named config needs to exist in Burp UI — works out of the box.
        config_dicts = [_BCHECK_ONLY_CONFIG]
    else:
        config_dicts = None

    await asyncio.sleep(settings.bcheck_reload_wait)

    client = _make_client()
    try:
        result = await client.create_scan(
            urls=[target_url],
            scan_configurations=config_dicts,
            resource_pool_name=resource_pool,
            application_logins=application_logins or None,
        )
    except BurpAPIError as e:
        return {"error": str(e)}

    task_id = result.get("task_id", -1)
    return {
        "task_id": task_id,
        "status_url": f"{settings.burp_api_url}/scan/{task_id}",
        "created_at": result.get("created_at", datetime.now(timezone.utc).isoformat()),
        "mock": result.get("_mock", False),
    }


async def get_scan_status(task_id: int) -> dict:
    client = _make_client()
    try:
        raw = await client.get_scan(task_id)
    except BurpAPIError as e:
        return {"error": str(e), "task_id": task_id}

    metrics = raw.get("scan_metrics", {})
    raw_status = raw.get("scan_status", "unknown").lower()

    return {
        "task_id": task_id,
        "status": raw_status,
        "progress": metrics.get("crawl_and_audit_progress", 0),
        "issue_count": metrics.get("issue_events", 0),
        "mock": raw.get("_mock", False),
    }
