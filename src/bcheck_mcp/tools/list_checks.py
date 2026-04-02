"""MCP tool: list_deployed_checks — enumerate .bcheck files in the watched directory."""

from __future__ import annotations

from bcheck_mcp.config import get_settings
from bcheck_mcp.filesystem.manager import FileSystemManager


def list_deployed_checks(include_content: bool = False) -> dict:
    """
    List all BCheck files currently deployed in Burp's watched directory.

    Args:
        include_content: If True, include the full DSL content of each check.
                         Default False.

    Returns:
        dict with 'bcheck_dir' path and 'checks' list.
        Each check has: filename, name, tags, file_size_bytes, deployed_at,
        and optionally 'content'.
    """
    settings = get_settings()
    manager = FileSystemManager(settings.bcheck_dir)
    checks = manager.list_checks(include_content=include_content)

    return {
        "bcheck_dir": settings.bcheck_dir,
        "check_count": len(checks),
        "checks": checks,
    }
