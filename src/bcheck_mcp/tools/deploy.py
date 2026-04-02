"""MCP tool: deploy_bcheck — write BCheck files to Burp's watched directory."""

from __future__ import annotations

from bcheck_mcp.bcheck.validator import validate
from bcheck_mcp.config import get_settings
from bcheck_mcp.filesystem.manager import FileSystemManager


def deploy_bcheck(
    checks: list[dict],
    overwrite: bool = True,
) -> dict:
    """
    Deploy generated BCheck scripts to Burp Suite's watched BCheck directory.

    Burp hot-reloads .bcheck files from this directory automatically.
    After deploying, wait ~3 seconds before triggering a scan (handled by create_scan).

    Args:
        checks: List of BCheckScript dicts from generate_bcheck().
                Each must have 'filename' and 'dsl_content' keys.
        overwrite: If False, skip files that already exist. Default True.

    Returns:
        dict with 'deployed', 'skipped', 'errors' filename lists and 'bcheck_dir' path.
    """
    settings = get_settings()

    # Validate each check before writing
    validated_checks = []
    pre_errors: list[str] = []

    for check in checks:
        dsl = check.get("dsl_content", "")
        filename = check.get("filename", "<unknown>")
        errors = validate(dsl)
        if errors:
            pre_errors.append(
                f"{filename}: validation failed — {'; '.join(errors)}"
            )
        else:
            validated_checks.append(check)

    manager = FileSystemManager(settings.bcheck_dir)
    result = manager.deploy(validated_checks, overwrite=overwrite)
    result["validation_errors"] = pre_errors

    return result
