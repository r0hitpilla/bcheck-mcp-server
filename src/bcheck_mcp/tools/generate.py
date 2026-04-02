"""MCP tool: generate_bcheck — build BCheck DSL from user intent."""

from __future__ import annotations

from bcheck_mcp.bcheck.builder import build
from bcheck_mcp.bcheck.templates import SUPPORTED_CLASSES


def generate_bcheck(
    description: str,
    target_url: str,
    vuln_classes: list[str] | None = None,
    severity_filter: str = "medium",
    passive_only: bool = False,
) -> dict:
    """
    Generate Burp BCheck DSL scripts for the specified vulnerability classes.

    This tool does NOT write any files — call deploy_bcheck() to deploy them.
    Review the returned dsl_content before deploying.

    Args:
        description: Natural language description of what to test, e.g.
                     "Test login form for SQL injection".
        target_url: Target URL being tested, e.g. "http://target.example.com".
        vuln_classes: List of vulnerability classes to generate checks for.
                      Supported: sqli, xss, ssrf, path_traversal, cmdi, xxe, idor, open_redirect.
                      If empty, the tool infers classes from 'description'.
        severity_filter: Minimum severity level for generated checks (low/medium/high/critical).
        passive_only: If True, only generate passive (non-modifying) checks.

    Returns:
        dict with 'checks' (list of BCheckScript dicts) and 'warnings' (list of strings).
    """
    if passive_only:
        return {
            "checks": [],
            "warnings": [
                "passive_only=True is not yet supported. "
                "All current templates are active checks."
            ],
        }

    scripts = build(
        description=description,
        target_url=target_url,
        vuln_classes=vuln_classes or [],
    )

    all_warnings: list[str] = []
    checks_out = []

    for s in scripts:
        if s.warnings:
            all_warnings.extend([f"[{s.vuln_class}] {w}" for w in s.warnings])
        checks_out.append(s.to_dict())

    if not checks_out:
        all_warnings.append(
            f"No checks generated. Provide one or more vuln_classes from: {SUPPORTED_CLASSES}"
        )

    return {
        "checks": checks_out,
        "supported_vuln_classes": SUPPORTED_CLASSES,
        "warnings": all_warnings,
    }
