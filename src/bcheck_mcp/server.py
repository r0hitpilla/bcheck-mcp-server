"""BCheck MCP Server — autonomous BCheck writer driven by real Burp proxy traffic."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from bcheck_mcp.tools.analyze import analyze_request
from bcheck_mcp.tools.write import write_bcheck
from bcheck_mcp.tools.scan import create_scan, get_scan_status
from bcheck_mcp.tools.issues import get_scan_issues
from bcheck_mcp.tools.list_checks import list_deployed_checks
from bcheck_mcp.bcheck.syntax_guide import BCHECK_SYNTAX_GUIDE

mcp = FastMCP(
    "bcheck-mcp",
    instructions=(
        "You are an autonomous BCheck security researcher. "
        "Workflow: (1) use the Burp MCP get_proxy_http_history tool to get real HTTP requests, "
        "(2) call analyze_request_tool to extract injection points, "
        "(3) call get_bcheck_syntax_guide_tool to learn DSL syntax, "
        "(4) write custom BCheck DSL targeting the exact params found — do NOT use generic templates, "
        "(5) call write_bcheck_tool to validate and deploy your DSL, "
        "(6) call create_scan_tool to start the scan, "
        "(7) poll get_scan_status_tool until done, "
        "(8) call get_scan_issues_tool to report findings."
    ),
)


@mcp.tool()
def analyze_request_tool(
    raw_request: str,
    raw_response: str = "",
) -> str:
    """
    Parse a raw HTTP request from Burp proxy history and map every injection point.

    Call this after getting a request from the Burp MCP get_proxy_http_history tool.
    Returns structured injection points, suggested vulnerability classes, and
    BCheck DSL writing hints so you can author a precise, custom BCheck script.

    Args:
        raw_request: Raw HTTP/1.x request text (headers + body).
        raw_response: Optional raw HTTP response — improves vuln class suggestions
                      and helps detect false-positive-prone error strings.
    """
    result = analyze_request(
        raw_request=raw_request,
        raw_response=raw_response if raw_response else None,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def write_bcheck_tool(
    dsl_content: str,
    filename: str = "",
    overwrite: bool = True,
) -> str:
    """
    Validate and save a BCheck DSL script you authored to Burp's watched directory.

    Burp hot-reloads .bcheck files automatically — the check is live within ~3 seconds.
    Call create_scan_tool after this to run the scan.

    IMPORTANT: Write the full BCheck v2-beta DSL yourself based on the injection points
    returned by analyze_request_tool. Do NOT use generic templates — write checks that
    target the specific parameter names, body format, and vulnerability indicators
    found in the actual request.

    Args:
        dsl_content: Complete BCheck v2-beta DSL string. Must include metadata block
                     and at least one given...then...end block.
        filename: Optional .bcheck filename. Auto-generated from the name: field if omitted.
        overwrite: If False, fail if file already exists.
    """
    result = write_bcheck(
        dsl_content=dsl_content,
        filename=filename if filename else None,
        overwrite=overwrite,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def get_bcheck_syntax_guide_tool() -> str:
    """
    Return the complete BCheck v2-beta DSL syntax reference.

    Call this before writing BCheck DSL to ensure correct syntax.
    Covers: metadata fields, given/then/end structure, send payload variants,
    param targeting (query/body/JSON/cookie/header), response conditions,
    Collaborator OOB patterns, and full worked examples for every vuln class.
    """
    return BCHECK_SYNTAX_GUIDE


@mcp.tool()
async def create_scan_tool(
    target_url: str,
    bcheck_only: bool = True,
    scan_configurations: list[str] | None = None,
    resource_pool: str = "Default resource pool",
    application_logins: list[dict] | None = None,
) -> str:
    """
    Create an active scan job in Burp Suite Professional.

    Automatically waits for Burp to hot-reload deployed BCheck files before starting.

    By default (bcheck_only=True) injects an inline CustomConfiguration that disables
    all Burp built-in audit checks and runs only extension/BCheck scripts. No named
    configuration needs to exist in the Burp UI — works out of the box.

    Set bcheck_only=False to run BChecks + all Burp built-in checks (slow, noisy).
    Pass scan_configurations to override with specific named Burp configurations.

    Args:
        target_url: URL to scan (must be in ALLOWED_TARGETS env var if set).
        bcheck_only: If True (default), only run deployed BCheck scripts. If False,
                     also run Burp's full built-in audit suite.
        scan_configurations: Override scan config names (ignores bcheck_only if set).
        resource_pool: Burp resource pool name.
        application_logins: Optional [{"username": "...", "password": "..."}] for auth scanning.
    """
    result = await create_scan(
        target_url=target_url,
        scan_configurations=scan_configurations,
        resource_pool=resource_pool,
        application_logins=application_logins,
        bcheck_only=bcheck_only,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_scan_status_tool(task_id: int) -> str:
    """
    Get the current status and progress of a Burp scan.

    Poll every 15 seconds until status is 'succeeded' or 'failed'.

    Args:
        task_id: The task ID returned by create_scan_tool.
    """
    result = await get_scan_status(task_id=task_id)
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_scan_issues_tool(
    task_id: int,
    severity_filter: str = "",
    vuln_type_filter: str = "",
) -> str:
    """
    Retrieve the full list of vulnerabilities found by a completed Burp scan.

    Call after get_scan_status_tool returns status='succeeded'.

    Args:
        task_id: The task ID returned by create_scan_tool.
        severity_filter: Optional filter — "info" | "low" | "medium" | "high" | "critical".
        vuln_type_filter: Optional substring match on issue type name, e.g. "SQL".
    """
    result = await get_scan_issues(
        task_id=task_id,
        severity_filter=severity_filter if severity_filter else None,
        vuln_type_filter=vuln_type_filter if vuln_type_filter else None,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def list_deployed_checks_tool(include_content: bool = False) -> str:
    """
    List all BCheck files currently deployed in Burp's watched directory.

    Args:
        include_content: If True, include the full DSL of each check.
    """
    result = list_deployed_checks(include_content=include_content)
    return json.dumps(result, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
