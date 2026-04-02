"""write_bcheck — validate and save a BCheck DSL string authored by Claude."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from bcheck_mcp.bcheck.validator import validate
from bcheck_mcp.config import get_settings


def write_bcheck(
    dsl_content: str,
    filename: str | None = None,
    overwrite: bool = True,
) -> dict:
    """
    Validate and save a BCheck DSL script to Burp's watched directory.

    This is the final step after Claude has written the BCheck DSL.
    Burp hot-reloads .bcheck files from the watched directory automatically.

    Args:
        dsl_content: Complete BCheck v2-beta DSL string authored by Claude.
        filename: Optional filename (must end in .bcheck). Auto-generated if omitted.
        overwrite: If False, fail if the file already exists.

    Returns:
        dict with 'success' (bool), 'filename', 'path', 'errors' list.
        On success, the file is live in Burp immediately.
    """
    settings = get_settings()
    bcheck_dir = Path(settings.bcheck_dir)

    # Auto-generate filename from metadata name field
    if not filename:
        name_match = re.search(r'^\s*name:\s*"?([^"\n]+)"?\s*$', dsl_content, re.MULTILINE)
        if name_match:
            raw_name = name_match.group(1).strip()
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_name)[:60]
        else:
            safe = "custom_check"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{safe}_{ts}.bcheck"

    if not filename.endswith(".bcheck"):
        filename += ".bcheck"

    target_path = bcheck_dir / filename

    if target_path.exists() and not overwrite:
        return {
            "success": False,
            "filename": filename,
            "path": str(target_path),
            "errors": [f"File already exists and overwrite=False: {filename}"],
        }

    # Validate DSL structure
    errors = validate(dsl_content)
    if errors:
        return {
            "success": False,
            "filename": filename,
            "path": str(target_path),
            "errors": errors,
            "dsl_preview": dsl_content[:400],
        }

    # Write atomically
    tmp_path = bcheck_dir / f".{filename}.tmp"
    try:
        bcheck_dir.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(dsl_content, encoding="utf-8")
        tmp_path.replace(target_path)
    except OSError as e:
        return {
            "success": False,
            "filename": filename,
            "path": str(target_path),
            "errors": [str(e)],
        }
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    return {
        "success": True,
        "filename": filename,
        "path": str(target_path),
        "errors": [],
        "note": "Burp will hot-reload this file within ~3 seconds. Then call create_scan_tool.",
    }
