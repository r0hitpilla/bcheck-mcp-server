"""Structural validator for BCheck DSL v2-beta."""

from __future__ import annotations

import re

MAX_FILE_SIZE = 64 * 1024  # 64 KB


def validate(dsl: str) -> list[str]:
    """Return a list of validation errors. Empty list means valid."""
    errors: list[str] = []

    if len(dsl.encode("utf-8")) > MAX_FILE_SIZE:
        errors.append(f"BCheck exceeds maximum file size of {MAX_FILE_SIZE // 1024} KB")

    # Required metadata fields
    for field in ("language", "name", "description", "author"):
        if not re.search(rf"^\s*{field}:", dsl, re.MULTILINE):
            errors.append(f"Missing required metadata field: {field}")

    # language must be v2-beta
    lang_match = re.search(r"^\s*language:\s*(.+)$", dsl, re.MULTILINE)
    if lang_match:
        lang_val = lang_match.group(1).strip().strip('"')
        if lang_val != "v2-beta":
            errors.append(f"Invalid language value '{lang_val}'; must be 'v2-beta'")

    # Must have at least one given...then...end block
    if not re.search(r"\bgiven\b.+\bthen\b", dsl, re.DOTALL):
        errors.append("No 'given ... then' block found")

    if "end" not in dsl:
        errors.append("No 'end' keyword found — check block structure")

    # report issue block must have severity and confidence
    if "report issue" in dsl:
        report_blocks = re.findall(
            r"report issue(.+?)end", dsl, re.DOTALL
        )
        for i, block in enumerate(report_blocks):
            if "severity:" not in block:
                errors.append(f"report issue block {i + 1} missing 'severity'")
            if "confidence:" not in block:
                errors.append(f"report issue block {i + 1} missing 'confidence'")
    else:
        errors.append("No 'report issue' block found — check will never report findings")

    return errors
