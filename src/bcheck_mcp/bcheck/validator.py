"""Structural validator for BCheck DSL v2-beta (correct syntax)."""

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
            errors.append(f"Invalid language value '{lang_val}'; must be v2-beta")

    # Must have exactly one given...then block
    given_blocks = re.findall(r"\bgiven\b.+\bthen\b", dsl)
    if len(given_blocks) == 0:
        errors.append("No 'given ... then' block found")
    elif len(given_blocks) > 1:
        errors.append(
            f"Found {len(given_blocks)} 'given...then' blocks — only ONE allowed per file. "
            "Use separate .bcheck files for each check."
        )

    # given...then must NOT be closed with bare 'end' — it ends at EOF
    # Detect the bad pattern: a bare 'end' after the last 'end if'
    stripped = dsl.rstrip()
    if stripped.endswith("\nend") or stripped == "end":
        errors.append(
            "given...then block must NOT be closed with 'end'. "
            "The block ends at EOF — remove the trailing 'end'."
        )

    # if...then must close with 'end if' — not bare 'end'
    if_count = len(re.findall(r"\bif\b.+\bthen\b", dsl))
    end_if_count = len(re.findall(r"\bend if\b", dsl))
    if if_count > 0 and end_if_count == 0:
        errors.append("'if...then' blocks must close with 'end if', not bare 'end'")
    elif if_count != end_if_count:
        errors.append(
            f"Mismatched if/end if: found {if_count} 'if...then' but {end_if_count} 'end if'"
        )

    # send payload syntax — must use colon form
    if re.search(r"send payload replacing", dsl):
        errors.append(
            "Invalid send payload syntax: use 'send payload:\\n    replacing: \"payload\"' "
            "(colon + indented form), not 'send payload replacing ...'"
        )

    # Must have at least one report issue
    if "report issue" not in dsl:
        errors.append("No 'report issue:' block found — check will never report findings")
    else:
        # report issue must have severity and confidence
        report_blocks = re.findall(r"report issue:(.*?)(?=end if|\Z)", dsl, re.DOTALL)
        for i, block in enumerate(report_blocks):
            if "severity:" not in block:
                errors.append(f"report issue block {i + 1} missing 'severity:'")
            if "confidence:" not in block:
                errors.append(f"report issue block {i + 1} missing 'confidence:'")

    # Wrong response references — match bare response.body not preceded by 'latest.'
    if re.search(r"(?<!latest\.)(?<!\w)response\.body\b", dsl):
        errors.append(
            "Use 'latest.response.body' not 'response.body'"
        )
    if re.search(r"(?<!latest\.)(?<!\w)response\.time\b", dsl) or re.search(r"\bresponse time\b", dsl):
        errors.append(
            "Use 'latest.response.duration' not 'response.time' or 'response time'"
        )

    return errors
