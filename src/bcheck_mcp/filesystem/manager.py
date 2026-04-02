"""Atomic .bcheck file management for the Burp-watched directory."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path


class FileSystemManager:
    def __init__(self, bcheck_dir: str):
        self.bcheck_dir = Path(bcheck_dir)

    def deploy(
        self,
        checks: list[dict],
        overwrite: bool = True,
    ) -> dict:
        """Write .bcheck files atomically. Returns deployed/skipped/errors lists."""
        deployed: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []

        for check in checks:
            filename = check.get("filename", "")
            content = check.get("dsl_content", "")

            if not filename or not content:
                errors.append(f"INVALID: missing filename or dsl_content in check entry")
                continue

            target_path = self.bcheck_dir / filename
            tmp_path = self.bcheck_dir / f".{filename}.tmp"

            if target_path.exists() and not overwrite:
                skipped.append(filename)
                continue

            try:
                tmp_path.write_text(content, encoding="utf-8")
                os.replace(tmp_path, target_path)
                deployed.append(filename)
            except OSError as e:
                errors.append(f"{filename}: {e}")
                # Clean up temp file if it exists
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

        return {
            "deployed": deployed,
            "skipped": skipped,
            "errors": errors,
            "bcheck_dir": str(self.bcheck_dir),
        }

    def list_checks(self, include_content: bool = False) -> list[dict]:
        """List all .bcheck files in the watched directory."""
        results = []
        for path in sorted(self.bcheck_dir.glob("*.bcheck")):
            try:
                stat = path.stat()
                content = path.read_text(encoding="utf-8")
                entry = {
                    "filename": path.name,
                    "name": _extract_metadata_field(content, "name"),
                    "tags": _extract_metadata_field(content, "tags"),
                    "file_size_bytes": stat.st_size,
                    "deployed_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
                if include_content:
                    entry["content"] = content
                results.append(entry)
            except OSError:
                pass
        return results

    def check_writable(self) -> bool:
        return os.access(self.bcheck_dir, os.W_OK)


def _extract_metadata_field(dsl: str, field: str) -> str:
    """Extract a field value from BCheck metadata block."""
    pattern = rf'^\s*{re.escape(field)}:\s*"?([^"\n]+)"?\s*$'
    match = re.search(pattern, dsl, re.MULTILINE)
    return match.group(1).strip() if match else ""
