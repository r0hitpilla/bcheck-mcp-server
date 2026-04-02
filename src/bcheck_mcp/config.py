"""Settings for bcheck-mcp — read from environment variables."""

from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    def __init__(self):
        self.burp_api_url: str = os.environ.get(
            "BURP_API_URL", "http://127.0.0.1:1337/v0.1"
        )
        self.burp_api_key: str = os.environ.get("BURP_API_KEY", "")
        self.bcheck_dir: str = os.environ.get(
            "BCHECK_DIR",
            os.path.expanduser("~/bcheck-mcp-server/bchecks"),
        )
        # Comma-separated list of allowed scan targets
        raw_targets = os.environ.get("ALLOWED_TARGETS", "")
        self.allowed_targets: list[str] = (
            [t.strip() for t in raw_targets.split(",") if t.strip()]
            if raw_targets
            else []
        )
        self.bcheck_reload_wait: int = int(
            os.environ.get("BCHECK_RELOAD_WAIT", "3")
        )
        self.scan_timeout_minutes: int = int(
            os.environ.get("SCAN_TIMEOUT_MINUTES", "30")
        )

    def is_target_allowed(self, url: str) -> bool:
        """Return True if url starts with any allowed_target prefix (or no whitelist set)."""
        if not self.allowed_targets:
            return True
        return any(url.startswith(t) for t in self.allowed_targets)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
