"""Async HTTP client for the Burp Suite Professional REST API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx


class BurpAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"Burp API error {status_code}: {message}")


class BurpClient:
    """Thin async wrapper around Burp Suite Professional REST API v0.1."""

    def __init__(self, base_url: str, api_key: str = "", mock_mode: bool = False):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.mock_mode = mock_mode
        self._mock_task_id = 1000

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(method, url, headers=self._headers(), **kwargs)
        if not resp.is_success:
            raise BurpAPIError(resp.status_code, resp.text[:500])
        if resp.content:
            return resp.json()
        return {}

    async def health_check(self) -> bool:
        """Return True if Burp REST API is reachable."""
        if self.mock_mode:
            return True
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/",
                    headers=self._headers(),
                )
            return resp.status_code < 500
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    async def create_scan(
        self,
        urls: list[str],
        scan_configurations: list[dict] | None = None,
        resource_pool_name: str = "Default resource pool",
        application_logins: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """POST /v0.1/scan — create an active scan job."""
        if self.mock_mode:
            self._mock_task_id += 1
            return {
                "task_id": self._mock_task_id,
                "status": "queued",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "_mock": True,
            }

        body: dict[str, Any] = {
            "urls": urls,
            "resource_pool_name": resource_pool_name,
        }
        if scan_configurations:
            body["scan_configurations"] = scan_configurations
        if application_logins:
            body["application_logins"] = application_logins

        # Burp returns 201 with a Location header containing the task ID
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self.base_url}/scan",
                headers=self._headers(),
                json=body,
            )
        if resp.status_code not in (200, 201):
            raise BurpAPIError(resp.status_code, resp.text[:500])

        # Extract task_id from Location header: /v0.1/scan/<id>
        location = resp.headers.get("location", "")
        task_id_str = location.rstrip("/").split("/")[-1]
        try:
            task_id = int(task_id_str)
        except ValueError:
            task_id = -1

        return {
            "task_id": task_id,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_scan(self, task_id: int) -> dict[str, Any]:
        """GET /v0.1/scan/{task_id} — get scan status and progress."""
        if self.mock_mode:
            return {
                "task_id": task_id,
                "scan_status": "succeeded",
                "scan_metrics": {
                    "crawl_and_audit_progress": 100,
                    "issue_events": 3,
                },
                "_mock": True,
            }
        return await self._request("GET", f"/scan/{task_id}")

    async def get_scan_issues(self, task_id: int) -> dict[str, Any]:
        """GET /v0.1/scan/{task_id}/issues — get all issues found."""
        if self.mock_mode:
            return {
                "issue_events": [
                    {
                        "issue": {
                            "serial_number": "1001",
                            "type_index": 1049088,
                            "type_name": "SQL injection",
                            "severity": "high",
                            "confidence": "tentative",
                            "origin": "http://localhost",
                            "path": "/login",
                            "detail": "Mock SQL injection finding at /login",
                            "remediation_background": "Use parameterized queries.",
                        }
                    }
                ],
                "_mock": True,
            }
        return await self._request("GET", f"/scan/{task_id}/issues")
