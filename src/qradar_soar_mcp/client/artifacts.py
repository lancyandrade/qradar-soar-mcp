"""Incident artifacts: list and add."""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import SoarClient, text_content
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarValidationError

MAX_ARTIFACT_VALUE_LENGTH = 4_000


class ArtifactsClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/artifacts"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /artifacts did not return a list")
        return [a for a in body if isinstance(a, dict)]

    async def add(
        self, incident_id: int, type_name: str, value: str, *, description: str | None = None
    ) -> dict[str, Any]:
        if not type_name.strip():
            raise SoarValidationError("artifact type is required")
        if not value.strip():
            raise SoarValidationError("artifact value is required")
        if len(value) > MAX_ARTIFACT_VALUE_LENGTH:
            raise SoarValidationError(
                f"artifact value exceeds {MAX_ARTIFACT_VALUE_LENGTH} characters"
            )
        body: dict[str, Any] = {"type": type_name, "value": value}
        if description:
            body["description"] = text_content(description)
        resp = await self._c.post(
            self._c.org_path(f"incidents/{int(incident_id)}/artifacts"), json_body=body
        )
        if not isinstance(resp, dict) or "id" not in resp:
            raise SoarMalformedResponseError("POST /artifacts did not return an artifact")
        return resp
