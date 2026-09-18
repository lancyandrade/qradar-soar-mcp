"""Manual actions on an incident: the incident-scoped list, and invocation.

Both calls are ✅ in 05 §1. The invocation body is exactly ``{"action_id": N}``.
"""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarValidationError


class ActionsClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list_for_incident(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/actions"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /incidents/{id}/actions did not return a list")
        return [
            {
                "id": a.get("id"),
                "name": a.get("name"),
                "object_type": a.get("object_type"),
                "enabled": bool(a.get("enabled", True)),
            }
            for a in body
            if isinstance(a, dict) and "id" in a and "name" in a
        ]

    async def invoke(self, incident_id: int, action_id: int) -> dict[str, Any]:
        if isinstance(action_id, bool) or int(action_id) <= 0:
            raise SoarValidationError("action_id must be a positive integer")
        await self._c.post(
            self._c.org_path(f"incidents/{int(incident_id)}/action_invocations"),
            json_body={"action_id": int(action_id)},
        )
        return {"incident_id": int(incident_id), "action_id": int(action_id), "invoked": True}
