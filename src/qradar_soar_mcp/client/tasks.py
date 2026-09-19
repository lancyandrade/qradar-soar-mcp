"""Tasks: the incident-scoped list. Changing a task is not implemented (08 §21).

On QRadar SOAR 51.0.9.0.20848 the appliance documents ``PUT /tasks/{task_id}``
and no ``PATCH``, and a task carries no version (docs/soar-api-verified.md §3,
D1/D2). The method and path are verified; the ``PUT`` request body is not. This
client therefore sends nothing to a task, by any method, until that body is
verified (P2-00b): ``soar_update_task_status`` is refused before it reaches the
client.
"""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.errors import SoarMalformedResponseError


class TasksClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/tasks"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /incidents/{id}/tasks did not return a list")
        return [t for t in body if isinstance(t, dict)]
