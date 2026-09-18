"""Tasks: list per incident; change status with ``PATCH /tasks/{id}`` (never PUT).

The task's current DTO — and the version the PatchDTO needs — comes from the
incident-scoped list (``GET /incidents/{id}/tasks``), the only task read in the
Phase-1 contract. Whether that DTO carries ``vers`` on every SOAR version is an
open question for P2-00; if it does not, the PATCH is refused rather than sent
without a version.
"""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import PatchOutcome, SoarClient
from qradar_soar_mcp.errors import (
    SoarMalformedResponseError,
    SoarNotFoundError,
    SoarValidationError,
)

STATUS_CODES: dict[str, str] = {"open": "O", "closed": "C", "o": "O", "c": "C"}


class TasksClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/tasks"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /incidents/{id}/tasks did not return a list")
        return [t for t in body if isinstance(t, dict)]

    async def set_status(self, incident_id: int, task_id: int, status: str) -> PatchOutcome:
        code = STATUS_CODES.get(status.strip().lower())
        if code is None:
            raise SoarValidationError("task status must be 'open' or 'closed'")
        tasks = await self.list(incident_id)
        current = next((t for t in tasks if t.get("id") == int(task_id)), None)
        if current is None:
            raise SoarNotFoundError(
                f"Not found: task {int(task_id)} on incident {int(incident_id)}", status=404
            )
        path = self._c.org_path(f"tasks/{int(task_id)}")
        if current.get("status") == code:
            return PatchOutcome(
                path=path,
                version_before=int(current.get("vers", 0)),
                pre_image=current,
                post_image=current,
                changes={},
            )
        result = await self._c.patch_object(path, current, {"status": code})
        post = dict(current)
        post["status"] = code
        post["vers"] = int(result["version"]) + 1
        return PatchOutcome(
            path=path,
            version_before=int(result["version"]),
            pre_image=current,
            post_image=post,
            changes=dict(result["changes"]),
        )
