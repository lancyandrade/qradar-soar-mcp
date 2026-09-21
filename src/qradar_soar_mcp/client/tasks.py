"""Tasks: the incident-scoped list, one task, and its status (08 §24).

Changing a task's status follows the contract verified on QRadar SOAR 51.0.9.0.20848
(docs/soar-api-verified.md §3.1), and nothing wider::

    GET /tasks/{task_id} -> deep copy -> change status only -> PUT /tasks/{task_id} -> GET

Both calls carry the two output-format controls as headers, in the form the contract
was verified with. The ``PUT`` body is the complete object the ``GET`` returned:
nothing is dropped, added or normalised, ``closed_date`` is the server's and is passed
through as read, and no version field is sent because none was observed.

Nothing here protects a task against a concurrent edit: on that appliance no conflict
was ever observed and no version field was seen on a task. The read and the write are
kept adjacent; a change made by someone else between them can still be overwritten.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from qradar_soar_mcp.client.base import TASK_FORMAT_HEADERS, SoarClient
from qradar_soar_mcp.errors import (
    SoarError,
    SoarMalformedResponseError,
    SoarNotFoundError,
    SoarUnverifiedWriteError,
    SoarValidationError,
)

TASK_STATUS_CODES: dict[str, str] = {"open": "O", "closed": "C"}


@dataclass(frozen=True, slots=True)
class TaskStatusOutcome:
    """What a status change did: the task as read before the PUT and after it."""

    pre_image: dict[str, Any]
    post_image: dict[str, Any]
    changes: dict[str, tuple[Any, Any]]


class TasksClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/tasks"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /incidents/{id}/tasks did not return a list")
        return [t for t in body if isinstance(t, dict)]

    async def get(self, task_id: int) -> dict[str, Any]:
        """One task, in the representation ``PUT /tasks/{task_id}`` was verified to accept."""
        body = await self._c.get(
            self._c.org_path(f"tasks/{int(task_id)}"), format_headers=TASK_FORMAT_HEADERS
        )
        if not isinstance(body, dict) or body.get("id") != int(task_id):
            raise SoarMalformedResponseError("GET /tasks/{id} did not return that task")
        return body

    async def set_status(self, incident_id: int, task_id: int, status: str) -> TaskStatusOutcome:
        """Open or close one task of one incident; ``status`` is ``open`` or ``closed``.

        Refused before anything is written: an unknown status, a task that is not in
        ``incident_id``, one already in the requested status, and one that does not
        report ``active: true`` and ``frozen: false`` (the contract was verified on an
        active, unfrozen task only).
        """
        code = TASK_STATUS_CODES.get(status) if isinstance(status, str) else None
        if code is None:
            raise SoarValidationError(f"task status must be one of {sorted(TASK_STATUS_CODES)}")
        current = await self.get(task_id)
        owner = current.get("inc_id")
        if not isinstance(owner, int) or isinstance(owner, bool):
            raise SoarMalformedResponseError("GET /tasks/{id} returned a task without an inc_id")
        if owner != int(incident_id):
            # That pair does not exist. No HTTP status: SOAR answered 200 for the task.
            raise SoarNotFoundError(
                f"Not found: task {int(task_id)} on incident {int(incident_id)}"
            )
        before = current.get("status")
        if before not in TASK_STATUS_CODES.values():
            raise SoarMalformedResponseError("GET /tasks/{id} returned an unknown task status")
        if before == code:
            raise SoarValidationError(f"task {int(task_id)} is already {status}; nothing was sent")
        if current.get("active") is not True or current.get("frozen") is not False:
            raise SoarValidationError(
                f"task {int(task_id)} is inactive or frozen; its status is not changed here"
            )

        candidate = copy.deepcopy(current)
        candidate["status"] = code
        path = self._c.org_path(f"tasks/{int(task_id)}")
        response = await self._c.put(path, json_body=candidate, format_headers=TASK_FORMAT_HEADERS)
        if not isinstance(response, dict) or not isinstance(response.get("success"), bool):
            raise SoarMalformedResponseError(
                f"PUT {path} ({before} -> {code}) did not return a status object; "
                "the task's state is unverified"
            )
        if response["success"] is not True:
            message = response.get("message")
            text = self._c.scrub(" ".join(str(message).split())) if message else "success=false"
            raise SoarValidationError(
                f"Task update rejected on PUT {path}: {(text or '')[:200]}",
                status=200,
                detail=self._c.scrub(json.dumps(response, default=str)),
            )

        failure: SoarError | None = None
        after: dict[str, Any] = {}
        try:
            after = await self.get(task_id)
        except SoarError as exc:
            failure = exc
        if failure is not None:
            raise SoarUnverifiedWriteError(
                f"PUT {path} ({before} -> {code}) was accepted but the task could not be "
                f"read back ({failure.code}); its state is unverified. List the incident's "
                "tasks before retrying",
                detail=failure.detail,
            )
        if after.get("status") != code:
            raise SoarUnverifiedWriteError(
                f"PUT {path} ({before} -> {code}) was accepted but the task does not show "
                f"status {code!r} afterwards. List the incident's tasks before retrying"
            )
        return TaskStatusOutcome(
            pre_image=current, post_image=after, changes={"status": (before, code)}
        )
