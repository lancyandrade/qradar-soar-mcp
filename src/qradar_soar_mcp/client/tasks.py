"""Tasks: the incident-scoped list, one task, and its status (08 §24).

Changing a task's status follows the contract verified on QRadar SOAR 51.0.9.0.20848
(docs/soar-api-verified.md §3.1), and nothing wider::

    GET /tasks/{task_id} -> deep copy -> change status only -> PUT /tasks/{task_id} -> GET

Both calls carry the two output-format controls as headers, in the form the contract
was verified with. The ``PUT`` body is the complete object the ``GET`` returned:
nothing is dropped, added or normalised, ``closed_date`` is the server's and is passed
through as read, and no version field is sent because none was observed.

The ``PUT`` is sent once and never retried. Once it may have reached SOAR, only the
read-back says what the task's status is. Two outcomes end the call without it: reliable
evidence that the request was never sent, and SOAR's own application-level refusal (an
HTTP-200 StatusDTO with ``success: false``). Every other outcome (``success: true``, an
answer that establishes neither, **any HTTP error status, 4xx included**, a timeout, a
dropped connection) is settled by that one ``GET``, and is a success only if it shows the
requested status. No HTTP status is taken as proof that the task was left alone: nothing
in docs/soar-api-verified.md establishes that for this call (08 §24).

Nothing here protects a task against a concurrent edit: on that appliance no conflict
was ever observed and no version field was seen on a task. The read and the write are
kept adjacent; a change made by someone else between them can still be overwritten.
"""

from __future__ import annotations

import copy
import json
import logging
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

logger = logging.getLogger(__name__)

TASK_STATUS_CODES: dict[str, str] = {"open": "O", "closed": "C"}
PUT_ACCEPTED = "success"


def _rules_out_the_write(failure: SoarError) -> bool:
    """Whether a failed PUT leaves no doubt that the task was not changed by it.

    Only reliable evidence that the request never left this process does (``not_sent``).

    No HTTP status does, 4xx included. The record for QRadar SOAR 51.0.9.0.20848
    (docs/soar-api-verified.md) has no basis for it: the reference lists 400, 401, 403,
    404, 409, 500 and 503 for this call as the same boilerplate it lists for the GET,
    with no meaning attached; 422 and 429 are not listed at all; the only error statuses
    seen live (403, 404, 500) were answers to reads and to one export POST, all with
    the same generic error object; and of that 403 the record states that it proves
    nothing about side effects (Q2). No refused task PUT was ever observed. A status
    class convention is not appliance evidence, so every answered PUT is read back.
    """
    return failure.not_sent


@dataclass(frozen=True, slots=True)
class TaskStatusOutcome:
    """What a status change did: the task as read before the PUT and after it.

    ``put_answer`` is ``success`` when SOAR said so, else ``unconfirmed (<why>)``: the
    change was then established by the read-back alone.
    """

    pre_image: dict[str, Any]
    post_image: dict[str, Any]
    changes: dict[str, tuple[Any, Any]]
    put_answer: str = PUT_ACCEPTED


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
                f"task {int(task_id)} is not reported active and unfrozen; its status is "
                "not changed here"
            )

        candidate = copy.deepcopy(current)
        candidate["status"] = code
        path = self._c.org_path(f"tasks/{int(task_id)}")
        # Sent once, never retried. The exception is kept and re-raised outside the
        # ``except`` block so nothing is chained.
        response: Any = None
        put_failure: SoarError | None = None
        try:
            response = await self._c.put(
                path, json_body=candidate, format_headers=TASK_FORMAT_HEADERS
            )
        except SoarError as exc:
            put_failure = exc
        if put_failure is not None and _rules_out_the_write(put_failure):
            raise put_failure
        answer = response.get("success") if isinstance(response, dict) else None
        if put_failure is None and answer is False:
            message = response.get("message")
            text = self._c.scrub(" ".join(str(message).split())) if message else "success=false"
            raise SoarValidationError(
                f"Task update rejected on PUT {path}: {(text or '')[:200]}",
                status=200,
                detail=self._c.scrub(json.dumps(response, default=str)),
            )

        # From here the PUT may have changed the task. SOAR either said so, or its answer
        # establishes nothing; only the read-back decides, and it is made exactly once.
        put_detail: str | None = None
        if put_failure is None and answer is True:
            put_answer = PUT_ACCEPTED
            lead = f"PUT {path} ({before} -> {code}) was accepted"
        else:
            if put_failure is None:
                reason = "malformed_response"
            elif put_failure.status is not None and put_failure.status >= 400:
                # The status itself, not this server's name for it: a 409 is reported as
                # what SOAR answered, never as a detected conflict.
                reason = f"HTTP {put_failure.status}"
            else:
                reason = put_failure.code
            put_answer = f"unconfirmed ({reason})"
            lead = (
                f"PUT {path} ({before} -> {code}) was sent, but SOAR's answer did not "
                f"establish its result ({reason})"
            )
            if put_failure is not None:
                put_detail = put_failure.detail
            else:
                put_detail = self._c.scrub(json.dumps(response, default=str))
            logger.warning("soar PUT %s -> outcome unconfirmed (%s); reading back", path, reason)

        failure: SoarError | None = None
        after: dict[str, Any] = {}
        try:
            after = await self.get(task_id)
        except SoarError as exc:
            failure = exc
        if failure is not None:
            raise SoarUnverifiedWriteError(
                f"{lead}. The task could not be read back ({failure.code}); its state is "
                "unverified. List the incident's tasks before retrying",
                detail="; ".join(d for d in (put_detail, failure.detail) if d) or None,
            )
        if after.get("status") != code:
            raise SoarUnverifiedWriteError(
                f"{lead}. The task does not show status {code!r} afterwards; whether the "
                "write took effect is unverified. List the incident's tasks before retrying",
                detail=put_detail,
            )
        return TaskStatusOutcome(
            pre_image=current,
            post_image=after,
            changes={"status": (before, code)},
            put_answer=put_answer,
        )
