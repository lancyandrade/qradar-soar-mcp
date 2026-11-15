"""Incident history reads for ``soar_analyse_incident_response`` (P2-07; 08 §35).

Exactly two calls, both ``GET``, both answered 200 on QRadar SOAR 51.0.9.0.20848
(``docs/soar-api-verified.md`` Q8):

* ``GET /incidents/{id}/history``: an object of seven ``*_history`` keys. Only
  ``incident_detail_history`` was seen holding rows (``date``, ``revision_number``,
  ``diffs[].name`` ...); the other six were null. :meth:`HistoryClient.incident_history`
  keeps, per row, the revision number, the date and the names of the changed fields, and
  for the other keys only whether they held anything. Values, old and new, and the user
  who made a change are never returned.
* ``GET /incidents/{id}/workflow_instances``: ``{"entities": []}`` on the one incident
  read, so the row shape is unknown and no row is parsed; only the count is returned.

A body that is not in that shape is reported as such (``shape_verified`` false) rather
than raised, so the tool can say what it could not read and carry on. Transport and HTTP
errors are raised as usual; the caller decides whether to degrade.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from qradar_soar_mcp.client.base import SoarClient

# The keys of the verified history object. incident_detail_history is the only one whose
# rows were seen; the rest are reported as present or not, never parsed.
HISTORY_KEYS: tuple[str, ...] = (
    "artifact_history",
    "attachment_history",
    "data_type_history",
    "incident_detail_history",
    "milestone_history",
    "record_count_history",
    "task_history",
)
DETAIL_KEY = "incident_detail_history"
MAX_FIELD_NAME = 200
MAX_DETAIL_ROWS = 10_000


@dataclass(frozen=True, slots=True)
class HistoryRevision:
    revision_number: int | None
    date: int | None
    changed_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IncidentHistory:
    shape_verified: bool
    revisions: tuple[HistoryRevision, ...] = ()  # the rows that could be read
    total_rows: int = 0  # every row of incident_detail_history, read or not
    unparsed_rows: int = 0  # detail rows without the verified fields
    other_sections_with_data: tuple[str, ...] = ()  # known keys holding data, not parsed
    rows_cut: bool = False


@dataclass(frozen=True, slots=True)
class WorkflowInstances:
    shape_verified: bool
    count: int = 0


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _field_names(diffs: Any) -> tuple[str, ...] | None:
    if not isinstance(diffs, list):
        return None
    names: list[str] = []
    for diff in diffs:
        name = diff.get("name") if isinstance(diff, dict) else None
        if not isinstance(name, str) or not name.strip() or len(name) > MAX_FIELD_NAME:
            return None
        names.append(name.strip())
    return tuple(names)


def parse_history(body: Any) -> IncidentHistory:
    """The verified part of a history object; anything else is counted, never read."""
    if not isinstance(body, dict) or not set(HISTORY_KEYS) <= set(body):
        return IncidentHistory(shape_verified=False)
    rows = body.get(DETAIL_KEY)
    if rows is not None and not isinstance(rows, list):
        return IncidentHistory(shape_verified=False)
    others = tuple(k for k in HISTORY_KEYS if k != DETAIL_KEY and body.get(k) not in (None, []))
    revisions: list[HistoryRevision] = []
    unparsed = 0
    for row in (rows or [])[:MAX_DETAIL_ROWS]:
        names = _field_names(row.get("diffs")) if isinstance(row, dict) else None
        if names is None:
            unparsed += 1
            continue
        number, date = _int(row.get("revision_number")), _int(row.get("date"))
        revisions.append(HistoryRevision(number, date, names))
    return IncidentHistory(
        shape_verified=True,
        revisions=tuple(revisions),
        total_rows=len(rows or []),
        unparsed_rows=unparsed,
        other_sections_with_data=others,
        rows_cut=len(rows or []) > MAX_DETAIL_ROWS,
    )


def parse_workflow_instances(body: Any) -> WorkflowInstances:
    entities = body.get("entities") if isinstance(body, dict) else None
    if not isinstance(entities, list):
        return WorkflowInstances(shape_verified=False)
    # Zero rows is the only shape seen; rows are counted and not read.
    return WorkflowInstances(shape_verified=not entities, count=len(entities))


class HistoryClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def incident_history(self, incident_id: int) -> IncidentHistory:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/history"))
        return parse_history(body)

    async def workflow_instances(self, incident_id: int) -> WorkflowInstances:
        body = await self._c.get(
            self._c.org_path(f"incidents/{int(incident_id)}/workflow_instances")
        )
        return parse_workflow_instances(body)
