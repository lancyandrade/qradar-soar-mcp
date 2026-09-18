"""Analyst projections (01 §4 step 12; 08 §7). Raw SOAR DTOs never leave the server.

Every list here is a deliberate contract, pinned by a snapshot test and
documented in the README. Adding a field is a reviewed change. Free-text
values are trimmed with a visible marker so the model knows it saw a cut.

Incident content — names, descriptions, notes, artifact values — is written
by whoever raised the incident, possibly an attacker. Projection does not
sanitise meaning; the server instructions tell the model to treat it as data.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

INCIDENT_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "description",
    "plan_status",
    "phase_id",
    "severity_code",
    "incident_type_ids",
    "owner_id",
    "discovered_date",
    "create_date",
    "start_date",
    "due_date",
    "inc_last_modified_date",
    "resolution_id",
    "resolution_summary",
    "vers",
)
TRIMMED_INCIDENT_FIELDS = frozenset({"description", "resolution_summary"})

# Character budgets per free-text value (documented in the README).
DESCRIPTION_LIMIT = 2_000
FIELD_LIMIT = 1_000
COMMENT_LIMIT = 2_000
ARTIFACT_VALUE_LIMIT = 1_000
ARTIFACT_DESCRIPTION_LIMIT = 500
TASK_INSTRUCTIONS_LIMIT = 1_000
NAME_LIMIT = 300


def text_of(value: Any) -> Any:
    """Unwrap a TextContentDTO (``{"format": ..., "content": ...}``) to its text."""
    if isinstance(value, Mapping) and "content" in value and "format" in value:
        return value.get("content")
    return value


def trim(value: Any, limit: int) -> Any:
    """Trim a free-text value to ``limit`` characters with a visible marker."""
    value = text_of(value)
    if not isinstance(value, str) or len(value) <= limit:
        return value
    cut = len(value) - limit
    return f"{value[:limit]}… [truncated {cut} chars]"


def summarise_incident(
    incident: Mapping[str, Any], custom_fields: Iterable[str] = ()
) -> dict[str, Any]:
    """The only shape an incident ever takes in MCP output (08 §7)."""
    out: dict[str, Any] = {}
    for name in INCIDENT_FIELDS:
        value = incident.get(name)
        if name in TRIMMED_INCIDENT_FIELDS:
            value = trim(value, DESCRIPTION_LIMIT)
        elif name == "name":
            value = trim(value, NAME_LIMIT)
        out[name] = value
    requested = [str(f).removeprefix("properties.") for f in custom_fields]
    if requested:
        props = incident.get("properties")
        props = props if isinstance(props, Mapping) else {}
        out["custom_fields"] = {name: trim(props.get(name), FIELD_LIMIT) for name in requested}
    return out


def summarise_comment(comment: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": comment.get("id"),
        "parent_id": comment.get("parent_id"),
        "text": trim(comment.get("text"), COMMENT_LIMIT),
        "create_date": comment.get("create_date"),
        "user_name": comment.get("user_name"),
    }


def flatten_comments(comments: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Depth-first flattening of the ``children`` tree; ``parent_id`` keeps the thread."""
    out: list[dict[str, Any]] = []
    stack = [c for c in reversed(list(comments))]
    while stack:
        comment = stack.pop()
        out.append(summarise_comment(comment))
        children = comment.get("children")
        if isinstance(children, list):
            stack.extend(c for c in reversed(children) if isinstance(c, Mapping))
    return out


def summarise_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    hits = artifact.get("hits")
    return {
        "id": artifact.get("id"),
        "type": artifact.get("type"),
        "value": trim(artifact.get("value"), ARTIFACT_VALUE_LIMIT),
        "description": trim(artifact.get("description"), ARTIFACT_DESCRIPTION_LIMIT),
        "created": artifact.get("created"),
        "hit_count": len(hits) if isinstance(hits, list) else 0,
    }


TASK_STATUS_LABELS = {"O": "open", "C": "closed"}


def summarise_task(task: Mapping[str, Any]) -> dict[str, Any]:
    status = task.get("status")
    return {
        "id": task.get("id"),
        "name": trim(task.get("name"), NAME_LIMIT),
        "phase_id": task.get("phase_id"),
        "status": status,
        "status_label": TASK_STATUS_LABELS.get(str(status)),
        "required": task.get("required"),
        "active": task.get("active"),
        "owner_id": task.get("owner_id"),
        "due_date": task.get("due_date"),
        "instructions": trim(task.get("instructions"), TASK_INSTRUCTIONS_LIMIT),
        "vers": task.get("vers"),
    }


def patch_changes(changes: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """``{field: (old, new)}`` from the client → ``{field: {"from": old, "to": new}}``."""
    out: dict[str, dict[str, Any]] = {}
    for name, pair in changes.items():
        old, new = pair
        out[name] = {"from": trim(old, FIELD_LIMIT), "to": trim(new, FIELD_LIMIT)}
    return out
