"""Playbooks (P2-01, P2-05; 08 §25, §30): the list row of ``POST /playbooks/query_paged``
and the single object of ``GET /playbooks/{playbook_id}``, as catalog types.

Parsing only, as the rest of ``catalog`` does it for the collections backend: nothing here
reads SOAR, builds a catalog or holds a service. ``soar_get_playbook`` uses
:func:`parse_playbook_detail` on the one object it reads; the backend uses
:func:`parse_playbook` on every row of the paged query.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from qradar_soar_mcp.catalog.bpmn import clean_tree, summarise_bpmn
from qradar_soar_mcp.catalog.models import PlaybookDetail, PlaybookSummary, RuleCondition
from qradar_soar_mcp.errors import SoarMalformedResponseError

TEXT_LIMIT = 1_000  # as for every catalog description (backends.TEXT_LIMIT)
PLAYBOOK_SUMMARY_FAILED = "the playbook XML could not be summarised"
PLAYBOOK_OBJECT = "GET /playbooks/{id}"
# The keys of the object that identity is parsed from: exactly what ``parse_playbook``
# reads. An allow-list, so nothing else (the XML, the conditions and the values they
# compare with, people, change history, tags, keys never observed) is even cleaned, and
# arbitrarily nested JSON under some other key is never walked (found in review).
PLAYBOOK_IDENTITY_KEYS = frozenset(
    {
        "id",
        "name",
        "display_name",
        "uuid",
        "status",
        "activation_type",
        "object_type",
        "type",
        "version",
        "has_logical_errors",
        "is_deleted",
        "is_locked",
        "description",
    }
)

Row = Mapping[str, Any]


def _malformed(section: str, problem: str) -> SoarMalformedResponseError:
    # Key names only. A value SOAR returned is never put into an error message. The same
    # wording as the backend's, so a malformed row reads the same wherever it is found.
    return SoarMalformedResponseError(f"Malformed response: catalog section {section}: {problem}")


def _req(row: Row, key: str, kind: type | tuple[type, ...], section: str) -> Any:
    value = row.get(key)
    if isinstance(value, bool) and kind is not bool:
        raise _malformed(section, f"{key!r} is not of the verified type")
    if not isinstance(value, kind):
        raise _malformed(section, f"{key!r} is missing or not of the verified type")
    return value


def _opt_str(row: Row, key: str) -> str | None:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        return None
    return value[:TEXT_LIMIT]


def _opt_int(row: Row, key: str) -> int | None:
    value = row.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _flag(row: Row, key: str) -> bool:
    return row.get(key) is True


def parse_playbook(row: Row) -> PlaybookSummary:
    section = "playbooks"
    return PlaybookSummary(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        display_name=_opt_str(row, "display_name") or _req(row, "name", str, section),
        uuid=_req(row, "uuid", str, section),
        status=_req(row, "status", str, section),
        activation_type=_req(row, "activation_type", str, section),
        object_type=_req(row, "object_type", str, section),
        type=_req(row, "type", str, section),
        version=_opt_int(row, "version"),
        has_logical_errors=_flag(row, "has_logical_errors"),
        is_deleted=_flag(row, "is_deleted"),
        is_locked=_flag(row, "is_locked"),
        description=_opt_str(row, "description"),
    )


def _playbook_malformed(problem: str) -> SoarMalformedResponseError:
    # Key names only, as for a catalog section. Nothing SOAR returned is quoted.
    return SoarMalformedResponseError(f"Malformed response: {PLAYBOOK_OBJECT}: {problem}")


def _activation(row: Row, clean: Callable[[str], str]) -> dict[str, Any]:
    """The activation conditions as field names and operators. Values are never read."""
    details = row.get("activation_details")
    if details is None:
        return {"activation": "absent"}
    if not isinstance(details, Mapping):
        raise _playbook_malformed("'activation_details' is not an object")
    conditions_object = details.get("activation_conditions")
    if conditions_object is None:
        return {"activation": "absent"}
    if not isinstance(conditions_object, Mapping):
        raise _playbook_malformed("'activation_conditions' is not an object")
    # Both keys were present on every object observed. Without them nothing is known about
    # when the playbook starts, and "no conditions" would be a guess: fail closed.
    items = conditions_object.get("conditions")
    if not isinstance(items, list):
        raise _playbook_malformed("'activation_conditions.conditions' is missing or not a list")
    logic_type = conditions_object.get("logic_type")
    if not isinstance(logic_type, str):
        raise _playbook_malformed("'activation_conditions.logic_type' is missing or not text")
    kept: list[RuleCondition] = []
    unreadable = 0
    for item in items:
        field_name = item.get("field_name") if isinstance(item, Mapping) else None
        method = item.get("method") if isinstance(item, Mapping) else None
        if isinstance(field_name, str) and isinstance(method, str):
            kept.append(RuleCondition(field_name=clean(field_name), method=clean(method)))
        else:
            unreadable += 1
    return {
        "activation": "present",
        "logic_type": clean(logic_type),
        "conditions": tuple(kept),
        "unreadable_conditions": unreadable,
    }


def parse_playbook_detail(
    row: Row,
    function_by_uuid: Mapping[str, str],
    ambiguous_uuids: frozenset[str],
    clean: Callable[[str], str],
) -> PlaybookDetail:
    """The single playbook object (P2-05; 08 §30) as a :class:`PlaybookDetail`.

    Verified on 51.0.9.0.20848 (``p2_05_playbook.json``): the list row's keys, plus
    ``content`` (``content_version``, ``xml``) and ``activation_details.
    activation_conditions`` (``logic_type``; ``conditions`` of ``field_name``, ``method``,
    ``value``, ``type``, ``evaluation_id``). Identity is parsed as a list row is, from the
    object's identity keys only (``PLAYBOOK_IDENTITY_KEYS``), every string cleaned. The
    XML is summarised as SOAR sent it (cleaning text can break XML, 08 §29.2) and only
    what the summary keeps is cleaned. Condition values are never read.

    A missing or mistyped verified key is ``malformed_response``; an object without
    ``activation_details`` or ``activation_conditions`` is ``activation: absent``. XML
    that cannot be summarised safely is ``structure: refused``, never an error."""
    # Identity values are scalars; a string is cleaned, anything else is left for the
    # type checks of parse_playbook to refuse. Nothing is walked recursively here.
    identity_row = {
        k: clean(v) if isinstance(v, str) else v
        for k, v in row.items()
        if k in PLAYBOOK_IDENTITY_KEYS
    }
    try:
        summary = parse_playbook(identity_row)
    except SoarMalformedResponseError:
        raise _playbook_malformed(
            "an identity key is missing or not of the verified type"
        ) from None
    content = row.get("content")
    if not isinstance(content, Mapping):
        raise _playbook_malformed("'content' is missing or not an object")
    xml = content.get("xml")
    if not isinstance(xml, str):
        raise _playbook_malformed("'content.xml' is missing or not text")
    activation = _activation(row, clean)
    structure = summarise_bpmn(
        xml,
        function_by_uuid,
        ambiguous_uuids,
        clean,
        document="playbook",
        failed=PLAYBOOK_SUMMARY_FAILED,
    )
    detail = PlaybookDetail(
        **summary.model_dump(),
        content_version=_opt_int(content, "content_version"),
        last_modified_time=_opt_int(row, "last_modified_time"),
        **activation,
        **structure,
    )
    # Every string the detail keeps, cleaned once more as a whole (ids, names, uuids,
    # input names, problems), then validated again, as a workflow summary is.
    return PlaybookDetail.model_validate_json(
        json.dumps(clean_tree(detail.model_dump(mode="json"), clean))
    )
