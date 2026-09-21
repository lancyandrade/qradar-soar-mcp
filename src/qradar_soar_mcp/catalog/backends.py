"""Catalog backends (P2-01; 08 §25): where a catalog comes from.

Two sources are selectable with ``SOAR_CATALOG_SOURCE``, as 06 P2-01 asks, and they are
not equals. ``docs/soar-api-verified.md`` Q2 reversed 05 §2.1:

* ``collections`` — the default, and the one that works. It reads the collection
  endpoints that were verified with a read-only key, and nothing else.
* ``export`` — selectable, and **unavailable**. The one export attempt was answered 403
  and no export document was ever obtained, so there is nothing verified to parse.
  :class:`ExportBackend` refuses every load, sends nothing, and never hands the job to
  another source. It becomes a real backend when an export contract is verified.

A load either yields a complete catalog or raises. Whatever one read cannot establish is
said in ``Catalog.sections``; it is never filled in.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import ValidationError

from qradar_soar_mcp.catalog.models import (
    SECRET_INPUT_TYPES,
    VALUELESS_INPUT_TYPES,
    Catalog,
    CatalogSourceName,
    DataTableColumn,
    DataTableSpec,
    FieldSpec,
    FunctionInput,
    FunctionSpec,
    GroupSpec,
    MDSpec,
    PhaseSpec,
    PlaybookSummary,
    RuleCondition,
    RuleSpec,
    ScriptSpec,
    SectionState,
    SectionStatus,
    SelectValue,
    TypeSpec,
)
from qradar_soar_mcp.client.discovery import FIELD_TYPES
from qradar_soar_mcp.errors import SoarCatalogUnavailableError, SoarMalformedResponseError
from qradar_soar_mcp.logging import redact

if TYPE_CHECKING:
    from qradar_soar_mcp.client.base import SoarClient

logger = logging.getLogger(__name__)

DATATABLE_TYPE_ID = 8  # docs/soar-api-verified.md Q4
PROPERTIES_PREFIX = "properties"
TEXT_LIMIT = 1_000  # descriptions, tooltips and placeholders are configuration, kept short
# The page length P2-00b sent live (and 1, by P2-00), both from start 0. A later page
# (start > 0) is the documented paging of this query and was never needed live: the
# research org had fewer than ten playbooks. So the pages must add up to recordsTotal,
# or the load fails.
PLAYBOOK_PAGE_LENGTH = 10
# Bounds on what one load may ask of the appliance. Exceeding one fails the load; a
# catalog is never cut short.
MAX_PLAYBOOK_PAGES = 200
MAX_FUNCTIONS = 1_000

EXPORT_UNAVAILABLE = (
    "SOAR_CATALOG_SOURCE=export is not available: the configuration export is unverified "
    "for QRadar SOAR 51.0.9.0.20848 (the one attempt, with a read-only key, was answered "
    "HTTP 403 and no export document was obtained), so there is no export contract to "
    "parse. Nothing was sent to SOAR and no other source was used. Set "
    "SOAR_CATALOG_SOURCE=collections"
)
NO_PERMISSION_SOURCE = (
    "a read-only API key cannot read its own permission set on 51.0.9.0.20848, and "
    "successful reads do not show what a key may write"
)
NO_APP_SOURCE = "no verified read reports installed apps or their versions"
WORKFLOW_SHAPE_UNVERIFIED = (
    "the workflow object is unverified on 51.0.9.0.20848 (SOAR returned none to the "
    "research key); the rows SOAR returned were counted and not parsed"
)

Row = Mapping[str, Any]


class CatalogBackend(Protocol):
    """Builds one complete catalog, or raises. Never returns part of one."""

    source: CatalogSourceName

    async def load(self) -> Catalog: ...


# ------------------------------------------------------------------ parsing
def _malformed(section: str, problem: str) -> SoarMalformedResponseError:
    # Key names only. A value SOAR returned is never put into an error message.
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


def _strings(row: Row, key: str) -> tuple[str, ...]:
    value = row.get(key)
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _select_values(row: Row) -> tuple[SelectValue, ...]:
    """The values of a select-type field, and never a person or a secret: nothing for a
    credential- or member-typed field, and no value that SOAR marks as a principal (the
    users and groups an owner or members field offers)."""
    if row.get("input_type") in VALUELESS_INPUT_TYPES:
        return ()
    out: list[SelectValue] = []
    values = row.get("values")
    for item in values if isinstance(values, list) else ():
        if not isinstance(item, Mapping) or not isinstance(item.get("label"), str):
            continue
        if "principal_type" in item:
            continue
        raw = item.get("value")
        out.append(
            SelectValue(
                label=item["label"][:TEXT_LIMIT],
                value=raw if isinstance(raw, int | str) and not isinstance(raw, bool) else None,
                enabled=item.get("enabled") is not False,
                default=item.get("default") is True,
            )
        )
    return tuple(out)


def _keyed[S](section: str, specs: list[tuple[str, S]]) -> dict[str, S]:
    out: dict[str, S] = {}
    for key, spec in specs:
        if key in out:
            # Two objects under one name: refusing beats silently keeping one of them.
            raise _malformed(section, "two entries share one name")
        out[key] = spec
    return out


def parse_function_input(field: Row) -> FunctionInput:
    section = "functions"
    input_type = _req(field, "input_type", str, section)
    secret = input_type in SECRET_INPUT_TYPES
    return FunctionInput(
        name=_req(field, "name", str, section),
        uuid=_req(field, "uuid", str, section),
        label=_opt_str(field, "text") or _req(field, "name", str, section),
        input_type=input_type,
        required=_opt_str(field, "required"),
        # A credential-typed input keeps its identity and nothing a value could hide in.
        tooltip=None if secret else _opt_str(field, "tooltip"),
        placeholder=None if secret else _opt_str(field, "placeholder"),
        values=_select_values(field),
    )


def parse_function(detail: Row, inputs_by_uuid: Mapping[str, FunctionInput]) -> FunctionSpec:
    """``view_items[].content`` joined to the ``__function`` fields by uuid (Q5)."""
    section = "functions"
    items = detail.get("view_items")
    if not isinstance(items, list):
        raise _malformed(section, "'view_items' is missing or not a list")
    inputs: list[FunctionInput] = []
    unresolved = 0
    for item in items:
        content = item.get("content") if isinstance(item, Mapping) else None
        resolved = inputs_by_uuid.get(content) if isinstance(content, str) else None
        if resolved is None:
            unresolved += 1
        elif resolved not in inputs:
            inputs.append(resolved)
    return FunctionSpec(
        id=_req(detail, "id", int, section),
        name=_req(detail, "name", str, section),
        uuid=_req(detail, "uuid", str, section),
        display_name=_opt_str(detail, "display_name") or _req(detail, "name", str, section),
        description=_opt_str(detail, "description"),
        destination_handle=_opt_str(detail, "destination_handle"),
        version=_opt_int(detail, "version"),
        inputs=tuple(inputs),
        unresolved_inputs=unresolved,
    )


def parse_script(row: Row) -> ScriptSpec:
    section = "scripts"
    return ScriptSpec(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        programmatic_name=_req(row, "programmatic_name", str, section),
        uuid=_req(row, "uuid", str, section),
        language=_req(row, "language", str, section),
        object_type=_req(row, "object_type", str, section),
        enabled=_req(row, "enabled", bool, section),
        description=_opt_str(row, "description"),
    )


def parse_message_destination(row: Row) -> MDSpec:
    section = "message_destinations"
    return MDSpec(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        programmatic_name=_req(row, "programmatic_name", str, section),
        uuid=_req(row, "uuid", str, section),
        destination_type=_req(row, "destination_type", int, section),
        expect_ack=_req(row, "expect_ack", bool, section),
    )


def parse_incident_type(row: Row) -> TypeSpec:
    section = "incident_types"
    parent = row.get("parent_id")
    return TypeSpec(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        uuid=_req(row, "uuid", str, section),
        enabled=_req(row, "enabled", bool, section),
        hidden=_req(row, "hidden", bool, section),
        system=_req(row, "system", bool, section),
        parent_id=parent
        if isinstance(parent, int | str) and not isinstance(parent, bool)
        else None,
    )


def parse_phase(row: Row) -> PhaseSpec:
    section = "phases"
    return PhaseSpec(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        uuid=_req(row, "uuid", str, section),
        enabled=_req(row, "enabled", bool, section),
        order=_req(row, "order", int, section),
    )


def parse_field(type_name: str, row: Row) -> FieldSpec:
    section = "fields"
    name = _req(row, "name", str, section)
    custom = row.get("prefix") == PROPERTIES_PREFIX
    return FieldSpec(
        type_name=type_name,
        name=name,
        api_name=f"{PROPERTIES_PREFIX}.{name}" if custom else name,
        prefix=_opt_str(row, "prefix"),
        label=_opt_str(row, "text") or name,
        input_type=_req(row, "input_type", str, section),
        custom=custom,
        required=_opt_str(row, "required"),
        read_only=_flag(row, "read_only"),
        internal=_flag(row, "internal"),
        values=_select_values(row),
    )


def parse_datatable(row: Row) -> DataTableSpec:
    section = "datatables"
    fields = row.get("fields")
    if not isinstance(fields, Mapping):
        raise _malformed(section, "'fields' is missing or not a map")
    columns = []
    for column in fields.values():
        if not isinstance(column, Mapping):
            raise _malformed(section, "a column is not an object")
        name = _req(column, "name", str, section)
        columns.append(
            DataTableColumn(
                name=name,
                label=_opt_str(column, "text") or name,
                input_type=_req(column, "input_type", str, section),
                order=_opt_int(column, "order"),
                required=_opt_str(column, "required"),
            )
        )
    columns.sort(key=lambda c: (c.order is None, c.order or 0, c.name))
    return DataTableSpec(
        id=_req(row, "id", int, section),
        type_name=_req(row, "type_name", str, section),
        display_name=_opt_str(row, "display_name") or _req(row, "type_name", str, section),
        uuid=_req(row, "uuid", str, section),
        parent_types=_strings(row, "parent_types"),
        columns=tuple(columns),
    )


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


def parse_rule(row: Row) -> RuleSpec:
    section = "rules"
    conditions = row.get("conditions")
    return RuleSpec(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        uuid=_req(row, "uuid", str, section),
        type=_req(row, "type", int, section),
        object_type=_req(row, "object_type", str, section),
        enabled=_req(row, "enabled", bool, section),
        logic_type=_opt_str(row, "logic_type"),
        timeout_seconds=_opt_int(row, "timeout_seconds"),
        message_destinations=_strings(row, "message_destinations"),
        conditions=tuple(
            RuleCondition(field_name=c["field_name"], method=c["method"])
            for c in (conditions if isinstance(conditions, list) else ())
            if isinstance(c, Mapping)
            and isinstance(c.get("field_name"), str)
            and isinstance(c.get("method"), str)
        ),
    )


def parse_group(row: Row) -> GroupSpec:
    section = "groups"
    return GroupSpec(
        id=_req(row, "id", int, section),
        name=_req(row, "name", str, section),
        uuid=_req(row, "uuid", str, section),
        enabled=_req(row, "enabled", bool, section),
        is_assignable=_flag(row, "is_assignable"),
        is_task_assignable=_flag(row, "is_task_assignable"),
    )


# -------------------------------------------------------------- collections
class CollectionsBackend:
    """The verified read-only collection endpoints, through ``client.discovery`` only."""

    source: CatalogSourceName = "collections"

    def __init__(self, client: SoarClient, *, now: Callable[[], datetime] | None = None) -> None:
        self._client = client
        self._now = now or (lambda: datetime.now(UTC))

    def _clean(self, value: Any) -> Any:
        """Every string SOAR returned, with this server's credential and anything shaped
        like one removed, before a spec is built from it. SOAR has no reason to echo the
        API key into configuration text; if it ever does, the catalog does not keep it."""
        if isinstance(value, str):
            return redact(self._client.scrub(value) or "")
        if isinstance(value, list):
            return [self._clean(item) for item in value]
        if isinstance(value, dict):
            return {key: self._clean(item) for key, item in value.items()}
        return value

    async def _read[T](self, call: Awaitable[T]) -> T:
        return self._clean(await call)  # type: ignore[no-any-return]

    async def load(self) -> Catalog:
        api = self._client.discovery
        read = self._read
        soar_version = await read(api.server_version())
        sections: dict[str, SectionStatus] = {}
        content: dict[str, dict[str, Any]] = {}

        def loaded(name: str, specs: list[tuple[str, Any]]) -> None:
            content[name] = _keyed(name, specs)
            sections[name] = SectionStatus(state=SectionState.LOADED, count=len(content[name]))

        loaded("functions", await self._functions())
        loaded(
            "scripts",
            [(s.programmatic_name, s) for s in map(parse_script, await read(api.scripts()))],
        )
        loaded(
            "message_destinations",
            [
                (d.programmatic_name, d)
                for d in map(parse_message_destination, await read(api.message_destinations()))
            ],
        )
        loaded(
            "incident_types",
            [
                (t.name, t)
                for t in map(parse_incident_type, (await read(api.incident_types())).values())
            ],
        )
        loaded("phases", [(p.name, p) for p in map(parse_phase, await read(api.phases()))])
        fields: list[tuple[str, FieldSpec]] = []
        for type_name in FIELD_TYPES:
            for row in await read(api.type_fields(type_name)):
                spec = parse_field(type_name, row)
                # Keyed with SOAR's own prefix, whatever it is, so that one name under
                # two prefixes is two fields. For ``properties`` this is the api name.
                qualified = f"{spec.prefix}.{spec.name}" if spec.prefix else spec.name
                fields.append((f"{type_name}.{qualified}", spec))
        loaded("fields", fields)
        loaded(
            "datatables",
            [
                (t.type_name, t)
                for t in (
                    parse_datatable(row)
                    for row in (await read(api.types())).values()
                    if row.get("type_id") == DATATABLE_TYPE_ID
                )
            ],
        )
        loaded("playbooks", [(p.name, p) for p in map(parse_playbook, await self._playbooks())])
        loaded("rules", [(r.name, r) for r in map(parse_rule, await read(api.rules()))])
        loaded("groups", [(g.name, g) for g in map(parse_group, await read(api.groups()))])

        workflows = await read(api.workflows())
        sections["workflows"] = (
            SectionStatus(
                state=SectionState.UNVERIFIED,
                count=len(workflows),
                reason=WORKFLOW_SHAPE_UNVERIFIED,
            )
            if workflows
            else SectionStatus(state=SectionState.LOADED, count=0)
        )
        sections["api_key_permissions"] = SectionStatus(
            state=SectionState.NOT_OBSERVABLE, reason=NO_PERMISSION_SOURCE
        )
        sections["installed_apps"] = SectionStatus(
            state=SectionState.NOT_OBSERVABLE, reason=NO_APP_SOURCE
        )
        try:
            catalog = Catalog.model_validate(
                {
                    "source": self.source,
                    "fetched_at": self._now(),
                    "soar_version": soar_version,
                    "org_id": str(self._client.org_id),
                    "sections": sections,
                    **content,
                }
            )
        except ValidationError as exc:  # unreachable unless a parser above is wrong
            raise _malformed("catalog", f"{exc.error_count()} model errors") from None
        logger.info(
            "catalog loaded from %s: %s",
            self.source,
            ", ".join(f"{name}={status.count}" for name, status in sections.items()),
        )
        return catalog

    async def _functions(self) -> list[tuple[str, FunctionSpec]]:
        api = self._client.discovery
        rows = await self._read(api.functions())
        if len(rows) > MAX_FUNCTIONS:
            raise _malformed("functions", f"more than {MAX_FUNCTIONS} functions")
        inputs = {
            i.uuid: i for i in map(parse_function_input, await self._read(api.function_fields()))
        }
        specs: list[tuple[str, FunctionSpec]] = []
        for row in rows:
            # The list row's view_items is empty on this version; the single object's is not.
            detail = await self._read(api.function(_req(row, "id", int, "functions")))
            spec = parse_function(detail, inputs)
            specs.append((spec.name, spec))
        return specs

    async def _playbooks(self) -> list[Row]:
        api = self._client.discovery
        rows: list[Row] = []
        for page in range(MAX_PLAYBOOK_PAGES):
            result = await self._read(
                api.playbooks_page(start=page * PLAYBOOK_PAGE_LENGTH, length=PLAYBOOK_PAGE_LENGTH)
            )
            rows.extend(result["items"])
            if not result["items"] or len(rows) >= result["total"]:
                if len(rows) != result["total"]:
                    # An early empty page, or more rows than SOAR counted: not a catalog.
                    raise _malformed("playbooks", "the pages do not add up to recordsTotal")
                return rows
        raise _malformed(
            "playbooks", f"more than {MAX_PLAYBOOK_PAGES * PLAYBOOK_PAGE_LENGTH} playbooks"
        )


# ------------------------------------------------------------------- export
class ExportBackend:
    """Selectable, and unavailable: see the module docstring. It holds no client, so it
    cannot send anything, and it knows no other backend, so it cannot fall back."""

    source: CatalogSourceName = "export"

    async def load(self) -> Catalog:
        raise SoarCatalogUnavailableError(EXPORT_UNAVAILABLE, not_sent=True)


def build_backend(source: str, client: SoarClient) -> CatalogBackend:
    """The backend ``SOAR_CATALOG_SOURCE`` names. An unknown name is a bug, not a default."""
    if source == "collections":
        return CollectionsBackend(client)
    if source == "export":
        return ExportBackend()
    raise ValueError(f"unknown catalog source {source!r}")
