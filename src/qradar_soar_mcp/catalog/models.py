"""The catalog and its typed specs (P2-01; 04 §1; 08 §25).

Every model is frozen and forbids unknown keys, so a catalog read back from JSON is
either exactly this schema or rejected; nothing is accepted in part.

The shape follows 04 §1 with the adjustments 08 §25 records, each of them there so the
catalog never says more than QRadar SOAR ``51.0.9.0.20848`` was seen to say
(``docs/soar-api-verified.md``):

* ``sections`` tells a *known empty* section from one that could *not be observed*. An
  empty ``workflows`` with state ``loaded`` means SOAR returned no workflow; an empty
  ``api_key_permissions`` with state ``not_observable`` means nothing at all.
* ``source`` names the backend that built the catalog, and ``format_version`` the schema
  of the JSON form.

What a spec carries is a projection fixed here, never the raw SOAR object. Principals
(creators, members, API-key names, the users and groups a member-type field offers as
values), script bodies, playbook XML, output examples and free-text defaults are not part
of any spec, and a ``password``-typed input or field keeps its name, label, type and
required-ness and nothing else.

The models are frozen; the mappings inside a catalog are ordinary dicts. The cache hands
one instance to every caller, so a catalog is read, never edited in place.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

FORMAT_VERSION = 1
CatalogSourceName = Literal["collections", "export"]

# Input types whose definition may hold a credential. Only ``password`` is named by
# 04 §1; it was not among the input types seen on 51.0.9.0.20848.
SECRET_INPUT_TYPES = frozenset({"password"})
# Input types whose values are people and groups (seen on 51.0.9.0.20848).
PRINCIPAL_INPUT_TYPES = frozenset({"select_owner", "multiselect_members"})
VALUELESS_INPUT_TYPES = SECRET_INPUT_TYPES | PRINCIPAL_INPUT_TYPES


class CatalogFormatError(ValueError):
    """A JSON document is not a catalog of this schema. Nothing of it is used."""


class SectionState(StrEnum):
    """How much the catalog knows about one of its sections."""

    # Read from SOAR in a verified shape. The section is complete as SOAR returned
    # it, so an empty section is a known-empty one.
    LOADED = "loaded"
    # SOAR returned rows, but their shape is not verified for this version. None was
    # parsed; ``count`` says how many there were.
    UNVERIFIED = "unverified"
    # No verified source exists for this section. Its emptiness says nothing.
    NOT_OBSERVABLE = "not_observable"


class _Spec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class SectionStatus(_Spec):
    state: SectionState
    count: int = 0
    reason: str | None = None


class SelectValue(_Spec):
    """One value of a select-type field or input."""

    label: str
    value: int | str | None = None
    enabled: bool = True
    default: bool = False


class FunctionInput(_Spec):
    """A function input: a ``__function`` field a function's ``view_items`` points at."""

    name: str
    uuid: str
    label: str
    input_type: str
    required: str | None = None
    tooltip: str | None = None
    placeholder: str | None = None
    values: tuple[SelectValue, ...] = ()

    @model_validator(mode="after")
    def _secret_inputs_carry_no_defaults(self) -> Self:
        if self.input_type in SECRET_INPUT_TYPES and (
            self.values or self.placeholder or self.tooltip
        ):
            raise ValueError(
                f"a {self.input_type}-typed input carries no values, placeholder or tooltip"
            )
        if self.input_type in PRINCIPAL_INPUT_TYPES and self.values:
            raise ValueError(f"a {self.input_type}-typed input carries no values")
        return self


class FunctionSpec(_Spec):
    id: int
    name: str
    uuid: str
    display_name: str
    description: str | None = None
    # As SOAR returns it with ``handle_format=names``.
    destination_handle: str | None = None
    version: int | None = None
    inputs: tuple[FunctionInput, ...] = ()
    # view_items that did not resolve to a ``__function`` field. Never guessed at.
    unresolved_inputs: int = 0


class ScriptSpec(_Spec):
    """A script, without its body: the list row of ``GET /scripts``."""

    id: int
    name: str
    programmatic_name: str
    uuid: str
    language: str
    object_type: str
    enabled: bool
    description: str | None = None


class MDSpec(_Spec):
    """A message destination, without the API keys and users bound to it."""

    id: int
    name: str
    programmatic_name: str
    uuid: str
    destination_type: int
    expect_ack: bool


class TypeSpec(_Spec):
    """An incident type."""

    id: int
    name: str
    uuid: str
    enabled: bool
    hidden: bool
    system: bool
    parent_id: int | str | None = None


class PhaseSpec(_Spec):
    id: int
    name: str
    uuid: str
    enabled: bool
    order: int


class FieldSpec(_Spec):
    """A field of ``incident``, ``task`` or ``artifact``. Custom fields are
    ``properties.<name>``, as everywhere else in this server. ``prefix`` is SOAR's own
    value, kept as it came; only ``properties`` is given a meaning here."""

    type_name: str
    name: str
    api_name: str
    prefix: str | None = None
    label: str
    input_type: str
    custom: bool
    required: str | None = None
    read_only: bool = False
    internal: bool = False
    values: tuple[SelectValue, ...] = ()

    @model_validator(mode="after")
    def _no_values_for_secrets_or_people(self) -> Self:
        if self.input_type in VALUELESS_INPUT_TYPES and self.values:
            raise ValueError(f"a {self.input_type}-typed field carries no values")
        return self


class DataTableColumn(_Spec):
    """A column. No values at all: a table is referenced by name and column."""

    name: str
    label: str
    input_type: str
    order: int | None = None
    required: str | None = None


class DataTableSpec(_Spec):
    """A type with ``type_id == 8`` (``docs/soar-api-verified.md`` Q4)."""

    id: int
    type_name: str
    display_name: str
    uuid: str
    parent_types: tuple[str, ...] = ()
    columns: tuple[DataTableColumn, ...] = ()


class PlaybookSummary(_Spec):
    """A row of ``POST /playbooks/query_paged``, without principals and change log."""

    id: int
    name: str
    display_name: str
    uuid: str
    status: str
    activation_type: str
    object_type: str
    type: str
    version: int | None = None
    has_logical_errors: bool = False
    is_deleted: bool = False
    is_locked: bool = False
    description: str | None = None


class RuleCondition(_Spec):
    """Which field a rule looks at and how. The compared value is not carried."""

    field_name: str
    method: str


class RuleSpec(_Spec):
    """A rule: ``actions`` in the API (05 §2)."""

    id: int
    name: str
    uuid: str
    type: int
    object_type: str
    enabled: bool
    logic_type: str | None = None
    timeout_seconds: int | None = None
    message_destinations: tuple[str, ...] = ()
    conditions: tuple[RuleCondition, ...] = ()


class WorkflowSummary(_Spec):
    """Deliberately without fields. SOAR returned no workflow to the research key, so no
    key of the workflow object is verified (``docs/soar-api-verified.md`` §3, §7.9), and P2-01
    never builds one: a non-empty ``GET /workflows`` makes the section ``unverified``.
    The type exists so that the catalog has the shape of 04 §1 for P2-04 to fill."""


class GroupSpec(_Spec):
    """A group, without its members."""

    id: int
    name: str
    uuid: str
    enabled: bool
    is_assignable: bool = False
    is_task_assignable: bool = False


# Every section of 04 §1, in its order.
MAPPING_SECTIONS: tuple[str, ...] = (
    "functions",
    "scripts",
    "message_destinations",
    "incident_types",
    "phases",
    "fields",
    "datatables",
    "playbooks",
    "rules",
    "workflows",
    "groups",
    "installed_apps",
)
SECTION_NAMES: tuple[str, ...] = (*MAPPING_SECTIONS, "api_key_permissions")


class Catalog(_Spec):
    format_version: Literal[1] = 1
    source: CatalogSourceName
    fetched_at: AwareDatetime
    soar_version: str
    org_id: str
    sections: dict[str, SectionStatus]
    functions: dict[str, FunctionSpec] = {}
    scripts: dict[str, ScriptSpec] = {}
    message_destinations: dict[str, MDSpec] = {}
    incident_types: dict[str, TypeSpec] = {}
    phases: dict[str, PhaseSpec] = {}
    fields: dict[str, FieldSpec] = {}
    datatables: dict[str, DataTableSpec] = {}
    playbooks: dict[str, PlaybookSummary] = {}
    rules: dict[str, RuleSpec] = {}
    workflows: dict[str, WorkflowSummary] = {}
    groups: dict[str, GroupSpec] = {}
    api_key_permissions: frozenset[str] = frozenset()
    installed_apps: dict[str, str] = {}

    # ---------------------------------------------------------- validation
    @field_validator("fetched_at", mode="after")
    @classmethod
    def _as_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _sections_agree_with_content(self) -> Self:
        if set(self.sections) != set(SECTION_NAMES):
            raise ValueError("sections must name every catalog section, and nothing else")
        for name in SECTION_NAMES:
            status, size = self.sections[name], len(getattr(self, name))
            if status.state is SectionState.LOADED:
                if status.count != size:
                    raise ValueError(f"{name}: count {status.count} but {size} entries")
            elif size:
                raise ValueError(f"{name}: a section that is {status.state} holds no entries")
        return self

    # --------------------------------------------------------------- JSON
    @field_serializer("api_key_permissions", when_used="json")
    def _sorted_permissions(self, value: frozenset[str]) -> list[str]:
        return sorted(value)

    def to_json(self) -> str:
        """Stable text: sorted keys, sorted sets, UTC timestamp. Ends with a newline."""
        return (
            json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> Catalog:
        """The catalog a JSON document describes.

        Raises:
            CatalogFormatError: if it is not JSON or not exactly this schema (strict:
                no coercion, no unknown key). The message names where the problem is (key
                names, which include the names objects have in SOAR) and never a value.
        """
        try:
            return cls.model_validate_json(text)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in err['loc']) or 'catalog'}: {err['msg']}"
                for err in exc.errors(include_input=False, include_url=False)[:10]
            )
            raise CatalogFormatError(f"not a catalog of this schema: {problems}") from None

    # ------------------------------------------------------------ summary
    def summary(self) -> dict[str, Any]:
        """Metadata and counts: what ``soar_refresh_catalog`` returns. No spec content."""
        return {
            "source": self.source,
            "fetched_at": self.fetched_at.isoformat(),
            "soar_version": self.soar_version,
            "org_id": self.org_id,
            "counts": {
                name: status.count
                for name, status in self.sections.items()
                if status.state is SectionState.LOADED
            },
            "not_loaded": {
                name: {"state": str(status.state), "count": status.count, "reason": status.reason}
                for name, status in self.sections.items()
                if status.state is not SectionState.LOADED
            },
        }
