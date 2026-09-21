"""P2-01: the catalog models and their JSON form (04 §1; 08 §25).

Round trip without loss, a timezone-aware timestamp, sets that survive, and one
strictness policy applied everywhere: a document is exactly this schema or it is
rejected, never accepted in part.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from qradar_soar_mcp.catalog import models
from qradar_soar_mcp.catalog.models import (
    MAPPING_SECTIONS,
    SECTION_NAMES,
    Catalog,
    CatalogFormatError,
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
    WorkflowSummary,
)

FETCHED = datetime(2026, 9, 18, 12, 30, tzinfo=UTC)


def full_catalog(**overrides: Any) -> Catalog:
    """One entry of every spec type, nested specs and optional values included.

    Two sections are given states the collections backend never produces for them
    (a loaded permission set and app list), so the round trip covers a non-empty
    frozenset and a non-empty ``installed_apps`` too.
    """
    select = SelectValue(label="High", value=3, default=True)
    content: dict[str, Any] = {
        "functions": {
            "fn_lookup": FunctionSpec(
                id=1,
                name="fn_lookup",
                uuid="uuid-1",
                display_name="Lookup",
                description="looks something up",
                destination_handle="fn_queue",
                version=4,
                inputs=(
                    FunctionInput(
                        name="lookup_mode",
                        uuid="uuid-2",
                        label="Mode",
                        input_type="select",
                        required="always",
                        tooltip="which mode",
                        values=(select, SelectValue(label="Low", value="low", enabled=False)),
                    ),
                    FunctionInput(
                        name="lookup_key", uuid="uuid-3", label="Key", input_type="password"
                    ),
                ),
                unresolved_inputs=1,
            )
        },
        "scripts": {
            "set_owner": ScriptSpec(
                id=2,
                name="Set owner",
                programmatic_name="set_owner",
                uuid="uuid-4",
                language="python3",
                object_type="incident",
                enabled=True,
            )
        },
        "message_destinations": {
            "fn_queue": MDSpec(
                id=3,
                name="Queue",
                programmatic_name="fn_queue",
                uuid="uuid-5",
                destination_type=0,
                expect_ack=True,
            )
        },
        "incident_types": {
            "Malware": TypeSpec(
                id=4, name="Malware", uuid="uuid-6", enabled=True, hidden=False, system=False
            ),
            "Ransomware": TypeSpec(
                id=5,
                name="Ransomware",
                uuid="uuid-7",
                enabled=True,
                hidden=False,
                system=False,
                parent_id="Malware",
            ),
        },
        "phases": {
            "Initial": PhaseSpec(id=6, name="Initial", uuid="uuid-8", enabled=True, order=1)
        },
        "fields": {
            "incident.properties.root_cause": FieldSpec(
                type_name="incident",
                name="root_cause",
                api_name="properties.root_cause",
                label="Root cause",
                input_type="select",
                custom=True,
                required="close",
                values=(select,),
            )
        },
        "datatables": {
            "hosts": DataTableSpec(
                id=7,
                type_name="hosts",
                display_name="Hosts",
                uuid="uuid-9",
                parent_types=("incident",),
                columns=(DataTableColumn(name="host", label="Host", input_type="text", order=0),),
            )
        },
        "playbooks": {
            "pb_triage": PlaybookSummary(
                id=8,
                name="pb_triage",
                display_name="Triage",
                uuid="uuid-10",
                status="enabled",
                activation_type="automatic",
                object_type="incident",
                type="default",
                version=12,
            )
        },
        "rules": {
            "Escalate": RuleSpec(
                id=9,
                name="Escalate",
                uuid="uuid-11",
                type=1,
                object_type="incident",
                enabled=True,
                logic_type="all",
                timeout_seconds=86400,
                message_destinations=("fn_queue",),
                conditions=(RuleCondition(field_name="incident.severity_code", method="equals"),),
            )
        },
        "workflows": {"wf": WorkflowSummary()},
        "groups": {"SOC": GroupSpec(id=10, name="SOC", uuid="uuid-12", enabled=True)},
        "api_key_permissions": frozenset({"zeta", "alpha", "mid"}),
        "installed_apps": {"fn_lookup_app": "1.2.3"},
    }
    sections = {
        name: SectionStatus(state=SectionState.LOADED, count=len(content[name]))
        for name in SECTION_NAMES
    }
    data: dict[str, Any] = {
        "source": "collections",
        "fetched_at": FETCHED,
        "soar_version": "51.0.9.0.20848",
        "org_id": "201",
        "sections": sections,
        **content,
    }
    data.update(overrides)
    return Catalog.model_validate(data)


def document(**changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(full_catalog().to_json())
    doc.update(changes)
    return doc


# ---------------------------------------------------------------- round trip
def test_catalog_round_trips_through_json_without_loss():
    catalog = full_catalog()
    text = catalog.to_json()
    again = Catalog.from_json(text)
    assert again == catalog
    assert again.to_json() == text  # and the text itself is stable


def test_the_fixture_above_really_covers_every_spec_model():
    """Every model class of the module takes part in the round trip."""
    specs = {
        cls
        for cls in vars(models).values()
        if isinstance(cls, type)
        and issubclass(cls, BaseModel)
        and cls.__module__ == models.__name__
    } - {models._Spec}
    seen: set[type] = set()

    def walk(value: Any) -> None:
        if isinstance(value, BaseModel):
            seen.add(type(value))
            for name in type(value).model_fields:
                walk(getattr(value, name))
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, tuple | frozenset):
            for item in value:
                walk(item)

    walk(full_catalog())
    assert seen == specs, f"not exercised: {sorted(c.__name__ for c in specs - seen)}"


def test_every_section_of_the_design_is_modelled():
    assert set(SECTION_NAMES) == {
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
        "api_key_permissions",
        "installed_apps",
    }
    for name in MAPPING_SECTIONS:
        assert name in Catalog.model_fields
    for header in ("fetched_at", "soar_version", "org_id"):
        assert header in Catalog.model_fields


def test_fetched_at_is_timezone_aware_and_normalised_to_utc():
    offset = timezone(timedelta(hours=4))
    catalog = full_catalog(fetched_at=FETCHED.astimezone(offset))
    assert catalog.fetched_at.utcoffset() == timedelta(0)
    assert catalog.fetched_at == FETCHED
    assert json.loads(catalog.to_json())["fetched_at"] == "2026-09-18T12:30:00Z"
    assert Catalog.from_json(catalog.to_json()).fetched_at == FETCHED
    # The same instant written with another offset is the same catalog.
    shifted = document(fetched_at="2026-09-18T16:30:00+04:00")
    assert Catalog.from_json(json.dumps(shifted)) == full_catalog()


def test_a_naive_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        full_catalog(fetched_at=datetime(2026, 9, 18, 12, 30))
    with pytest.raises(CatalogFormatError, match="fetched_at"):
        Catalog.from_json(json.dumps(document(fetched_at="2026-09-18T12:30:00")))


def test_sets_survive_as_sets_and_serialise_in_a_stable_order():
    catalog = full_catalog()
    assert json.loads(catalog.to_json())["api_key_permissions"] == ["alpha", "mid", "zeta"]
    shuffled = document(api_key_permissions=["zeta", "mid", "alpha"])
    again = Catalog.from_json(json.dumps(shuffled))
    assert isinstance(again.api_key_permissions, frozenset)
    assert again == catalog


def test_dictionary_keys_are_written_sorted_whatever_the_insertion_order():
    doc = document()
    reordered = {key: doc[key] for key in reversed(list(doc))}
    reordered["incident_types"] = dict(reversed(list(doc["incident_types"].items())))
    text = Catalog.from_json(json.dumps(reordered)).to_json()
    assert text == full_catalog().to_json()
    assert list(json.loads(text)) == sorted(doc)


def test_tuples_and_optional_values_survive():
    again = Catalog.from_json(full_catalog().to_json())
    fn = again.functions["fn_lookup"]
    assert isinstance(fn.inputs, tuple) and isinstance(fn.inputs[0].values, tuple)
    assert fn.inputs[0].values[1].value == "low" and fn.inputs[0].values[0].value == 3
    assert fn.inputs[1].tooltip is None and fn.inputs[1].values == ()
    assert again.incident_types["Malware"].parent_id is None
    assert again.incident_types["Ransomware"].parent_id == "Malware"
    assert again.datatables["hosts"].parent_types == ("incident",)


def test_models_are_immutable():
    catalog = full_catalog()
    with pytest.raises(ValidationError, match="frozen"):
        catalog.soar_version = "0"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="frozen"):
        catalog.functions["fn_lookup"].name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------- strictness
def _nested(doc: dict[str, Any], path: tuple[Any, ...]) -> Any:
    node: Any = doc
    for step in path:
        node = node[step]
    return node


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("functions", "fn_lookup"),
        ("functions", "fn_lookup", "inputs", 0),
        ("functions", "fn_lookup", "inputs", 0, "values", 0),
        ("scripts", "set_owner"),
        ("datatables", "hosts", "columns", 0),
        ("rules", "Escalate", "conditions", 0),
        ("workflows", "wf"),
        ("sections", "functions"),
    ],
    ids=lambda p: ".".join(map(str, p)) or "catalog",
)
def test_an_unexpected_key_is_rejected_at_every_level(path: tuple[Any, ...]):
    doc = document()
    _nested(doc, path)["script_text"] = "print('not part of any spec')"
    with pytest.raises(CatalogFormatError, match="script_text"):
        Catalog.from_json(json.dumps(doc))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "{not json",
        "[]",
        "null",
        json.dumps({"source": "collections"}),
    ],
)
def test_a_document_that_is_not_a_catalog_is_rejected(text: str):
    with pytest.raises(CatalogFormatError):
        Catalog.from_json(text)


@pytest.mark.parametrize(
    ("path", "key", "value"),
    [
        ((), "format_version", 2),
        ((), "source", "guess"),
        ((), "org_id", 201),
        ((), "soar_version", None),
        ((), "api_key_permissions", "admin"),
        (("functions", "fn_lookup"), "id", "1"),
        (("functions", "fn_lookup"), "id", True),
        (("functions", "fn_lookup"), "inputs", {}),
        (("scripts", "set_owner"), "enabled", "true"),
        (("sections", "functions"), "state", "probably"),
    ],
)
def test_a_wrong_type_is_rejected_not_coerced(path: tuple[Any, ...], key: str, value: Any):
    doc = document()
    _nested(doc, path)[key] = value
    with pytest.raises(CatalogFormatError):
        Catalog.from_json(json.dumps(doc))


def test_a_missing_required_key_is_rejected_whole():
    doc = document()
    del doc["functions"]["fn_lookup"]["uuid"]
    with pytest.raises(CatalogFormatError, match=r"functions\.fn_lookup\.uuid"):
        Catalog.from_json(json.dumps(doc))


def test_a_format_error_names_keys_and_never_echoes_a_value():
    doc = document()
    doc["functions"]["fn_lookup"]["id"] = "VALUE-THAT-MUST-NOT-BE-ECHOED"
    with pytest.raises(CatalogFormatError) as caught:
        Catalog.from_json(json.dumps(doc))
    assert "VALUE-THAT-MUST-NOT-BE-ECHOED" not in str(caught.value)
    assert caught.value.__cause__ is None


# ------------------------------------------------- known empty vs not observable
def test_sections_must_name_every_section_and_nothing_else():
    doc = document()
    del doc["sections"]["workflows"]
    with pytest.raises(CatalogFormatError, match="every catalog section"):
        Catalog.from_json(json.dumps(doc))
    doc = document()
    doc["sections"]["users"] = {"state": "loaded", "count": 0, "reason": None}
    with pytest.raises(CatalogFormatError, match="every catalog section"):
        Catalog.from_json(json.dumps(doc))


def test_a_loaded_section_must_count_its_entries():
    doc = document()
    doc["sections"]["scripts"]["count"] = 5
    with pytest.raises(CatalogFormatError, match="scripts"):
        Catalog.from_json(json.dumps(doc))


@pytest.mark.parametrize("state", ["unverified", "not_observable"])
def test_a_section_that_was_not_loaded_cannot_hold_entries(state: str):
    doc = document()
    doc["sections"]["api_key_permissions"] = {"state": state, "count": 0, "reason": "x"}
    with pytest.raises(CatalogFormatError, match="api_key_permissions"):
        Catalog.from_json(json.dumps(doc))
    doc["api_key_permissions"] = []
    catalog = Catalog.from_json(json.dumps(doc))
    assert catalog.sections["api_key_permissions"].state == state


def test_known_empty_and_not_observable_are_different_catalogs():
    """The reason the model has ``sections`` at all."""
    doc = document(workflows={})
    doc["sections"]["workflows"] = {"state": "loaded", "count": 0, "reason": None}
    known_empty = Catalog.from_json(json.dumps(doc))
    doc["sections"]["workflows"] = {"state": "unverified", "count": 3, "reason": "shape"}
    unverified = Catalog.from_json(json.dumps(doc))
    assert known_empty.workflows == unverified.workflows == {}
    assert known_empty != unverified
    assert Catalog.from_json(unverified.to_json()) == unverified
    assert unverified.summary()["not_loaded"]["workflows"]["count"] == 3
    assert "workflows" not in unverified.summary()["counts"]


# ------------------------------------------------------------------ secrets
def test_a_password_typed_input_cannot_be_built_with_a_default():
    with pytest.raises(ValidationError, match="password"):
        FunctionInput(
            name="api_token",
            uuid="uuid-1",
            label="Token",
            input_type="password",
            values=(SelectValue(label="hunter2", default=True),),
        )
    with pytest.raises(ValidationError, match="password"):
        FunctionInput(
            name="api_token",
            uuid="uuid-1",
            label="Token",
            input_type="password",
            placeholder="hunter2",
        )


def test_a_password_typed_input_cannot_carry_a_tooltip_either():
    with pytest.raises(ValidationError, match="password"):
        FunctionInput(
            name="api_token",
            uuid="uuid-1",
            label="Token",
            input_type="password",
            tooltip="the default is hunter2",
        )


@pytest.mark.parametrize("key", ["placeholder", "tooltip"])
def test_a_document_cannot_smuggle_a_password_default_in(key: str):
    doc = document()
    doc["functions"]["fn_lookup"]["inputs"][1][key] = "hunter2"
    with pytest.raises(CatalogFormatError, match="password"):
        Catalog.from_json(json.dumps(doc))


@pytest.mark.parametrize("input_type", ["password", "select_owner", "multiselect_members"])
def test_a_secret_or_member_typed_field_cannot_carry_values(input_type: str):
    with pytest.raises(ValidationError, match=input_type):
        FieldSpec(
            type_name="incident",
            name="owner_id",
            api_name="owner_id",
            label="Owner",
            input_type=input_type,
            custom=False,
            values=(SelectValue(label="a.person@example.com", value=7),),
        )
    doc = document()
    field = doc["fields"]["incident.properties.root_cause"]
    field["input_type"] = input_type
    with pytest.raises(CatalogFormatError, match=input_type):
        Catalog.from_json(json.dumps(doc))
    if input_type != "password":
        with pytest.raises(ValidationError, match=input_type):
            FunctionInput(
                name="who",
                uuid="uuid-1",
                label="Who",
                input_type=input_type,
                values=(SelectValue(label="a.person@example.com", value=7),),
            )


def test_a_python_mode_dump_round_trips_as_well():
    catalog = full_catalog()
    dumped = catalog.model_dump()
    assert isinstance(dumped["api_key_permissions"], frozenset)
    assert Catalog.model_validate(dumped) == catalog


def test_no_spec_has_a_place_for_credentials_bodies_or_principals():
    banned = {
        "password",
        "secret",
        "api_key",
        "api_keys",
        "token",
        "authorization",
        "script_text",
        "xml",
        "content",
        "default_value",
        "templates",
        "output_json_example",
        "creator",
        "creator_principal",
        "members",
        "users",
        "email",
    }
    for cls in vars(models).values():
        if isinstance(cls, type) and issubclass(cls, BaseModel):
            assert not (set(cls.model_fields) & banned), cls.__name__


def test_the_summary_is_metadata_and_counts_only():
    summary = full_catalog().summary()
    assert set(summary) == {
        "source",
        "fetched_at",
        "soar_version",
        "org_id",
        "counts",
        "not_loaded",
    }
    assert summary["counts"]["incident_types"] == 2 and summary["not_loaded"] == {}
    assert all(isinstance(v, int) for v in summary["counts"].values())
    assert "fn_lookup" not in json.dumps(summary)
