"""P2-03 (06 P2-03; 08 §28): incident types, phases, fields and data tables.

Four Tier-0 tools that answer from the cached catalog and send nothing of their own.
Everything here is offline: ``FakeSoar`` behind respx, or the committed catalog fixture
with no request at all. Catalogs built in a test (``rebuilt``) are synthetic models for
projection logic only; they are never evidence of what an appliance returns.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from qradar_soar_mcp.catalog.models import (
    FIELD_OBJECT_TYPES,
    FieldSpec,
    SectionState,
    SectionStatus,
    SelectValue,
)
from qradar_soar_mcp.client.discovery import FIELD_TYPES
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime
from qradar_soar_mcp.tools import discovery as discovery_tools
from qradar_soar_mcp.tools.projection import (
    DISCOVERY_PAGE_MAX,
    FIELD_VALUES_MAX,
    OBSERVED_REQUIRED_TOKENS,
    REQUIRED_SEMANTICS,
    TABLE_COLUMNS_MAX,
    summarise_datatable,
    summarise_field,
)
from tests.conftest import SENTINEL
from tests.fake_soar import FakeSoar
from tests.test_catalog_backends import EXPECTED_READS
from tests.test_discovery_tools import call, failed, lab_catalog, ok, rebuilt, sent, with_catalog
from tests.tool_harness import audit_records, base_env, build_runtime

TOOLS = [
    "soar_list_incident_types",
    "soar_list_phases",
    "soar_list_fields",
    "soar_list_datatables",
]
ARGS: dict[str, dict[str, Any]] = {
    "soar_list_incident_types": {},
    "soar_list_phases": {},
    "soar_list_fields": {"object_type": "incident"},
    "soar_list_datatables": {},
}
SECTION = {
    "soar_list_incident_types": "incident_types",
    "soar_list_phases": "phases",
    "soar_list_fields": "fields",
    "soar_list_datatables": "datatables",
}
PAGE_KEYS = {"total", "matched", "start", "length", "count", "more", "next_start"}
LOAD = len(EXPECTED_READS)


@pytest.fixture
async def rt(fake: FakeSoar, tmp_path: Path):
    runtime = build_runtime(fake, tmp_path)
    yield runtime
    await runtime.aclose()


# ------------------------------------------------------------ declaration
@pytest.mark.parametrize("tool", TOOLS)
def test_each_is_a_tier_0_read_with_no_capability_and_no_mutation(tool: str):
    spec = TOOL_REGISTRY[tool]
    assert spec.tier is Tier.READ and int(spec.tier) == 0
    assert spec.capability is None
    assert spec.mutations == 0 and spec.mutating is False
    assert spec.needs_approval_arg is False and spec.unsupported is None
    assert spec.classify is None and spec.describe is None
    assert getattr(spec.func, "__soar_tool__", None) is spec


def test_the_tool_contracts_are_these_parameters():
    def params(tool: str) -> dict[str, Any]:
        sig = inspect.signature(TOOL_REGISTRY[tool].func)
        return {n: p.default for n, p in sig.parameters.items() if n != "rt"}

    paging = {"name_contains": None, "start": 0, "length": None}
    assert params("soar_list_incident_types") == paging
    assert params("soar_list_phases") == paging
    assert params("soar_list_datatables") == paging
    assert params("soar_list_fields") == {
        "object_type": inspect.Parameter.empty,  # required: there is no default type
        "name_contains": None,
        "custom_only": False,
        "start": 0,
        "length": None,
    }


def test_no_tool_takes_a_path_a_method_a_url_or_a_body():
    for tool in TOOLS:
        names = set(inspect.signature(TOOL_REGISTRY[tool].func).parameters)
        assert not names & {"path", "url", "method", "endpoint", "body", "params", "query"}, tool
        assert not names & {"type_name", "type", "table", "rows"}, tool


def test_each_reads_the_cache_once_and_touches_no_client():
    """Catalog first and catalog only: ``get()`` once, never ``refresh()``, never a client."""
    tree = ast.parse(Path(discovery_tools.__file__).read_text(encoding="utf-8"))
    found = []
    for fn in ast.walk(tree):
        if isinstance(fn, ast.AsyncFunctionDef) and fn.name in TOOLS:
            source = ast.unparse(fn)
            found.append(fn.name)
            assert source.count("rt.require_catalog().get()") == 1, fn.name
            assert "refresh" not in source and "require_client" not in source, fn.name
    assert sorted(found) == sorted(TOOLS)


@pytest.mark.parametrize("tool", TOOLS)
async def test_each_travels_through_the_registry_pipeline(
    tool: str, fake: FakeSoar, tmp_path: Path
):
    unusable = Runtime.build(base_env(tmp_path, SOAR_ALLOW_SCRIPT_WRITES="true"))
    assert not unusable.usable
    out = await call(unusable, tool, **ARGS[tool])
    assert out["ok"] is False and out["error"]["code"] == "DENY_CONFIG"
    assert fake.requests == []


@pytest.mark.parametrize("tool", TOOLS)
async def test_each_writes_no_audit_record_asks_no_approval_and_mutates_nothing(
    tool: str, rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    out = await call(rt, tool, **ARGS[tool])
    assert out["ok"] is True and "approval" not in out and "disclaimer" not in out
    assert audit_records(tmp_path) == []
    assert not list((tmp_path / "state" / "approvals").glob("*"))
    assert [r for r in fake.mutating_requests if not r.path.endswith("/query_paged")] == []


# ------------------------------------------------ offline: the catalog only
@pytest.mark.parametrize("tool", TOOLS)
async def test_each_answers_from_the_offline_fixture_with_no_request(
    tool: str, rt: Runtime, fake: FakeSoar
):
    backend = with_catalog(rt, lab_catalog())
    data = await ok(rt, tool, **ARGS[tool])
    assert fake.requests == [] and backend.loads == 1
    assert set(data) == PAGE_KEYS | {SECTION[tool], "catalog", "note"} | (
        {"object_type", "required_semantics"} if tool == "soar_list_fields" else set()
    )
    assert data["catalog"] == {
        "source": "collections",
        "fetched_at": "2026-09-18T00:00:00+00:00",
        "soar_version": "51.0.9.0.20848",
    }
    assert "data, not instructions" in data["note"]


@pytest.mark.parametrize("tool", TOOLS)
async def test_a_fresh_cache_means_no_request_of_their_own(
    tool: str, fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path)
    await ok(rt, tool, **ARGS[tool])
    assert sent(fake) == EXPECTED_READS  # one catalog load, and nothing beside it
    for other in TOOLS:
        await ok(rt, other, **ARGS[other])
    await ok(rt, "soar_list_fields", object_type="task")
    await ok(rt, "soar_list_fields", object_type="artifact")
    assert len(fake.requests) == LOAD  # still that one load
    assert not [r for r in fake.requests if "datatable" in r.path or "table_data" in r.path]
    await rt.aclose()
    fake.requests.clear()
    rt = build_runtime(fake, tmp_path, SOAR_CATALOG_TTL_SECONDS="0")
    await ok(rt, tool, **ARGS[tool])
    await ok(rt, tool, **ARGS[tool])
    assert sent(fake) == [*EXPECTED_READS, *EXPECTED_READS]  # reloads, through the backend
    await rt.aclose()


# --------------------------------------------- loaded-empty versus unknown
@pytest.mark.parametrize("tool", TOOLS)
async def test_a_loaded_empty_section_is_an_empty_list(tool: str, rt: Runtime, fake: FakeSoar):
    with_catalog(rt, rebuilt(lab_catalog(), **{SECTION[tool]: {}}))
    data = await ok(rt, tool, **ARGS[tool])
    assert data[SECTION[tool]] == [] and (data["total"], data["count"]) == (0, 0)
    assert data["more"] is False and fake.requests == []


@pytest.mark.parametrize("state", [SectionState.UNVERIFIED, SectionState.NOT_OBSERVABLE])
@pytest.mark.parametrize("tool", TOOLS)
async def test_a_section_that_is_not_loaded_is_an_error_never_an_empty_list(
    tool: str, state: SectionState, rt: Runtime, fake: FakeSoar
):
    doc = lab_catalog().model_dump()
    doc[SECTION[tool]] = {}
    doc["sections"][SECTION[tool]] = SectionStatus(state=state, count=3, reason="synthetic")
    with_catalog(rt, type(lab_catalog()).model_validate(doc))
    error = await failed(rt, tool, "catalog_unavailable", **ARGS[tool])
    assert SECTION[tool] in error["message"] and str(state) in error["message"]
    assert fake.requests == []


# ----------------------------------------------------------- incident types
async def test_incident_types_are_the_safe_projection_sorted_by_name(rt: Runtime, fake: FakeSoar):
    types = fake.discovery["incident_types"]
    fake.discovery["incident_types"] = dict(reversed(list(types.items())))
    data = await ok(rt, "soar_list_incident_types")
    assert [t["name"] for t in data["incident_types"]] == ["incident_type_950", "incident_type_951"]
    assert data["incident_types"][0] == {
        "name": "incident_type_950",
        "id": 950,
        "uuid": "uuid-950",
        "enabled": True,
        "hidden": True,
        "system": True,
        "parent_id": None,
    }
    rendered = json.dumps(data["incident_types"])
    assert "create_date" not in rendered and "description" not in rendered  # not the raw row


async def test_incident_types_filter_and_page(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path, SOAR_MAX_RESULTS="1")
    first = await ok(rt, "soar_list_incident_types")
    assert (first["total"], first["count"], first["more"], first["next_start"]) == (2, 1, True, 1)
    second = await ok(rt, "soar_list_incident_types", start=1, length=50)
    assert [t["id"] for t in second["incident_types"]] == [951] and second["more"] is False
    hit = await ok(rt, "soar_list_incident_types", name_contains="TYPE_951")
    assert [t["id"] for t in hit["incident_types"]] == [951] and hit["matched"] == 1
    assert (await ok(rt, "soar_list_incident_types", name_contains=".*"))["matched"] == 0
    await rt.aclose()


async def test_a_parent_is_shown_as_soar_gave_it_and_nothing_is_derived(rt: Runtime):
    catalog = lab_catalog()
    child = {**catalog.incident_types["incident_type_951"].model_dump(), "parent_id": 950}
    with_catalog(rt, rebuilt(catalog, incident_types={"incident_type_951": child}))
    (row,) = (await ok(rt, "soar_list_incident_types"))["incident_types"]
    assert row["parent_id"] == 950
    assert not {"children", "parent", "parent_name", "depth", "path"} & set(row)


# ------------------------------------------------------------------- phases
async def test_phases_are_ordered_by_order_then_name(rt: Runtime, fake: FakeSoar):
    catalog = lab_catalog()
    template = catalog.phases["phase_600"].model_dump()
    phases = {
        name: {**template, "name": name, "id": n, "order": order}
        for n, (name, order) in enumerate(
            [("Zeta", 1), ("alpha", 3), ("Beta", 2), ("Alpha", 2)], start=1
        )
    }
    with_catalog(rt, rebuilt(catalog, phases=phases))
    data = await ok(rt, "soar_list_phases")
    assert [(p["order"], p["name"]) for p in data["phases"]] == [
        (1, "Zeta"),
        (2, "Alpha"),
        (2, "Beta"),
        (3, "alpha"),
    ]
    assert await ok(rt, "soar_list_phases") == data
    paged = await ok(rt, "soar_list_phases", start=1, length=2)
    assert [p["name"] for p in paged["phases"]] == ["Alpha", "Beta"] and paged["next_start"] == 3
    assert fake.requests == []


async def test_a_phase_is_its_safe_projection_and_implies_nothing_else(rt: Runtime):
    data = await ok(rt, "soar_list_phases", name_contains="phase_601")
    assert data["phases"] == [
        {"name": "phase_601", "id": 601, "uuid": "uuid-601", "enabled": True, "order": 601}
    ]
    assert (data["total"], data["matched"]) == (2, 1)
    assert not {"tasks", "playbooks", "rules", "workflows"} & set(data["phases"][0])


# -------------------------------------------------------------- data tables
async def test_datatables_are_the_catalogs_type_id_8_entries_with_columns(
    rt: Runtime, fake: FakeSoar
):
    assert {t["type_id"] for t in fake.discovery["types"].values()} == {0, 8}
    data = await ok(rt, "soar_list_datatables")
    assert [t["type_name"] for t in data["datatables"]] == ["table_1", "table_2"]  # not incident
    assert data["datatables"][0] == {
        "type_name": "table_1",
        "id": 901,
        "display_name": "display_name-901",
        "uuid": "uuid-901",
        "parent_types": ["incident"],
        "column_count": 2,
        "columns": [
            {
                "name": "column_a",
                "label": "text-901",
                "input_type": "text",
                "order": 0,
                "required": None,
            },
            {
                "name": "column_b",
                "label": "text-901",
                "input_type": "text",
                "order": 1,
                "required": None,
            },
        ],
        "columns_omitted": 0,
    }
    paths = [path for _, path in sent(fake)]
    assert paths.count("/rest/orgs/201/types") == 1  # the catalog load's, and no other
    assert not [p for p in paths if "datatable" in p or "table_data" in p or "/rows" in p]


async def test_datatables_never_carry_rows_values_or_a_derived_requiredness(rt: Runtime):
    data = await ok(rt, "soar_list_datatables")
    for table in data["datatables"]:
        assert not {"rows", "cells", "data", "fields"} & set(table)
        for column in table["columns"]:
            assert set(column) == {"name", "label", "input_type", "order", "required"}


async def test_datatables_filter_by_type_name_or_display_name_and_page(
    fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path, SOAR_MAX_RESULTS="1")
    first = await ok(rt, "soar_list_datatables")
    assert (first["count"], first["more"], first["next_start"]) == (1, True, 1)
    by_display = await ok(rt, "soar_list_datatables", name_contains="NAME-902")
    assert [t["type_name"] for t in by_display["datatables"]] == ["table_2"]
    by_type = await ok(rt, "soar_list_datatables", name_contains="able_1")
    assert [t["type_name"] for t in by_type["datatables"]] == ["table_1"]
    await rt.aclose()


async def test_a_wide_table_shows_a_bounded_number_of_columns(rt: Runtime):
    catalog = lab_catalog()
    table = catalog.datatables["table_1"].model_dump()
    column = table["columns"][0]
    table["columns"] = tuple({**column, "name": f"c_{n:03d}", "order": n} for n in range(150))
    with_catalog(rt, rebuilt(catalog, datatables={"table_1": table}))
    (row,) = (await ok(rt, "soar_list_datatables"))["datatables"]
    assert row["column_count"] == 150 and len(row["columns"]) == TABLE_COLUMNS_MAX == 100
    assert row["columns_omitted"] == 50


# ------------------------------------------------------------ shared input
@pytest.mark.parametrize(
    "args",
    [
        {"start": -1},
        {"start": "0"},
        {"start": True},
        {"length": 0},
        {"length": 1.5},
        {"name_contains": ""},
        {"name_contains": "x" * 301},
        {"name_contains": 7},
    ],
)
@pytest.mark.parametrize("tool", TOOLS)
async def test_invalid_list_input_is_refused(tool: str, args: dict[str, Any], rt: Runtime):
    error = await failed(rt, tool, "validation", **{**ARGS[tool], **args})
    assert "x" * 50 not in error["message"]


@pytest.mark.parametrize("tool", TOOLS)
async def test_a_page_never_exceeds_the_discovery_maximum(
    tool: str, fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path, SOAR_MAX_RESULTS="500")
    data = await ok(rt, tool, **ARGS[tool], length=500)
    assert data["length"] == DISCOVERY_PAGE_MAX == 100
    await rt.aclose()


# ------------------------------------------------------------------- fields
FIELD_KEYS = {
    "object_type",
    "name",
    "api_name",
    "prefix",
    "label",
    "input_type",
    "custom",
    "required",
    "read_only",
    "internal",
}


async def fields_of(rt: Runtime, object_type: str, **args: Any) -> dict[str, dict[str, Any]]:
    data = await ok(rt, "soar_list_fields", object_type=object_type, **args)
    return {f["api_name"]: f for f in data["fields"]}


def test_the_supported_object_types_are_the_ones_the_catalog_loads():
    assert FIELD_OBJECT_TYPES == FIELD_TYPES == ("incident", "task", "artifact")


@pytest.mark.parametrize("object_type", ["incident", "task", "artifact"])
async def test_only_the_requested_object_type_is_returned(
    object_type: str, rt: Runtime, fake: FakeSoar
):
    with_catalog(rt, lab_catalog())
    data = await ok(rt, "soar_list_fields", object_type=object_type)
    expected = sorted(
        key.removeprefix(f"{object_type}.")
        for key, spec in lab_catalog().fields.items()
        if spec.type_name == object_type
    )
    assert data["object_type"] == object_type and data["total"] == len(expected) > 0
    listed = [f"{f['prefix']}.{f['name']}" if f["prefix"] else f["name"] for f in data["fields"]]
    assert listed == expected
    for field in data["fields"]:
        assert field["object_type"] == object_type
        assert FIELD_KEYS <= set(field) <= FIELD_KEYS | {"values", "values_omitted"}
    assert fake.requests == []


@pytest.mark.parametrize(
    "object_type",
    [
        "note",
        "Incident",
        " incident",
        "incident/fields",
        "../incident",
        "incident?x=1",
        "__function",
        "table_1",
        "actioninvocation",
        "",
        None,
        7,
        ["incident"],
    ],
)
async def test_an_unsupported_object_type_is_refused_before_anything_happens(
    object_type: Any, fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path)
    error = await failed(rt, "soar_list_fields", "validation", object_type=object_type)
    assert "incident, task, artifact" in error["message"]
    assert fake.requests == []  # not even the catalog was loaded
    await rt.aclose()


async def test_object_type_is_required(rt: Runtime, fake: FakeSoar):
    out = await call(rt, "soar_list_fields")
    assert out["ok"] is False and fake.requests == []


async def test_custom_fields_keep_the_properties_api_name(rt: Runtime):
    fields = await fields_of(rt, "incident")
    custom = fields["properties.root_cause"]
    assert (custom["name"], custom["prefix"], custom["custom"]) == (
        "root_cause",
        "properties",
        True,
    )
    builtin = fields["severity_code"]
    assert (builtin["name"], builtin["prefix"], builtin["custom"]) == ("severity_code", None, False)
    assert builtin["input_type"] == "select" and builtin["label"] == "Severity"
    for object_type in ("task", "artifact"):
        listed = await fields_of(rt, object_type)
        assert [n for n, f in listed.items() if f["custom"]] == [
            n for n in listed if n.startswith("properties.")
        ]
        assert any(f["custom"] for f in listed.values())
        assert any(not f["custom"] for f in listed.values())


async def test_read_only_and_internal_flags_are_shown(rt: Runtime):
    fields = await fields_of(rt, "incident")
    assert (fields["create_date"]["read_only"], fields["create_date"]["internal"]) == (True, True)
    assert (fields["description"]["read_only"], fields["description"]["internal"]) == (False, False)


async def test_select_values_are_the_label_and_value_of_the_catalog_exactly(rt: Runtime):
    catalog = lab_catalog()
    with_catalog(rt, catalog)
    fields = await fields_of(rt, "incident")
    for api_name in ("severity_code", "plan_status", "incident_type_ids", "resolution_id"):
        spec = catalog.fields[f"incident.{api_name}"]
        assert fields[api_name]["values"] == [
            {"label": v.label, "value": v.value, "enabled": v.enabled, "default": v.default}
            for v in spec.values
        ]
        assert fields[api_name]["values_omitted"] == 0
    # The label and the stored value are different things, and a value keeps its type.
    medium = {"label": "Medium", "value": 5, "enabled": True, "default": True}
    assert medium in fields["severity_code"]["values"]
    assert [v["value"] for v in fields["plan_status"]["values"]] == ["A", "C"]
    assert "values" not in fields["description"] and "values_omitted" not in fields["description"]


async def test_people_and_secret_typed_fields_show_no_values(rt: Runtime):
    fields = await fields_of(rt, "incident")
    assert fields["owner_id"]["input_type"] == "select_owner"
    assert "values" not in fields["owner_id"]
    # The projection does not rely on the catalog having refused them (synthetic model).
    for input_type in ("select_owner", "multiselect_members", "password"):
        spec = FieldSpec.model_construct(
            type_name="incident",
            name="x",
            api_name="x",
            prefix=None,
            label="X",
            input_type=input_type,
            custom=False,
            required=None,
            read_only=False,
            internal=False,
            values=(SelectValue(label="someone", value=1),),
        )
        assert "values" not in summarise_field(spec)


async def test_no_principal_reaches_a_field_list(rt: Runtime, fake: FakeSoar):
    rows = fake.fields
    owner = next(r for r in rows if r["name"] == "owner_id")
    owner["values"] = [{"value": 9, "label": "analyst.nine@example.internal"}]
    members = {**owner, "id": 77, "name": "members", "input_type": "multiselect_members"}
    picker = {
        "id": 78,
        "name": "picker",
        "text": "Picker",
        "input_type": "select",
        "values": [
            {"value": 1, "label": "Plain"},
            {"value": 2, "label": "group.alpha", "principal_type": "group"},
        ],
    }
    rows.extend([members, picker])
    rendered = json.dumps(await ok(rt, "soar_list_fields", object_type="incident"))
    assert "analyst.nine" not in rendered and "group.alpha" not in rendered
    assert '"label": "Plain"' in rendered


async def test_fields_are_sorted_filtered_and_paged_deterministically(
    fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path, SOAR_MAX_RESULTS="5")
    first = await ok(rt, "soar_list_fields", object_type="incident")
    names = [f["api_name"] for f in first["fields"]]
    assert names == sorted(names) and first["count"] == 5 and first["more"] is True
    assert first["total"] == 19 and first["next_start"] == 5
    seen = list(names)
    start = first["next_start"]
    while start is not None:
        page = await ok(rt, "soar_list_fields", object_type="incident", start=start)
        seen += [f["api_name"] for f in page["fields"]]
        start = page["next_start"]
    assert seen == sorted(seen) and len(seen) == len(set(seen)) == 19
    assert await ok(rt, "soar_list_fields", object_type="incident") == first
    by_name = await ok(rt, "soar_list_fields", object_type="incident", name_contains="RESOLUTION")
    assert [f["api_name"] for f in by_name["fields"]] == ["resolution_id", "resolution_summary"]
    by_label = await ok(rt, "soar_list_fields", object_type="incident", name_contains="date closed")
    assert [f["api_name"] for f in by_label["fields"]] == ["end_date"]
    # The object type is not part of what is searched, and nothing is a pattern.
    for literal in ("incident", "incident.", ".*", "%"):
        hit = await ok(rt, "soar_list_fields", object_type="incident", name_contains=literal)
        assert [f["api_name"] for f in hit["fields"]] == (
            ["incident_type_ids"] if literal == "incident" else []
        )
    await rt.aclose()


async def test_custom_only_keeps_the_custom_fields(rt: Runtime):
    data = await ok(rt, "soar_list_fields", object_type="incident", custom_only=True)
    assert [f["api_name"] for f in data["fields"]] == [
        "properties.asset_count",
        "properties.root_cause",
        "properties.threat_source",
        "properties.triage_summary",
    ]
    assert data["total"] == 4 and all(f["custom"] for f in data["fields"])
    for bad in ("true", 1, None):
        await failed(rt, "soar_list_fields", "validation", object_type="incident", custom_only=bad)


async def test_a_field_with_many_values_shows_a_bounded_number(rt: Runtime):
    catalog = lab_catalog()
    field = catalog.fields["incident.severity_code"].model_dump()
    field["values"] = tuple(
        {"label": f"L{n}", "value": n, "enabled": True, "default": False} for n in range(250)
    )
    with_catalog(rt, rebuilt(catalog, fields={"incident.severity_code": field}))
    (row,) = (await ok(rt, "soar_list_fields", object_type="incident"))["fields"]
    assert len(row["values"]) == FIELD_VALUES_MAX == 100 and row["values_omitted"] == 150


# ------------------------------------- the ``required`` token (P2-03 addendum)
# Three levels of evidence, kept apart (docs/soar-api-verified.md §3.2): DOCUMENTED (the
# on-box description defines no string ``required``), OBSERVED (the tokens below, read
# from the appliance) and BEHAVIOUR (never exercised: no incident was closed).
EVIDENCE = Path(__file__).parent / "fixtures" / "soar" / "verified"
DERIVED_FLAGS = {"close_required", "required_always", "required_at_close", "optional", "mandatory"}


def evidence(name: str) -> dict[str, Any]:
    return json.loads((EVIDENCE / f"p2_03_{name}.json").read_text(encoding="utf-8"))


def test_the_observed_tokens_are_exactly_what_the_evidence_recorded():
    for object_type, tokens in OBSERVED_REQUIRED_TOKENS.items():
        doc = evidence(f"fields_{object_type}_required")
        assert doc["_status"] == 200 and doc["_request"]["method"] == "GET"
        assert doc["_request"]["path"] == f"/rest/orgs/{{org_id}}/types/{object_type}/fields"
        assert doc["_request"]["query_keys"] == ["handle_format", "text_content_output_format"]
        assert tuple(doc["_enums"]["required"]) == tokens
        facts = doc["_facts"]["required"]
        # The key was absent, never null, wherever there was no token; no custom field had one.
        assert facts["rows_without_a_token"]["null"] == "0"
        assert all(cell["custom"] == "0" for cell in facts["rows_by_token"].values())
    assert set(OBSERVED_REQUIRED_TOKENS) == set(FIELD_OBJECT_TYPES)
    assert OBSERVED_REQUIRED_TOKENS["incident"] == ("always", "close")
    assert OBSERVED_REQUIRED_TOKENS["task"] == OBSERVED_REQUIRED_TOKENS["artifact"] == ("always",)


def test_the_on_box_description_documents_no_token_meaning():
    doc = evidence("doc_swagger_required")
    assert doc["_request"] == {
        "method": "GET",
        "path": "/docs/rest-api/ui/swagger.json",
        "query_keys": [],
    }
    # No data type has a ``required`` property that is a string, an enum or a reference.
    assert doc["_status"] == 200 and doc["_facts"]["data_types"] == {}
    assert REQUIRED_SEMANTICS["status"] == "unresolved"


def test_the_research_sent_four_gets_and_nothing_else():
    ledger = json.loads((EVIDENCE / "_ledger_p2_03.json").read_text(encoding="utf-8"))
    assert [(r["method"], r["path"], r["status"], r["count"]) for r in ledger["requests"]] == [
        ("GET", "/docs/rest-api/ui/swagger.json", 200, 1),
        *(
            ("GET", f"/rest/orgs/{{org_id}}/types/{t}/fields", 200, 1)
            for t in ("incident", "task", "artifact")
        ),
    ]
    assert ledger["refused_by_policy"] == []


async def test_the_answer_says_what_is_known_about_required_and_no_more(rt: Runtime):
    data = await ok(rt, "soar_list_fields", object_type="task")
    semantics = data["required_semantics"]
    assert semantics == REQUIRED_SEMANTICS and semantics["status"] == "unresolved"
    assert semantics["observed_tokens"] == {
        "soar_version": "51.0.9.0.20848",
        "incident": ["always", "close"],
        "task": ["always"],
        "artifact": ["always"],
    }
    meaning = semantics["meaning"]
    assert "not documented" in meaning and "not verified by behaviour" in meaning
    assert "no incident was closed" in meaning and "does not mean optional" in meaning


@pytest.mark.parametrize(
    ("object_type", "with_token", "without"),
    [
        ("incident", {"name": "always", "resolution_id": "close"}, "description"),
        ("task", {"task_field_800": "always"}, "properties.task_field_801"),
        ("artifact", {"artifact_field_800": "always"}, "properties.artifact_field_801"),
    ],
)
async def test_the_raw_token_survives_ingestion_and_nothing_is_derived_from_it(
    object_type: str, with_token: dict[str, str], without: str, rt: Runtime, fake: FakeSoar
):
    """From the collection rows, through the real backend and the catalog, to the tool."""
    fields = await fields_of(rt, object_type)
    for api_name, token in with_token.items():
        assert fields[api_name]["required"] == token
    assert fields[without]["required"] is None
    for field in fields.values():
        assert not DERIVED_FLAGS & set(field)
    tokens = {f["required"] for f in fields.values()} - {None}
    assert tokens <= set(OBSERVED_REQUIRED_TOKENS[object_type])  # the fixture invents none


def test_the_offline_catalog_carries_no_filler_token():
    tokens = {spec.required for spec in lab_catalog().fields.values()}
    assert tokens == {None, "always", "close"}
    for function in lab_catalog().functions.values():
        assert {i.required for i in function.inputs} == {None}  # never recorded, so none
    for table in lab_catalog().datatables.values():
        assert {c.required for c in table.columns} == {None}  # the column shape has no such key


async def test_a_token_never_seen_before_stays_raw_and_is_never_read_as_optional(rt: Runtime):
    """Synthetic model, for the projection only: SOAR was not seen to send this token."""
    catalog = lab_catalog()
    field = {**catalog.fields["incident.description"].model_dump(), "required": "on_escalation"}
    with_catalog(rt, rebuilt(catalog, fields={"incident.description": field}))
    data = await ok(rt, "soar_list_fields", object_type="incident")
    (row,) = data["fields"]
    assert row["required"] == "on_escalation"
    assert not DERIVED_FLAGS & set(row)
    assert "on_escalation" not in json.dumps(data["required_semantics"]["observed_tokens"])
    assert "unknown" in data["required_semantics"]["meaning"]


async def test_the_three_object_types_keep_their_own_tokens(rt: Runtime):
    seen = {}
    for object_type in FIELD_OBJECT_TYPES:
        fields = await fields_of(rt, object_type)
        seen[object_type] = sorted({f["required"] for f in fields.values()} - {None})
    assert seen == {"incident": ["always", "close"], "task": ["always"], "artifact": ["always"]}


def test_a_datatable_column_is_not_given_field_semantics():
    """The verified column shape has ``perms.modify_required`` and no ``required`` key."""
    for name in ("datatable_type", "datatable_fields"):
        doc = json.loads((EVIDENCE / f"{name}.json").read_text(encoding="utf-8"))
        shape = doc["shape"]
        column = shape["fields"]["<name>"] if name == "datatable_type" else shape[0]
        assert "required" not in column and "required?" not in column
        assert column["perms"]["modify_required"] == "bool"
    row = summarise_datatable(lab_catalog().datatables["table_1"])
    assert all(c["required"] is None and not DERIVED_FLAGS & set(c) for c in row["columns"])
    assert "modify_required" not in json.dumps(row)


# ------------------------------------------------ the output redactor stays on
@pytest.mark.parametrize("tool", TOOLS)
async def test_a_credential_in_configuration_text_never_leaves_the_pipeline(
    tool: str, rt: Runtime, fake: FakeSoar
):
    """Synthetic catalog, built around ingestion on purpose: the registry's structural
    redaction (08 §26, §27) is the last defence and must cover these answers too."""
    catalog = lab_catalog()
    doc = catalog.model_dump()
    basic = "Basic " + "QUxBRERJTjpvcGVuIHNlc2FtZQ" + "=="  # assembled: not a real token
    planted = f"label {SENTINEL} {basic}"
    doc["incident_types"]["incident_type_950"]["name"] = planted
    doc["phases"]["phase_600"]["name"] = planted
    doc["datatables"]["table_1"]["display_name"] = planted
    doc["datatables"]["table_1"]["columns"][0]["label"] = planted
    doc["fields"]["incident.severity_code"]["label"] = planted
    doc["fields"]["incident.severity_code"]["values"][0]["label"] = planted
    doc["fields"]["incident.severity_code"]["values"][0]["value"] = planted
    with_catalog(rt, type(catalog).model_validate(doc))
    rendered = json.dumps(await ok(rt, tool, **ARGS[tool]))
    assert SENTINEL not in rendered and basic not in rendered
    assert "[REDACTED]" in rendered and fake.requests == []
