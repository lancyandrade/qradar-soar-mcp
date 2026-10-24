"""P2-04 (06 P2-04; 08 §29): rules and workflows.

Four Tier-0 tools. Three answer from the cached catalog and send nothing of their own;
``soar_get_workflow`` with ``include_raw=true`` sends exactly one ``GET /workflows``.
Everything here is offline (``FakeSoar`` behind respx, or the committed catalog fixture),
and every workflow is the synthetic document of ``tests/workflow_data.py``, whose
structure ``test_workflow_summary.py`` checks against the P2-04 record.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from qradar_soar_mcp.catalog.models import SectionState, SectionStatus
from qradar_soar_mcp.client.discovery import WorkflowSource
from qradar_soar_mcp.logging import REDACTED
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime
from qradar_soar_mcp.tools import discovery as discovery_tools
from qradar_soar_mcp.tools.projection import (
    WORKFLOW_RAW_NOTE,
    WORKFLOW_XML_LIMIT,
    workflow_xml,
)
from tests.conftest import SENTINEL
from tests.fake_soar import FakeSoar
from tests.test_catalog_backends import EXPECTED_READS
from tests.test_discovery_tools import call, failed, lab_catalog, ok, sent, with_catalog
from tests.tool_harness import audit_records, build_runtime
from tests.workflow_data import CONDITION_TEXT, INPUT_VALUE
from tests.workflow_data import workflow_xml as synthetic

ORG = "/rest/orgs/201"
TOOLS = ["soar_list_rules", "soar_get_rule", "soar_list_workflows", "soar_get_workflow"]
ARGS: dict[str, dict[str, Any]] = {
    "soar_list_rules": {},
    "soar_get_rule": {"rule_id": 300},
    "soar_list_workflows": {},
    "soar_get_workflow": {"workflow_id": 1100},
}
CATALOG_ONLY_CALLS = [(tool, ARGS[tool]) for tool in TOOLS]
LOAD = len(EXPECTED_READS)
WORKFLOW = "workflow_1100"


@pytest.fixture
async def rt(fake: FakeSoar, tmp_path: Path):
    runtime = build_runtime(fake, tmp_path)
    yield runtime
    await runtime.aclose()


def workflow_row(fake: FakeSoar) -> dict[str, Any]:
    (row,) = fake.discovery["workflows"]["entities"]
    return row


# ------------------------------------------------------------ declaration
@pytest.mark.parametrize("tool", TOOLS)
def test_each_is_a_tier_0_read_with_no_capability_and_no_mutation(tool: str):
    spec = TOOL_REGISTRY[tool]
    assert spec.tier is Tier.READ and int(spec.tier) == 0
    assert spec.capability is None
    assert spec.mutations == 0 and spec.mutating is False
    assert spec.needs_approval_arg is False and spec.unsupported is None
    assert spec.classify is None and spec.describe is None


def test_the_tool_contracts_are_these_parameters():
    def params(tool: str) -> dict[str, Any]:
        sig = inspect.signature(TOOL_REGISTRY[tool].func)
        return {n: p.default for n, p in sig.parameters.items() if n != "rt"}

    paging = {"name_contains": None, "start": 0, "length": None}
    assert params("soar_list_rules") == paging
    assert params("soar_list_workflows") == paging
    assert params("soar_get_rule") == {"name": None, "rule_id": None}
    assert params("soar_get_workflow") == {
        "programmatic_name": None,
        "workflow_id": None,
        "include_raw": False,  # raw XML is off by default
    }


def test_no_tool_takes_a_path_a_method_a_url_or_a_body():
    for tool in TOOLS:
        names = set(inspect.signature(TOOL_REGISTRY[tool].func).parameters)
        assert not names & {"path", "url", "method", "endpoint", "body", "params", "query"}
        assert not names & {"xml", "content", "uuid"}, tool


def test_only_get_workflow_reaches_the_client_and_only_for_include_raw():
    tree = ast.parse(Path(discovery_tools.__file__).read_text(encoding="utf-8"))
    bodies = {
        fn.name: ast.unparse(fn)
        for fn in ast.walk(tree)
        if isinstance(fn, ast.AsyncFunctionDef) and fn.name in TOOLS
    }
    for tool, source in bodies.items():
        assert source.count("rt.require_catalog().get()") == 1, tool
        assert "refresh()" not in source, tool
        assert ("require_client" in source) is (tool == "soar_get_workflow"), tool
    get_workflow = next(
        fn
        for fn in ast.walk(tree)
        if isinstance(fn, ast.AsyncFunctionDef) and fn.name == "soar_get_workflow"
    )
    branch = next(
        n
        for n in ast.walk(get_workflow)
        if isinstance(n, ast.If)
        and "include_raw" in ast.unparse(n.test)
        and "isinstance" not in ast.unparse(n.test)
    )
    assert "require_client" in ast.unparse(branch)
    assert "workflow_source(spec.workflow_id)" in ast.unparse(branch)


# ---------------------------------------------------------- no traffic of their own
@pytest.mark.parametrize(("tool", "args"), CATALOG_ONLY_CALLS)
async def test_answers_cost_only_the_catalog_load(
    tool: str, args: dict[str, Any], rt: Runtime, fake: FakeSoar
):
    await ok(rt, tool, **args)
    assert len(fake.requests) == LOAD
    await ok(rt, tool, **args)
    assert len(fake.requests) == LOAD  # cached: nothing more


@pytest.mark.parametrize(("tool", "args"), CATALOG_ONLY_CALLS)
async def test_the_committed_fixture_answers_with_no_request(
    tool: str, args: dict[str, Any], rt: Runtime, fake: FakeSoar
):
    with_catalog(rt, lab_catalog())
    await ok(rt, tool, **args)
    assert fake.requests == []


@pytest.mark.parametrize(("tool", "args"), CATALOG_ONLY_CALLS)
async def test_each_writes_no_audit_record_and_mutates_nothing(
    tool: str, args: dict[str, Any], rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    await ok(rt, tool, **args)
    await ok(rt, "soar_get_workflow", workflow_id=1100, include_raw=True)
    assert audit_records(tmp_path) == []
    assert all(r.method == "GET" or r.path.endswith("query_paged") for r in fake.requests)


@pytest.mark.parametrize(
    ("tool", "section"), [("soar_list_rules", "rules"), ("soar_list_workflows", "workflows")]
)
async def test_an_unknown_section_is_an_error_never_an_empty_list(
    tool: str, section: str, rt: Runtime
):
    catalog = lab_catalog()
    doc = catalog.model_dump()
    doc[section] = {}
    doc["sections"][section] = SectionStatus(state=SectionState.NOT_OBSERVABLE, reason="test")
    with_catalog(rt, type(catalog).model_validate(doc))
    error = await failed(rt, tool, "catalog_unavailable")
    assert section in error["message"]


# --------------------------------------------------------------------- rules
async def test_list_rules_is_compact_sorted_and_counted(rt: Runtime):
    data = await ok(rt, "soar_list_rules")
    assert set(data) == {
        "total", "matched", "start", "length", "count", "more", "next_start",
        "rules", "catalog", "note",
    }  # fmt: skip
    assert [r["name"] for r in data["rules"]] == ["rule_300", "rule_301"]
    row = data["rules"][0]
    assert set(row) == {
        "name", "id", "type", "object_type", "enabled", "logic_type",
        "condition_count", "message_destinations",
    }  # fmt: skip
    assert row["id"] == 300 and row["condition_count"] == 1
    assert "compares with" in data["note"]


async def test_get_rule_shows_conditions_and_never_their_values(rt: Runtime, fake: FakeSoar):
    rule = fake.discovery["actions"]["entities"][0]
    rule["conditions"][0]["value"] = "COMPARED-VALUE-MARKER"
    rule["automations"] = [{"type": "x", "value": "AUTOMATION-MARKER"}]
    rule["workflows"] = ["WORKFLOW-LINK-MARKER"]
    data = await ok(rt, "soar_get_rule", name="rule_300")
    described = data["rule"]
    assert described["conditions"] == [
        {
            "field_name": rule["conditions"][0]["field_name"],
            "method": rule["conditions"][0]["method"],
        }
    ]
    assert described["uuid"] == rule["uuid"] and described["timeout_seconds"] == 300
    rendered = str(data)
    for marker in ("COMPARED-VALUE-MARKER", "AUTOMATION-MARKER", "WORKFLOW-LINK-MARKER"):
        assert marker not in rendered


@pytest.mark.parametrize(
    ("args", "code"),
    [
        ({}, "validation"),
        ({"name": "rule_300", "rule_id": 300}, "validation"),
        ({"rule_id": 0}, "validation"),
        ({"rule_id": True}, "validation"),
        ({"name": "RULE_300"}, "not_found"),  # exact, never case-folded
        ({"name": "rule_30"}, "not_found"),
        ({"rule_id": 999}, "not_found"),
    ],
)
async def test_rule_lookups_are_exact(args: dict[str, Any], code: str, rt: Runtime):
    await failed(rt, "soar_get_rule", code, **args)


# ----------------------------------------------------------------- workflows
async def test_list_workflows_names_the_functions_each_calls(rt: Runtime):
    data = await ok(rt, "soar_list_workflows")
    (row,) = data["workflows"]
    assert row["programmatic_name"] == WORKFLOW and row["workflow_id"] == 1100
    assert row["structure"] == "parsed"
    # The acceptance criterion: a workflow's summary lists the functions it calls.
    assert row["functions"] == ["function_200"]
    assert row["node_count"] == 5 and row["edge_count"] == 4
    assert row["function_call_count"] == 1 and row["unresolved_function_calls"] == 0
    assert row["problem_count"] == 0
    assert "never their text" not in data["note"] and "not included" in data["note"]


async def test_get_workflow_returns_the_structural_summary(rt: Runtime, fake: FakeSoar):
    data = await ok(rt, "soar_get_workflow", programmatic_name=WORKFLOW)
    assert set(data) == {"workflow", "catalog", "note"}
    workflow = data["workflow"]
    assert [(n["id"], n["type"]) for n in workflow["nodes"]][:3] == [
        ("StartEvent_1", "startEvent"),
        ("ServiceTask_1", "serviceTask"),
        ("ExclusiveGateway_1", "exclusiveGateway"),
    ]
    kinds = {e["id"]: e["kind"] for e in workflow["edges"]}
    assert kinds == {
        "SequenceFlow_1": "unconditional",
        "SequenceFlow_2": "unconditional",
        "SequenceFlow_3": "default",
        "SequenceFlow_4": "conditional",
    }
    (function,) = workflow["functions"]
    assert function["resolution"] == "resolved" and function["function"] == "function_200"
    assert function["uuid"] == fake.discovery["functions"]["entities"][0]["uuid"]
    assert function["input_names"] == ["input_100"]
    assert workflow["problems"] == [] and workflow["refusal"] is None
    assert workflow["nodes_omitted"] == 0 and workflow["edges_omitted"] == 0
    assert "raw" not in data  # off by default
    assert len(fake.requests) == LOAD  # and nothing beyond the catalog load


async def test_the_summary_holds_no_script_and_no_input_value(rt: Runtime):
    data = await ok(rt, "soar_get_workflow", workflow_id=1100)
    rendered = str(data)
    assert CONDITION_TEXT not in rendered and INPUT_VALUE not in rendered
    assert "<definitions" not in rendered


async def test_an_unresolved_function_is_reported_as_such(rt: Runtime, fake: FakeSoar):
    workflow_row(fake)["content"]["xml"] = synthetic("uuid-nobody")
    data = await ok(rt, "soar_get_workflow", workflow_id=1100)
    (function,) = data["workflow"]["functions"]
    assert function["resolution"] == "unresolved" and function["function"] is None
    assert any("names no function in this catalog" in p for p in data["workflow"]["problems"])
    listing = await ok(rt, "soar_list_workflows")
    assert listing["workflows"][0]["functions"] == []
    assert listing["workflows"][0]["unresolved_function_calls"] == 1


async def test_refused_xml_is_listed_as_refused_not_dropped(rt: Runtime, fake: FakeSoar):
    workflow_row(fake)["content"]["xml"] = '<!DOCTYPE x [<!ENTITY a "b">]><definitions/>'
    data = await ok(rt, "soar_get_workflow", workflow_id=1100)
    assert data["workflow"]["structure"] == "refused"
    assert data["workflow"]["refusal"] == "the workflow XML declares a DTD or an entity"
    assert data["workflow"]["nodes"] == [] and data["workflow"]["edges"] == []


@pytest.mark.parametrize(
    ("args", "code"),
    [
        ({}, "validation"),
        ({"programmatic_name": WORKFLOW, "workflow_id": 1100}, "validation"),
        ({"workflow_id": -1}, "validation"),
        ({"workflow_id": "1100"}, "validation"),
        ({"programmatic_name": WORKFLOW.upper()}, "not_found"),
        ({"workflow_id": 1101}, "not_found"),
        ({"workflow_id": 1100, "include_raw": "yes"}, "validation"),
        ({"workflow_id": 1100, "include_raw": 1}, "validation"),
    ],
)
async def test_workflow_lookups_are_exact_and_send_nothing(
    args: dict[str, Any], code: str, rt: Runtime, fake: FakeSoar
):
    with_catalog(rt, lab_catalog())
    await failed(rt, "soar_get_workflow", code, **args)
    assert fake.requests == []


# ---------------------------------------------------------------- include_raw
async def test_include_raw_sends_exactly_one_get_of_the_collection(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    data = await ok(rt, "soar_get_workflow", programmatic_name=WORKFLOW, include_raw=True)
    assert sent(fake) == [("GET", f"{ORG}/workflows")]
    raw = data["raw"]
    assert raw["text"] == workflow_row(fake)["content"]["xml"]
    assert raw["text_is"] == "exact_xml" and raw["untrusted"] is True
    assert raw["redacted"] is False and raw["truncated"] is False
    assert raw["source_chars"] == raw["safe_chars"] == raw["returned_chars"] == len(raw["text"])
    assert raw["limit_chars"] == WORKFLOW_XML_LIMIT
    assert raw["matches_catalog_version"] is True
    assert WORKFLOW_RAW_NOTE in data["note"] and "UNTRUSTED" in data["note"]


async def test_a_credential_in_the_xml_is_redacted_before_the_cut(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    row = workflow_row(fake)
    row["content"]["xml"] = row["content"]["xml"].replace(
        "</definitions>", f"<!-- {SENTINEL} --></definitions>"
    )
    data = await ok(rt, "soar_get_workflow", workflow_id=1100, include_raw=True)
    raw = data["raw"]
    assert SENTINEL not in str(data)
    assert raw["redacted"] is True and raw["text_is"] == "redacted_xml"
    assert REDACTED in raw["text"]
    assert raw["source_chars"] == len(row["content"]["xml"])


async def test_an_oversized_xml_is_cut_with_both_transformations_reported(
    rt: Runtime, fake: FakeSoar
):
    with_catalog(rt, lab_catalog())
    row = workflow_row(fake)
    padding = "x" * (WORKFLOW_XML_LIMIT + 10)
    row["content"]["xml"] = row["content"]["xml"].replace(
        "</definitions>", f"<!-- {padding} --></definitions>"
    )
    raw = (await ok(rt, "soar_get_workflow", workflow_id=1100, include_raw=True))["raw"]
    assert raw["truncated"] is True and raw["text_is"] == "exact_xml_prefix"
    assert raw["returned_chars"] == WORKFLOW_XML_LIMIT == len(raw["text"])
    assert raw["safe_chars"] == len(row["content"]["xml"])


def test_the_raw_block_reports_each_transformation_by_itself():
    for redacted in (False, True):
        for size, truncated in ((10, False), (WORKFLOW_XML_LIMIT + 1, True)):
            block = workflow_xml("a" * size, source_chars=size, redacted=redacted)
            assert block["redacted"] is redacted and block["truncated"] is truncated
            assert block["untrusted"] is True


async def test_a_renamed_workflow_is_a_conflict(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    workflow_row(fake)["programmatic_name"] = "renamed_since"
    await failed(rt, "soar_get_workflow", "conflict", workflow_id=1100, include_raw=True)
    assert len(fake.requests) == 1


async def test_a_newer_version_is_returned_and_said_to_differ(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    workflow_row(fake)["content_version"] = 9_999
    raw = (await ok(rt, "soar_get_workflow", workflow_id=1100, include_raw=True))["raw"]
    assert raw["content_version"] == 9_999 and raw["matches_catalog_version"] is False


async def test_a_workflow_gone_from_soar_is_not_found(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    fake.discovery["workflows"] = {"entities": []}
    await failed(rt, "soar_get_workflow", "not_found", workflow_id=1100, include_raw=True)


@pytest.mark.parametrize(
    "rows",
    [
        "duplicate",
        "no_xml",
    ],
)
async def test_an_ambiguous_or_malformed_row_fails_closed(rows: str, rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    row = workflow_row(fake)
    if rows == "duplicate":
        fake.discovery["workflows"]["entities"].append(dict(row))
    else:
        row["content"] = {"version": 1}
    out = await call(rt, "soar_get_workflow", workflow_id=1100, include_raw=True)
    assert out["ok"] is False and out["error"]["code"] == "malformed_response"
    assert "raw" not in str(out)


async def test_raw_is_never_cached_in_the_catalog(rt: Runtime, fake: FakeSoar):
    await ok(rt, "soar_get_workflow", workflow_id=1100, include_raw=True)
    catalog = await rt.require_catalog().get()
    assert "<definitions" not in catalog.to_json()


def test_workflow_source_does_not_appear_in_a_repr():
    source = WorkflowSource(
        workflow_id=1, programmatic_name="wf", content_version=1, text="<x/>", source_chars=4,
        redacted=False,
    )  # fmt: skip
    assert "<x/>" not in repr(source)


@pytest.mark.parametrize("workflow_id", [0, -5, True, "7", 1.5])
async def test_workflow_source_validates_before_sending(
    workflow_id: Any, rt: Runtime, fake: FakeSoar
):
    from qradar_soar_mcp.errors import SoarValidationError

    with pytest.raises(SoarValidationError):
        await rt.require_client().discovery.workflow_source(workflow_id)
    assert fake.requests == []


async def test_a_row_without_its_identity_fails_closed(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    workflow_row(fake)["programmatic_name"] = None
    out = await call(rt, "soar_get_workflow", workflow_id=1100, include_raw=True)
    assert out["ok"] is False and out["error"]["code"] == "malformed_response"
