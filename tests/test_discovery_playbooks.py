"""P2-05 (06 P2-05; 08 §30): playbooks.

Two Tier-0 tools. ``soar_list_playbooks`` answers from the cached catalog and sends
nothing of its own; ``soar_get_playbook`` sends exactly one ``GET /playbooks/{id}`` after
the catalog has resolved the playbook. Three kinds of test, all offline:

* **contract** — the synthetic playbook of ``tests/playbook_data.py`` has exactly the
  structure the P2-05 read recorded on QRadar SOAR 51.0.9.0.20848
  (``p2_05_playbook.json``, ``p2_05_playbook_xml.json``), so no test relies on a name the
  appliance was not seen to use; and the record says the call's uuid matched exactly one
  function, which is what resolution by exact uuid equality rests on.
* **parser** — ``catalog.playbooks.parse_playbook_detail``: identity, activation
  conditions without their values, the BPMN summary, exact uuid resolution, and every
  unexpected shape failing closed or being said, never guessed.
* **tools** — declarations, requests sent, what is and is never returned, SOAR errors,
  conflicts, no caching, no audit record.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from qradar_soar_mcp.catalog.bpmn import function_index
from qradar_soar_mcp.catalog.playbooks import parse_playbook_detail
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarValidationError
from qradar_soar_mcp.logging import REDACTED, redact
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime
from qradar_soar_mcp.tools.projection import PLAYBOOK_VERIFIED_ON
from tests.conftest import SENTINEL
from tests.discovery_data import build_payloads, verified
from tests.fake_soar import FakeSoar
from tests.playbook_data import (
    CONDITION_VALUE,
    NAMESPACE_CLASS,
    RESULT_NAME,
    SCRIPT_TEXT,
    function_settings,
    playbook_xml,
)
from tests.test_discovery_tools import call, failed, lab_catalog, ok, sent, with_catalog
from tests.tool_harness import audit_records, build_runtime

ORG = "/rest/orgs/201"
TOOLS = ["soar_list_playbooks", "soar_get_playbook"]
PLAYBOOK = "playbook_1000"
FUNCTION = "function_200"
FUNCTION_UUID = "uuid-200"
RECORD = verified("p2_05_playbook_xml")["_facts"]
OBJECT_RECORD = verified("p2_05_playbook")
NEVER = (CONDITION_VALUE, SCRIPT_TEXT, "<definitions", "<?xml", "sequenceFlow id=")


@pytest.fixture
async def rt(fake: FakeSoar, tmp_path: Path):
    runtime = build_runtime(fake, tmp_path)
    yield runtime
    await runtime.aclose()


def detail_row(fake: FakeSoar, playbook_id: int = 1000) -> dict[str, Any]:
    row: dict[str, Any] = fake.discovery[f"playbook:{playbook_id}"]
    return row


def _class_and_local(tag: str) -> tuple[str, str]:
    uri, _, local = tag[1:].partition("}")
    return NAMESPACE_CLASS[uri], local


def _root() -> ET.Element:
    return ET.fromstring(playbook_xml(FUNCTION_UUID))  # noqa: S314 - the test's own document


def _parse(row: dict[str, Any], functions: dict[str, str] | None = None, shared=frozenset()):
    by_uuid = {FUNCTION_UUID: FUNCTION} if functions is None else functions
    return parse_playbook_detail(row, by_uuid, frozenset(shared), redact)


def _row(**changes: Any) -> dict[str, Any]:
    row = json.loads(json.dumps(build_payloads()["playbook:1000"]))
    row.update(changes)
    return row


# ------------------------------------------------------------------ contract
def test_the_records_are_the_p2_05_reads_of_the_single_playbook():
    assert OBJECT_RECORD["_ticket"] == "P2-05"
    assert OBJECT_RECORD["_request"]["method"] == "GET"
    assert OBJECT_RECORD["_request"]["path"] == "/rest/orgs/{org_id}/playbooks/{playbook_id}"
    assert OBJECT_RECORD["_appliance"] == f"QRadar SOAR {PLAYBOOK_VERIFIED_ON}"
    assert RECORD["parsed"] is True and RECORD["root"]["local_name"] == "definitions"
    assert RECORD["root"]["namespace_class"] == "bpmn_model"


def test_the_record_says_the_call_uuid_matched_exactly_one_function():
    """What resolution by exact uuid equality rests on, on 51.0.9.0.20848."""
    assert RECORD["function_matching"] == "run"
    assert RECORD["uuid_attribute_match"] == "succeeded"
    assert RECORD["uuid_attribute_outcomes"] == {"matched_exactly_one": "1-9"}
    assert RECORD["uuid_attribute_value_forms"] == ["uuid_shaped_string"]
    assert RECORD["attribute_names_by_element"]["vendor_ibm:function"] == ["uuid"]
    located = RECORD["locations_holding_a_function_identity"]
    assert located["vendor_ibm:function@uuid"]["matched_properties"] == ["uuid"]
    assert located["vendor_ibm:function@uuid"]["a_value_matched_more_than_one_function"] is False


def test_the_synthetic_document_has_exactly_the_recorded_elements():
    found: dict[str, set[str]] = {}
    for element in _root().iter():
        ns_class, local = _class_and_local(element.tag)
        found.setdefault(ns_class, set()).add(local)
    assert {k: sorted(v) for k, v in found.items()} == RECORD["namespace_classes"]


def test_the_synthetic_document_has_exactly_the_recorded_attribute_names():
    found: dict[str, set[str]] = {}
    for element in _root().iter():
        if element.attrib:
            ns_class, local = _class_and_local(element.tag)
            found.setdefault(f"{ns_class}:{local}", set()).update(element.attrib)
    assert {k: sorted(v) for k, v in found.items()} == RECORD["attribute_names_by_element"]


def test_the_synthetic_document_puts_text_where_the_record_saw_text():
    with_text = {
        "{}:{}".format(*_class_and_local(e.tag))
        for e in _root().iter()
        if e.text and e.text.strip()
    }
    assert with_text == set(RECORD["elements_with_text_by_element"])


def test_the_synthetic_references_name_the_recorded_kinds():
    referenced = {
        name.split(":")[1] for name in RECORD["elements_referenced_by_a_source_or_target_attribute"]
    }
    assert referenced == {"startEvent", "serviceTask", "endEvent"}
    assert RECORD["source_target_attribute_names_by_element"] == {
        "bpmn_model:sequenceFlow": ["sourceRef", "targetRef"]
    }
    root = _root()
    ids = {e.get("id"): _class_and_local(e.tag)[1] for e in root.iter() if e.get("id")}
    targets = {
        ids[e.get(attr)]
        for e in root.iter()
        if _class_and_local(e.tag)[1] == "sequenceFlow"
        for attr in ("sourceRef", "targetRef")
    }
    assert targets == referenced


def test_the_function_settings_have_the_recorded_key_shape():
    recorded = RECORD["json_payload_shapes_by_element"]["vendor_ibm:function"]
    settings = function_settings()
    assert set(settings) == set(recorded)
    assert settings["inputs"] == {} == recorded["inputs"]
    assert isinstance(settings["result_name"], str) and recorded["result_name"] == "str"


def test_the_synthetic_object_has_the_recorded_keys():
    row = build_payloads()["playbook:1000"]
    assert sorted(row) == OBJECT_RECORD["_facts"]["object_keys"]
    conditions = row["activation_details"]["activation_conditions"]
    assert sorted(conditions) == OBJECT_RECORD["_facts"]["activation_conditions_keys"]
    assert sorted(conditions["conditions"][0]) == OBJECT_RECORD["_facts"]["condition_keys"]
    assert sorted(row["content"]) == OBJECT_RECORD["_facts"]["content_keys"]


# -------------------------------------------------------------------- parser
def test_the_synthetic_playbook_is_described_completely():
    detail = _parse(_row())
    assert (detail.id, detail.name, detail.uuid) == (1000, PLAYBOOK, "uuid-1000")
    assert detail.structure == "parsed" and detail.refusal is None
    assert [(n.id, n.type) for n in detail.nodes] == [
        ("Start_1", "startEvent"),
        ("Function_1", "serviceTask"),
        ("EndPoint_1", "endEvent"),
    ]
    assert [(e.id, e.source, e.target, e.kind) for e in detail.edges] == [
        ("Flow_1", "Start_1", "Function_1", "unconditional"),
        ("Flow_2", "Function_1", "EndPoint_1", "unconditional"),
    ]
    (call_,) = detail.functions
    assert call_.uuid == FUNCTION_UUID and call_.resolution == "resolved"
    assert call_.function == FUNCTION and call_.result_name == RESULT_NAME
    assert call_.input_names == () and call_.settings_parsed is True
    assert detail.problems == () and detail.content_version == 3


def test_conditions_keep_field_and_method_and_never_the_value():
    detail = _parse(_row())
    assert detail.activation == "present" and detail.logic_type == "all"
    assert [(c.field_name, c.method) for c in detail.conditions] == [
        ("incident.field_1000", "contains")
    ]
    assert CONDITION_VALUE not in detail.model_dump_json()


def test_scripts_and_xml_never_reach_the_detail():
    settings = function_settings(
        pre_processing_script=SCRIPT_TEXT, post_processing_script=SCRIPT_TEXT
    )
    detail = _parse(
        _row(content={"content_version": 1, "xml": playbook_xml(FUNCTION_UUID, settings=settings)})
    )
    (call_,) = detail.functions
    assert call_.has_pre_processing_script and call_.has_post_processing_script
    text = detail.model_dump_json()
    assert not [bad for bad in NEVER if bad in text]


@pytest.mark.parametrize(
    ("uuid", "functions", "shared", "resolution", "problem"),
    [
        ("uuid-999", None, (), "unresolved", "names no function"),
        ("UUID-200", None, (), "unresolved", "names no function"),  # exact: no case-folding
        ("uuid-200 ", None, (), "unresolved", "names no function"),  # nor stripping
        ("uuid-2", None, (), "unresolved", "names no function"),  # nor prefixes
        (FUNCTION_UUID, None, (FUNCTION_UUID,), "unresolved", "shared by more than one"),
        (None, None, (), "no_uuid", "has no uuid"),
    ],
)
def test_a_call_resolves_only_by_exact_uuid_to_exactly_one_function(
    uuid: str | None, functions: Any, shared: tuple[str, ...], resolution: str, problem: str
):
    row = _row(content={"content_version": 1, "xml": playbook_xml(uuid)})
    detail = _parse(row, functions, shared)
    (call_,) = detail.functions
    assert call_.resolution == resolution and call_.function is None
    assert any(problem in p for p in detail.problems), detail.problems


def test_function_index_marks_a_uuid_two_functions_share():
    catalog = lab_catalog()
    by_uuid, shared = function_index(catalog.functions)
    assert by_uuid[FUNCTION_UUID] == FUNCTION and shared == frozenset()
    twins = {**catalog.functions, "twin": catalog.functions[FUNCTION]}
    _, shared = function_index(twins)
    assert shared == frozenset({FUNCTION_UUID})


@pytest.mark.parametrize(
    ("xml", "refusal"),
    [
        (
            '<!DOCTYPE x [<!ENTITY e "boom">]><definitions>&e;</definitions>',
            "the playbook XML declares a DTD or an entity",
        ),
        ("<definitions", "the playbook XML is not well-formed"),
        ("<other/>", "the root element is not a BPMN 2.0 definitions element"),
        (
            '<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"/>',
            "the playbook XML has no BPMN process",
        ),
    ],
)
def test_unsafe_or_unexpected_xml_is_refused_not_an_error(xml: str, refusal: str):
    detail = _parse(_row(content={"content_version": 1, "xml": xml}))
    assert detail.structure == "refused" and detail.refusal == refusal
    assert detail.nodes == () and detail.edges == () and detail.problems == ()
    assert detail.activation == "present"  # the rest of the object is still described


def test_a_dangling_flow_is_a_problem_and_kept_invalid():
    detail = _parse(
        _row(
            content={"content_version": 1, "xml": playbook_xml(FUNCTION_UUID, end_target="Nowhere")}
        )
    )
    assert detail.structure == "parsed"
    (flow,) = [e for e in detail.edges if e.id == "Flow_2"]
    assert flow.valid is False
    assert any("Flow_2: its target does not name a node" in p for p in detail.problems)


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"content": None}, "'content' is missing or not an object"),
        ({"content": {"content_version": 1}}, "'content.xml' is missing or not text"),
        ({"content": {"xml": 7}}, "'content.xml' is missing or not text"),
        ({"name": None}, "an identity key is missing"),
        ({"uuid": 5}, "an identity key is missing"),
        ({"status": True}, "an identity key is missing"),
        ({"activation_details": []}, "'activation_details' is not an object"),
        ({"activation_details": {"activation_conditions": "x"}}, "is not an object"),
        (
            {
                "activation_details": {
                    "activation_conditions": {"conditions": {}, "logic_type": "all"}
                }
            },
            "'activation_conditions.conditions' is missing or not a list",
        ),
        (
            # Without the list nothing is known about when it starts: never "no conditions".
            {"activation_details": {"activation_conditions": {"logic_type": "all"}}},
            "'activation_conditions.conditions' is missing or not a list",
        ),
        (
            {"activation_details": {"activation_conditions": {"conditions": []}}},
            "'activation_conditions.logic_type' is missing or not text",
        ),
        (
            {"activation_details": {"activation_conditions": {"conditions": [], "logic_type": 1}}},
            "'activation_conditions.logic_type' is missing or not text",
        ),
    ],
)
def test_an_unexpected_object_shape_fails_closed(change: dict[str, Any], problem: str):
    with pytest.raises(SoarMalformedResponseError) as raised:
        _parse(_row(**change))
    assert problem in str(raised.value)
    assert CONDITION_VALUE not in str(raised.value) and "<definitions" not in str(raised.value)


@pytest.mark.parametrize(
    "details",
    [None, {}, {"activation_conditions": None}],
)
def test_no_activation_conditions_is_said_as_absent(details: Any):
    row = _row(activation_details=details)
    if details is None:
        row.pop("activation_details")
    detail = _parse(row)
    assert detail.activation == "absent"
    assert detail.conditions == () and detail.logic_type is None


def test_an_unreadable_condition_is_counted_not_shown():
    row = _row()
    row["activation_details"]["activation_conditions"]["conditions"].extend(
        [{"field_name": 3, "method": "equals"}, "not an object", {"method": "equals"}]
    )
    detail = _parse(row)
    assert len(detail.conditions) == 1 and detail.unreadable_conditions == 3


def test_a_credential_in_any_kept_text_is_redacted():
    row = _row(display_name=f"pb {SENTINEL}", description=f"key {SENTINEL}")
    row["activation_details"]["activation_conditions"]["conditions"][0]["field_name"] = SENTINEL
    xml = playbook_xml(FUNCTION_UUID).replace('name="synthetic call"', f'name="{SENTINEL}"')
    row["content"]["xml"] = xml
    detail = parse_playbook_detail(
        row, {FUNCTION_UUID: FUNCTION}, frozenset(), lambda t: redact(t.replace(SENTINEL, REDACTED))
    )
    text = detail.model_dump_json()
    assert SENTINEL not in text and REDACTED in text


# --------------------------------------------------------------------- tools
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

    assert params("soar_list_playbooks") == {"name_contains": None, "start": 0, "length": None}
    # No raw XML switch and no condition-value switch: neither can be asked for.
    assert params("soar_get_playbook") == {"name": None, "playbook_id": None}


async def test_list_is_catalog_only(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    data = await ok(rt, "soar_list_playbooks")
    assert fake.requests == []
    assert data["total"] == 2 and [r["name"] for r in data["playbooks"]] == [
        "playbook_1000",
        "playbook_1001",
    ]
    row = data["playbooks"][0]
    assert set(row) == {
        "name", "id", "display_name", "status", "activation_type", "object_type", "type",
        "version", "has_logical_errors", "is_deleted", "is_locked", "description",
    }  # fmt: skip
    assert row["status"] == "enabled" and row["activation_type"] == "automatic"
    assert "uuid" not in row
    assert "values the conditions compare with are not shown" in data["note"]


async def test_list_pages_and_filters(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    page = await ok(rt, "soar_list_playbooks", start=1, length=1)
    assert [r["name"] for r in page["playbooks"]] == ["playbook_1001"] and page["more"] is False
    first = await ok(rt, "soar_list_playbooks", length=1)
    assert first["more"] is True and first["next_start"] == 1
    found = await ok(rt, "soar_list_playbooks", name_contains="DISPLAY_NAME-1001")
    assert [r["id"] for r in found["playbooks"]] == [1001]
    assert fake.requests == []


async def test_get_sends_exactly_one_get_of_the_playbook(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    data = await ok(rt, "soar_get_playbook", playbook_id=1000)
    assert sent(fake) == [("GET", f"{ORG}/playbooks/1000")]
    assert fake.requests[0].params == {
        "handle_format": "names",
        "text_content_output_format": "always_text",
    }
    playbook = data["playbook"]
    assert playbook["name"] == PLAYBOOK and playbook["verified_on"] == PLAYBOOK_VERIFIED_ON
    assert playbook["functions_called"] == [FUNCTION]
    assert playbook["activation"] == {
        "state": "present",
        "logic_type": "all",
        "conditions": [{"field_name": "incident.field_1000", "method": "contains"}],
        "conditions_omitted": 0,
        "unreadable_conditions": 0,
        "values_shown": False,
    }
    assert playbook["structure"] == "parsed" and playbook["function_call_count"] == 1
    assert playbook["functions"][0]["resolution"] == "resolved"
    assert "51.0.9.0.20848" in data["note"] and "never enables" in data["note"]


async def test_get_by_name_is_exact_and_an_unknown_one_sends_nothing(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    await ok(rt, "soar_get_playbook", name=PLAYBOOK)
    assert sent(fake) == [("GET", f"{ORG}/playbooks/1000")]
    fake.requests.clear()
    await failed(rt, "soar_get_playbook", "not_found", name="PLAYBOOK_1000")
    await failed(rt, "soar_get_playbook", "not_found", playbook_id=4242)
    await failed(rt, "soar_get_playbook", "validation")
    await failed(rt, "soar_get_playbook", "validation", name=PLAYBOOK, playbook_id=1000)
    await failed(rt, "soar_get_playbook", "validation", playbook_id=True)
    assert fake.requests == []


async def test_nothing_of_the_xml_or_the_condition_values_is_returned(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    settings = function_settings(pre_processing_script=SCRIPT_TEXT)
    detail_row(fake)["content"]["xml"] = playbook_xml(FUNCTION_UUID, settings=settings)
    out = await call(rt, "soar_get_playbook", playbook_id=1000)
    text = json.dumps(out)
    assert out["ok"] is True
    assert not [bad for bad in NEVER if bad in text]


async def test_a_credential_in_the_object_is_redacted(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    row = detail_row(fake)
    row["description"] = f"see {SENTINEL}"
    conditions = row["activation_details"]["activation_conditions"]
    conditions["logic_type"] = SENTINEL
    conditions["conditions"][0]["field_name"] = f"incident.{SENTINEL}"
    row["content"]["xml"] = row["content"]["xml"].replace(
        'name="synthetic call"', f'name="call {SENTINEL}"'
    )
    out = await call(rt, "soar_get_playbook", playbook_id=1000)
    assert out["ok"] is True and SENTINEL not in json.dumps(out)


async def test_the_detail_is_read_each_time_and_never_cached(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    await ok(rt, "soar_get_playbook", playbook_id=1000)
    await ok(rt, "soar_get_playbook", playbook_id=1000)
    assert sent(fake) == [("GET", f"{ORG}/playbooks/1000")] * 2
    catalog = await rt.require_catalog().get()
    text = catalog.to_json()
    assert "<definitions" not in text and CONDITION_VALUE not in text


async def test_a_renamed_or_replaced_playbook_is_a_conflict(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    detail_row(fake)["name"] = "renamed_since"
    await failed(rt, "soar_get_playbook", "conflict", playbook_id=1000)
    detail_row(fake)["name"] = PLAYBOOK
    detail_row(fake)["uuid"] = "uuid-other"
    await failed(rt, "soar_get_playbook", "conflict", playbook_id=1000)


async def test_another_object_in_the_answer_fails_closed(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    detail_row(fake)["id"] = 1001
    await failed(rt, "soar_get_playbook", "malformed_response", playbook_id=1000)


async def test_an_unexpected_object_fails_closed(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    detail_row(fake)["content"] = {"content_version": 1}
    error = await failed(rt, "soar_get_playbook", "malformed_response", playbook_id=1000)
    assert "content.xml" in error["message"]


async def test_unsafe_xml_is_described_as_refused(rt: Runtime, fake: FakeSoar):
    with_catalog(rt, lab_catalog())
    detail_row(fake)["content"]["xml"] = '<!DOCTYPE x [<!ENTITY e "a">]><definitions/>'
    playbook = (await ok(rt, "soar_get_playbook", playbook_id=1000))["playbook"]
    assert playbook["structure"] == "refused"
    assert playbook["refusal"] == "the playbook XML declares a DTD or an entity"
    assert playbook["nodes"] == [] and playbook["functions_called"] == []


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "auth_failed"), (403, "forbidden"), (404, "not_found"), (500, "server_error")],
)
async def test_soar_errors_are_reported_and_nothing_is_retried_elsewhere(
    status: int, code: str, rt: Runtime, fake: FakeSoar
):
    with_catalog(rt, lab_catalog())
    fake.fault("GET", r"/playbooks/1000$", status=status, body={"message": f"no {SENTINEL}"})
    error = await failed(rt, "soar_get_playbook", code, playbook_id=1000)
    assert SENTINEL not in json.dumps(error)
    assert {path for _, path in sent(fake)} == {f"{ORG}/playbooks/1000"}


async def test_the_tools_write_no_audit_record(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    with_catalog(rt, lab_catalog())
    await ok(rt, "soar_list_playbooks")
    await ok(rt, "soar_get_playbook", playbook_id=1000)
    assert audit_records(tmp_path) == []
    assert all(r.method == "GET" for r in fake.requests)


async def test_both_work_against_the_real_collections_backend(rt: Runtime, fake: FakeSoar):
    """No fixed catalog: the runtime's own backend loads it from the fake, as in use."""
    listing = await ok(rt, "soar_list_playbooks")
    assert listing["total"] == 2
    playbook = (await ok(rt, "soar_get_playbook", name=PLAYBOOK))["playbook"]
    assert playbook["functions_called"] == [FUNCTION]
    assert sent(fake)[-1] == ("GET", f"{ORG}/playbooks/1000")


@pytest.mark.parametrize("playbook_id", [0, -5, True, "7", 1.5])
async def test_the_client_validates_the_id_before_sending(
    playbook_id: Any, rt: Runtime, fake: FakeSoar
):
    with pytest.raises(SoarValidationError):
        await rt.require_client().discovery.playbook(playbook_id)
    assert fake.requests == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_the_fake_answers_only_get_on_a_playbook(method: str, fake: FakeSoar):
    import httpx

    from tests.fake_soar import API_KEY_ID, API_KEY_SECRET, BASE_URL

    async with httpx.AsyncClient(base_url=BASE_URL, auth=(API_KEY_ID, API_KEY_SECRET)) as client:
        answer = await client.request(
            method,
            f"{ORG}/playbooks/1000",
            params={"handle_format": "names", "text_content_output_format": "always_text"},
            json={},
        )
    assert answer.status_code == 405
