"""P2-01: the catalog backends (08 §25).

``collections`` reads exactly the verified read-only calls and parses each wrapper as
``docs/soar-api-verified.md`` recorded it; what that record could not establish stays
unknown. ``export`` is selectable, refuses every load, sends nothing and never falls back.
"""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator
from typing import Any

import pytest

from qradar_soar_mcp.catalog import (
    Catalog,
    CatalogService,
    CollectionsBackend,
    ExportBackend,
    SectionState,
    build_backend,
)
from qradar_soar_mcp.catalog import backends as backends_module
from qradar_soar_mcp.catalog.backends import EXPORT_UNAVAILABLE, PLAYBOOK_PAGE_LENGTH
from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.errors import (
    SoarCatalogUnavailableError,
    SoarForbiddenError,
    SoarMalformedResponseError,
    SoarValidationError,
)
from tests.conftest import connection_env
from tests.discovery_data import verified
from tests.fake_soar import FakeSoar

ORG = "/rest/orgs/201"
# Every request one collections load may send (08 §25), functions/{id} once per function.
EXPECTED_READS = [
    ("GET", "/rest/const"),
    ("GET", f"{ORG}/functions"),
    ("GET", f"{ORG}/types/__function/fields"),
    ("GET", f"{ORG}/functions/200"),
    ("GET", f"{ORG}/functions/201"),
    ("GET", f"{ORG}/scripts"),
    ("GET", f"{ORG}/message_destinations"),
    ("GET", f"{ORG}/incident_types"),
    ("GET", f"{ORG}/phases"),
    ("GET", f"{ORG}/types/incident/fields"),
    ("GET", f"{ORG}/types/task/fields"),
    ("GET", f"{ORG}/types/artifact/fields"),
    ("GET", f"{ORG}/types"),
    ("POST", f"{ORG}/playbooks/query_paged"),
    ("GET", f"{ORG}/actions"),
    ("GET", f"{ORG}/groups"),
    ("GET", f"{ORG}/workflows"),
]


@pytest.fixture
async def client(fake: FakeSoar) -> AsyncIterator[SoarClient]:
    async with SoarClient(Settings.load(connection_env())) as c:
        yield c


async def load(client: SoarClient) -> Catalog:
    return await CollectionsBackend(client).load()


# ------------------------------------------------------------ the requests
async def test_a_load_sends_exactly_the_verified_reads(client: SoarClient, fake: FakeSoar):
    await load(client)
    assert [(r.method, r.path) for r in fake.requests] == EXPECTED_READS


async def test_no_mutation_and_no_export_request_is_emitted(client: SoarClient, fake: FakeSoar):
    await load(client)
    assert {r.method for r in fake.requests} == {"GET", "POST"}
    posts = [r for r in fake.requests if r.method == "POST"]
    assert [r.path for r in posts] == [f"{ORG}/playbooks/query_paged"]
    for r in fake.requests:
        assert "configurations" not in r.path and "export" not in r.path
        assert "import" not in r.path and "execution" not in r.path


async def test_the_playbook_query_is_the_verified_criteria_only_request(
    client: SoarClient, fake: FakeSoar
):
    await load(client)
    (query,) = [r for r in fake.requests if r.method == "POST"]
    assert query.json == {"filters": [], "start": 0, "length": PLAYBOOK_PAGE_LENGTH}
    assert query.params == {
        "handle_format": "names",
        "text_content_output_format": "always_text",
        "return_level": "normal",
    }
    recorded = verified("playbooks_query_paged")["_request"]
    assert recorded["method"] == "POST" and sorted(query.params) == recorded["query_keys"]


async def test_every_read_matches_a_request_the_verified_record_lists(
    client: SoarClient, fake: FakeSoar
):
    import json

    from tests.discovery_data import VERIFIED

    ledger = json.loads((VERIFIED / "_ledger.json").read_text(encoding="utf-8"))
    ok = {
        (r["method"], r["path"])
        for r in ledger["requests"]
        if r["status"] == 200 and r["method"] in ("GET", "POST")
    }
    templates = {
        "/rest/orgs/201/functions/200": "/rest/orgs/{org_id}/functions/{function_id}",
        "/rest/orgs/201/functions/201": "/rest/orgs/{org_id}/functions/{function_id}",
    }
    await load(client)
    for r in fake.requests:
        path = templates.get(r.path, r.path.replace("/rest/orgs/201", "/rest/orgs/{org_id}"))
        assert (r.method, path) in ok, f"{r.method} {path} is not a verified 200 in the ledger"


# ---------------------------------------------------------- wrapper shapes
async def test_each_verified_wrapper_shape_is_parsed(client: SoarClient, fake: FakeSoar):
    catalog = await load(client)
    assert catalog.source == "collections" and catalog.org_id == "201"
    assert catalog.soar_version == "51.0.9.0.20848"  # GET /rest/const, server_version.version
    assert catalog.fetched_at.utcoffset() is not None
    # entities wrappers
    assert set(catalog.functions) == {"function_200", "function_201"}
    assert set(catalog.scripts) == {"programmatic_name-400", "programmatic_name-401"}
    assert set(catalog.message_destinations) == {
        "programmatic_name-500",
        "programmatic_name-501",
    }
    assert set(catalog.phases) == {"phase_600", "phase_601"}
    assert set(catalog.rules) == {"rule_300", "rule_301"}
    # bare lists
    assert set(catalog.groups) == {"group_700", "group_701"}
    assert "task.task_field_800" in catalog.fields
    assert "artifact.properties.artifact_field_801" in catalog.fields
    assert catalog.fields["incident.properties.root_cause"].required == "close"
    # name-keyed maps
    assert set(catalog.incident_types) == {"incident_type_950", "incident_type_951"}
    # data + totals
    assert set(catalog.playbooks) == {"playbook_1000", "playbook_1001"}
    assert catalog.playbooks["playbook_1000"].status == "enabled"
    for name in ("functions", "scripts", "playbooks", "rules", "groups", "fields", "datatables"):
        status = catalog.sections[name]
        assert status.state is SectionState.LOADED
        assert status.count == len(getattr(catalog, name)) > 0


@pytest.mark.parametrize(
    ("key", "bad", "where"),
    [
        ("functions", [], "GET /functions"),
        ("scripts", {"data": []}, "GET /scripts"),
        ("actions", {"entities": "x"}, "rule collection"),
        ("phases", {"entities": [1]}, "GET /phases"),
        ("groups", {"entities": []}, "GET /groups"),
        ("function_fields", {"entities": []}, "__function"),
        ("fields:task", {}, "GET /types/task/fields"),
        ("types", [], "GET /types"),
        ("incident_types", {"entities": []}, "GET /incident_types"),
        ("workflows", [], "GET /workflows"),
    ],
)
async def test_a_wrapper_other_than_the_verified_one_is_malformed(
    client: SoarClient, fake: FakeSoar, key: str, bad: Any, where: str
):
    """No universal wrapper: a bare list where ``entities`` was verified (and the
    reverse) fails the load instead of being read some other way."""
    fake.discovery[key] = bad
    with pytest.raises(SoarMalformedResponseError, match=where):
        await load(client)


async def test_a_playbook_answer_without_the_paged_wrapper_is_malformed(
    client: SoarClient, fake: FakeSoar
):
    fake.fault("POST", r"/playbooks/query_paged$", status=200, body={"entities": []})
    with pytest.raises(SoarMalformedResponseError, match="paged result"):
        await load(client)
    fake.fault("POST", r"/playbooks/query_paged$", status=200, body={"data": []})
    with pytest.raises(SoarMalformedResponseError, match="recordsTotal"):
        await load(client)


async def test_const_without_a_version_is_malformed(client: SoarClient, fake: FakeSoar):
    del fake.discovery["const"]["server_version"]["version"]
    with pytest.raises(SoarMalformedResponseError, match="server version"):
        await load(client)


# ---------------------------------------------------------------- playbooks
async def test_playbooks_are_listed_by_the_paged_query_never_by_get(
    client: SoarClient, fake: FakeSoar
):
    await load(client)
    assert not [r for r in fake.requests if r.path.endswith("/playbooks")]
    assert not [r for r in fake.requests if r.method == "GET" and "/playbooks" in r.path]


async def test_playbooks_are_paged_until_the_total_is_reached(client: SoarClient, fake: FakeSoar):
    row = fake.discovery["playbooks"][0]
    fake.discovery["playbooks"] = [
        {**copy.deepcopy(row), "id": n, "name": f"pb_{n}"} for n in range(PLAYBOOK_PAGE_LENGTH + 7)
    ]
    catalog = await load(client)
    assert len(catalog.playbooks) == PLAYBOOK_PAGE_LENGTH + 7
    pages = [r.json for r in fake.requests if r.method == "POST"]
    assert pages == [
        {"filters": [], "start": 0, "length": PLAYBOOK_PAGE_LENGTH},
        {"filters": [], "start": PLAYBOOK_PAGE_LENGTH, "length": PLAYBOOK_PAGE_LENGTH},
    ]


async def test_pages_that_do_not_add_up_to_the_total_fail_the_load(
    client: SoarClient, fake: FakeSoar
):
    """Later pages were never needed live, so they are checked instead of trusted."""
    row = fake.discovery["playbooks"][0]
    many = [
        {**copy.deepcopy(row), "id": n, "name": f"pb_{n}"} for n in range(PLAYBOOK_PAGE_LENGTH + 3)
    ]
    # An early empty page: SOAR counts 13 and stops handing rows out after the first page.
    fake.fault(
        "POST",
        r"/playbooks/query_paged$",
        status=200,
        body={"data": [], "recordsTotal": len(many), "recordsFiltered": len(many)},
    )
    fake.fault(
        "POST",
        r"/playbooks/query_paged$",
        status=200,
        times=1,
        body={
            "data": many[:PLAYBOOK_PAGE_LENGTH],
            "recordsTotal": len(many),
            "recordsFiltered": len(many),
        },
    )
    with pytest.raises(SoarMalformedResponseError, match="do not add up to recordsTotal"):
        await load(client)


async def test_more_rows_than_the_total_fail_the_load(client: SoarClient, fake: FakeSoar):
    fake.fault(
        "POST",
        r"/playbooks/query_paged$",
        status=200,
        body={"data": fake.discovery["playbooks"], "recordsTotal": 1, "recordsFiltered": 1},
    )
    with pytest.raises(SoarMalformedResponseError, match="do not add up to recordsTotal"):
        await load(client)


async def test_a_server_that_ignores_start_cannot_produce_a_catalog(
    client: SoarClient, fake: FakeSoar
):
    row = fake.discovery["playbooks"][0]
    many = [
        {**copy.deepcopy(row), "id": n, "name": f"pb_{n}"} for n in range(PLAYBOOK_PAGE_LENGTH * 2)
    ]
    fake.fault(
        "POST",
        r"/playbooks/query_paged$",
        status=200,
        body={
            "data": many[:PLAYBOOK_PAGE_LENGTH],  # page one again, whatever start says
            "recordsTotal": len(many),
            "recordsFiltered": len(many),
        },
    )
    with pytest.raises(SoarMalformedResponseError, match="share one name"):
        await load(client)


def test_the_page_length_is_one_that_was_sent_live():
    assert verified("p2_00b_playbooks")["_facts"]["page_length"] == PLAYBOOK_PAGE_LENGTH


async def test_too_many_playbook_pages_fail_the_load_instead_of_truncating(
    client: SoarClient, fake: FakeSoar, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(backends_module, "MAX_PLAYBOOK_PAGES", 1)
    row = fake.discovery["playbooks"][0]
    fake.discovery["playbooks"] = [
        {**copy.deepcopy(row), "id": n, "name": f"pb_{n}"} for n in range(PLAYBOOK_PAGE_LENGTH + 1)
    ]
    with pytest.raises(SoarMalformedResponseError, match="playbooks"):
        await load(client)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"start": -1, "length": 10},
        {"start": 0, "length": 0},
        {"start": 0, "length": 101},
        {"start": True, "length": 10},
        {"start": "0", "length": 10},
        {"start": 0, "length": 10.0},
        {"start": None, "length": 10},
    ],
)
async def test_the_playbook_query_takes_two_integers_and_nothing_else(
    client: SoarClient, fake: FakeSoar, kwargs: dict[str, Any]
):
    with pytest.raises(SoarValidationError) as caught:
        await client.discovery.playbooks_page(**kwargs)
    assert caught.value.not_sent is True and fake.requests == []
    import inspect

    assert list(inspect.signature(client.discovery.playbooks_page).parameters) == [
        "start",
        "length",
    ]


# --------------------------------------------------------------- datatables
async def test_datatables_are_the_types_with_type_id_8(client: SoarClient, fake: FakeSoar):
    types = fake.discovery["types"]
    assert {name: t["type_id"] for name, t in types.items()} == {
        "incident": 0,
        "table_1": 8,
        "table_2": 8,
    }
    # Looks like a table in every other respect; only the discriminator counts.
    types["lookalike"] = {**copy.deepcopy(types["table_1"]), "type_name": "lookalike", "type_id": 9}
    catalog = await load(client)
    assert set(catalog.datatables) == {"table_1", "table_2"}
    table = catalog.datatables["table_1"]
    assert table.parent_types == ("incident",)
    assert [c.name for c in table.columns] == ["column_a", "column_b"]
    assert not [r for r in fake.requests if "datatable" in r.path or "table_data" in r.path]


# ---------------------------------------------------------------- functions
async def test_function_inputs_resolve_through_view_items_to_function_fields(
    client: SoarClient, fake: FakeSoar
):
    fields = fake.discovery["function_fields"]
    assert "required" not in fields[0]  # no token value was ever recorded for an input
    fields[0]["required"] = "token-100"  # synthetic: whatever SOAR says is kept as it is
    detail = fake.discovery["function:200"]
    assert fake.discovery["functions"]["entities"][0]["view_items"] == []  # as verified
    assert [item["content"] for item in detail["view_items"]] == [f["uuid"] for f in fields]
    catalog = await load(client)
    fn = catalog.functions["function_200"]
    assert [i.uuid for i in fn.inputs] == [f["uuid"] for f in fields]
    assert [i.name for i in fn.inputs] == ["input_100", "input_101"]
    assert [i.input_type for i in fn.inputs] == ["boolean", "select"]
    assert fn.inputs[0].required == "token-100" and fn.inputs[1].required is None
    assert fn.unresolved_inputs == 0
    assert fn.destination_handle == "destination_handle-200" and fn.version == 200
    # No special parameter: the single read carries only the two default ones.
    single = next(r for r in fake.requests if r.path.endswith("/functions/200"))
    assert set(single.params) == {"handle_format", "text_content_output_format"}


async def test_a_view_item_that_resolves_to_nothing_is_counted_not_guessed(
    client: SoarClient, fake: FakeSoar
):
    detail = fake.discovery["function:200"]
    detail["view_items"].append({**detail["view_items"][0], "content": "uuid-of-no-field"})
    detail["view_items"].append({**detail["view_items"][0], "content": None})
    fn = (await load(client)).functions["function_200"]
    assert len(fn.inputs) == 2 and fn.unresolved_inputs == 2


async def test_a_field_referenced_twice_is_one_input(client: SoarClient, fake: FakeSoar):
    detail = fake.discovery["function:200"]
    detail["view_items"].append(dict(detail["view_items"][0]))
    fn = (await load(client)).functions["function_200"]
    assert [i.name for i in fn.inputs] == ["input_100", "input_101"]
    assert fn.unresolved_inputs == 0


async def test_a_catalog_the_model_refuses_is_an_error_not_a_partial_catalog(
    client: SoarClient, fake: FakeSoar
):
    from datetime import datetime

    naive = CollectionsBackend(client, now=lambda: datetime(2026, 9, 18))
    with pytest.raises(SoarMalformedResponseError, match="section catalog") as caught:
        await naive.load()
    assert caught.value.__cause__ is None


async def test_an_optional_required_key_may_be_absent(client: SoarClient, fake: FakeSoar):
    assert "required?" in verified("function_fields")["shape"][0]  # optional on the appliance
    assert "required" not in fake.discovery["function_fields"][0]  # and absent here
    fn = (await load(client)).functions["function_200"]
    assert fn.inputs[0].required is None


# ------------------------------------------- the least the appliance guarantees
async def test_the_loader_needs_nothing_the_recorded_shapes_mark_optional_or_nullable(
    client: SoarClient, fake: FakeSoar
):
    """Every ``key?`` absent and every nullable value null, incident fields included."""
    from tests.discovery_data import build_payloads

    full = await load(client)
    fake.discovery = build_payloads(minimal=True)
    fake.fields = fake.discovery["fields:incident"]
    assert "required" not in fake.discovery["function_fields"][0]
    assert fake.discovery["fields:artifact"][0]["prefix"] is None
    assert fake.discovery["playbooks"][0]["description"] is None
    minimal = await load(client)
    for name in ("functions", "scripts", "message_destinations", "incident_types", "phases"):
        assert set(getattr(minimal, name)) == set(getattr(full, name)), name
    for name in ("datatables", "playbooks", "rules", "groups"):
        assert set(getattr(minimal, name)) == set(getattr(full, name)), name
    assert {k for k in minimal.fields if k.startswith("incident.")} == {
        "incident.incident_field_800",
        "incident.properties.incident_field_801",
    }
    fn = minimal.functions["function_200"]
    assert len(fn.inputs) == 2 and fn.inputs[0].required is None
    assert Catalog.from_json(minimal.to_json()) == minimal


async def test_the_recorded_incident_field_shape_loads_too(client: SoarClient, fake: FakeSoar):
    from tests.discovery_data import build_payloads

    fake.fields = build_payloads()["fields:incident"]
    fields = (await load(client)).fields
    assert fields["incident.properties.incident_field_801"].custom is True


# ------------------------------------------------- unknown stays unknown
async def test_what_the_record_could_not_establish_stays_unknown(
    client: SoarClient, fake: FakeSoar
):
    catalog = await load(client)
    for name in ("api_key_permissions", "installed_apps"):
        status = catalog.sections[name]
        assert status.state is SectionState.NOT_OBSERVABLE and status.reason
        assert len(getattr(catalog, name)) == 0
    # Successful reads are not evidence about what the key may write.
    assert "write" in (catalog.sections["api_key_permissions"].reason or "")
    assert catalog.api_key_permissions == frozenset()
    # Nothing asked SOAR about permissions, sessions or API keys.
    for r in fake.requests:
        assert not any(w in r.path for w in ("permissions", "apikeys", "session", "acl"))


async def test_an_empty_workflow_collection_is_known_empty(client: SoarClient, fake: FakeSoar):
    assert verified("workflows")["_facts"]["rows"] == "0"
    catalog = await load(client)
    assert catalog.workflows == {}
    assert catalog.sections["workflows"].state is SectionState.LOADED
    assert catalog.sections["workflows"].count == 0


async def test_workflow_rows_of_unverified_shape_are_counted_never_parsed(
    client: SoarClient, fake: FakeSoar
):
    fake.discovery["workflows"] = {
        "entities": [
            {"workflow_id": 1, "name": "wf", "content": {"xml": "<definitions/>"}},
            {"anything": "at all"},
        ]
    }
    catalog = await load(client)
    status = catalog.sections["workflows"]
    assert catalog.workflows == {}
    assert status.state is SectionState.UNVERIFIED and status.count == 2
    assert "unverified" in (status.reason or "")
    assert "definitions" not in catalog.to_json()
    assert not [r for r in fake.requests if r.path.count("/workflows/")]  # no GET by id


async def test_people_bodies_and_bound_keys_are_not_ingested(client: SoarClient, fake: FakeSoar):
    d = fake.discovery
    d["scripts"]["entities"][0]["script_text"] = "BODY-MARKER"
    d["scripts"]["entities"][0]["creator_id"] = "PERSON-MARKER-1"
    d["playbooks"][0]["content"] = {"xml": "XML-MARKER"}
    d["playbooks"][0]["creator_principal"]["display_name"] = "PERSON-MARKER-2"
    d["groups"][0]["members"] = ["PERSON-MARKER-3"]
    d["message_destinations"]["entities"][0]["api_keys"] = ["KEY-NAME-MARKER"]
    d["function_fields"][0]["templates"][0]["template"] = "TEMPLATE-MARKER"
    d["function:200"]["output_json_example"] = "EXAMPLE-MARKER"
    d["function:200"]["last_modified_by"]["display_name"] = "PERSON-MARKER-4"
    # The users and groups an owner or members field offers as its values.
    person = {"label": "PERSON-MARKER-5", "value": 7, "enabled": True, "default": False}
    d["fields:task"][0].update(input_type="select_owner", values=[dict(person)])
    d["fields:task"][1].update(input_type="multiselect_members", values=[dict(person)])
    d["fields:artifact"][0].update(
        input_type="select",
        values=[{**person, "principal_type": "user"}, {**person, "label": "an option"}],
    )
    d["function_fields"][1].update(
        input_type="select", values=[{**person, "principal_type": "group"}]
    )
    catalog = await load(client)
    assert "MARKER" not in catalog.to_json()
    assert catalog.fields["task.task_field_800"].values == ()
    assert [v.label for v in catalog.fields["artifact.artifact_field_800"].values] == ["an option"]
    assert not [r for r in fake.requests if r.path.endswith("/users")]


# ------------------------------------------------------- malformed content
@pytest.mark.parametrize(
    ("key", "mutate", "section"),
    [
        ("scripts", lambda d: d["entities"][0].pop("programmatic_name"), "scripts"),
        ("scripts", lambda d: d["entities"][0].update(id="400"), "scripts"),
        ("scripts", lambda d: d["entities"][0].update(id=True), "scripts"),
        ("phases", lambda d: d["entities"][0].update(order=None), "phases"),
        ("groups", lambda d: d[0].pop("uuid"), "groups"),
        ("actions", lambda d: d["entities"][0].update(enabled="yes"), "rules"),
        ("types", lambda d: d["table_1"].update(fields=[]), "datatables"),
        ("types", lambda d: d["table_1"]["fields"].update(column_a="text"), "datatables"),
        ("function:200", lambda d: d.pop("view_items"), "functions"),
        ("function_fields", lambda d: d[0].pop("input_type"), "functions"),
    ],
)
async def test_a_row_that_lacks_a_verified_key_fails_the_whole_load(
    client: SoarClient, fake: FakeSoar, key: str, mutate: Any, section: str
):
    mutate(fake.discovery[key])
    with pytest.raises(SoarMalformedResponseError, match=f"section {section}"):
        await load(client)


async def test_more_functions_than_the_bound_fail_the_load_before_any_detail_read(
    client: SoarClient, fake: FakeSoar, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(backends_module, "MAX_FUNCTIONS", 1)
    with pytest.raises(SoarMalformedResponseError, match="more than 1 functions"):
        await load(client)
    assert not [r for r in fake.requests if "/functions/" in r.path]


async def test_a_single_function_that_is_not_an_object_is_malformed(
    client: SoarClient, fake: FakeSoar
):
    fake.discovery["function:200"] = ["not", "an", "object"]
    with pytest.raises(SoarMalformedResponseError, match=r"GET /functions/\{id\}"):
        await load(client)


async def test_select_values_without_a_label_are_skipped_and_odd_values_are_dropped(
    client: SoarClient, fake: FakeSoar
):
    fake.discovery["function_fields"][1]["values"] = [
        {"label": "kept", "value": 7, "default": False, "enabled": False},
        {"value": 8},
        "not an object",
        {"label": "no usable value", "value": {"nested": True}},
    ]
    values = (await load(client)).functions["function_200"].inputs[1].values
    assert [(v.label, v.value, v.enabled, v.default) for v in values] == [
        ("kept", 7, False, False),
        ("no usable value", None, True, False),
    ]


async def test_a_field_prefix_is_kept_as_it_came_and_only_properties_has_a_meaning(
    client: SoarClient, fake: FakeSoar
):
    fake.discovery["fields:task"][0]["prefix"] = "some_other_prefix"
    fields = (await load(client)).fields
    other = fields["task.some_other_prefix.task_field_800"]
    assert other.prefix == "some_other_prefix" and other.custom is False
    assert other.api_name == "task_field_800"  # no meaning is given to an unknown prefix
    custom = fields["task.properties.task_field_801"]
    assert custom.prefix == "properties" and custom.custom is True


async def test_one_name_under_two_prefixes_is_two_fields_not_a_failed_load(
    client: SoarClient, fake: FakeSoar
):
    first, second = fake.discovery["fields:artifact"]
    second.update(name=first["name"], prefix="some_other_prefix")
    fields = (await load(client)).fields
    assert {"artifact.artifact_field_800", "artifact.some_other_prefix.artifact_field_800"} <= set(
        fields
    )


async def test_text_is_capped(client: SoarClient, fake: FakeSoar):
    fake.discovery["scripts"]["entities"][0]["description"] = "d" * 5_000
    script = next(iter((await load(client)).scripts.values()))
    assert script.description is not None and len(script.description) == 1_000


async def test_two_objects_under_one_name_fail_the_load(client: SoarClient, fake: FakeSoar):
    rows = fake.discovery["scripts"]["entities"]
    rows[1]["programmatic_name"] = rows[0]["programmatic_name"]
    with pytest.raises(SoarMalformedResponseError, match="share one name"):
        await load(client)


async def test_a_malformed_error_never_echoes_a_value(client: SoarClient, fake: FakeSoar):
    fake.discovery["scripts"]["entities"][0]["id"] = "VALUE-THAT-MUST-NOT-BE-ECHOED"
    with pytest.raises(SoarMalformedResponseError) as caught:
        await load(client)
    assert "VALUE-THAT-MUST-NOT-BE-ECHOED" not in caught.value.safe_message


async def test_a_refused_read_fails_the_load_and_no_partial_catalog_exists(
    client: SoarClient, fake: FakeSoar
):
    fake.fault("GET", r"/scripts$", status=403, body={"message": "Forbidden"})
    service = CatalogService(CollectionsBackend(client), ttl_seconds=300)
    with pytest.raises(SoarForbiddenError):
        await service.get()
    assert service.cached() is None


async def test_field_definitions_are_read_for_the_three_verified_types_only(
    client: SoarClient, fake: FakeSoar
):
    with pytest.raises(SoarValidationError) as caught:
        await client.discovery.type_fields("__function/../users")
    assert caught.value.not_sent is True and fake.requests == []


# ------------------------------------------------------------------- export
async def test_export_is_selectable_and_its_selection_is_explicit(client: SoarClient):
    assert isinstance(build_backend("collections", client), CollectionsBackend)
    backend = build_backend("export", client)
    assert isinstance(backend, ExportBackend) and backend.source == "export"
    with pytest.raises(ValueError, match="unknown catalog source"):
        build_backend("whatever", client)
    settings = Settings.load(connection_env(SOAR_CATALOG_SOURCE="export"))
    assert CatalogService.from_settings(settings, client).source == "export"
    assert CatalogService.from_settings(Settings.load(connection_env()), client).source == (
        "collections"
    )


async def test_the_export_backend_refuses_clearly_and_sends_nothing(
    client: SoarClient, fake: FakeSoar
):
    service = CatalogService(build_backend("export", client), ttl_seconds=300)
    for call in (service.get, service.refresh):
        with pytest.raises(SoarCatalogUnavailableError) as caught:
            await call()
        error = caught.value
        assert error.code == "catalog_unavailable" and error.not_sent is True
        assert error.safe_message == EXPORT_UNAVAILABLE
        assert "403" in error.safe_message and "collections" in error.safe_message
    assert fake.requests == []  # no export POST, and no fallback to the collections
    assert service.cached() is None  # and no invented catalog


def test_the_export_backend_cannot_send_or_fall_back_by_construction():
    backend = ExportBackend()
    assert vars(backend) == {}  # it holds no client and knows no other backend
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(backends_module))
    cls = next(
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "ExportBackend"
    )
    names = {n.id for n in ast.walk(cls) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(cls) if isinstance(n, ast.Attribute)}
    assert "CollectionsBackend" not in names and "discovery" not in attrs
    # And nowhere in the catalog or the client is an export request spelled out.
    from pathlib import Path

    import qradar_soar_mcp

    for path in Path(qradar_soar_mcp.__file__).parent.rglob("*.py"):
        assert "configurations/" not in path.read_text(encoding="utf-8"), path.name
