"""P1-01 (08 §2.1): the documented Phase-1 REST semantics, in executable form.

These tests drive the fake with a bare httpx client. They are the contract the
project's client (P1-04) must satisfy; they do not depend on it.

Source of truth: docs/design/05-SOAR-API-SURFACE.md §1 and §1.1, except for tasks
and manual actions, where docs/soar-api-verified.md (QRadar SOAR 51.0.9.0.20848)
wins (P1-CORR-01 and P1-CORR-02; 08 §21, §24).
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import httpx
import pytest

from tests.fake_soar import (
    API_KEY_ID,
    BASE_URL,
    REQUIRED_PARAMS,
    TASK_CLOSED_AT,
    TASK_FORMAT_HEADERS,
    FakeSoar,
)

pytestmark = pytest.mark.contract

ORG = "/rest/orgs/201"
QP = {"return_level": "normal"}


def _patch(version: int, **changes: tuple[object, object]) -> dict:
    return {
        "version": version,
        "changes": [
            {"field": {"name": name}, "old_value": {"object": old}, "new_value": {"object": new}}
            for name, (old, new) in changes.items()
        ],
    }


# ------------------------------------------------------------- auth + params


async def test_basic_auth_is_required(fake: FakeSoar):
    async with httpx.AsyncClient(base_url=BASE_URL, params=REQUIRED_PARAMS) as c:
        r = await c.get(f"{ORG}/incidents/42")
    assert r.status_code == 401


async def test_wrong_secret_is_401(fake: FakeSoar):
    async with httpx.AsyncClient(
        base_url=BASE_URL, auth=(API_KEY_ID, "wrong"), params=REQUIRED_PARAMS
    ) as c:
        r = await c.get(f"{ORG}/incidents/42")
    assert r.status_code == 401
    assert r.json()["success"] is False


async def test_auth_header_is_basic_id_colon_secret(fake: FakeSoar, raw_client):
    await raw_client.get(f"{ORG}/incidents/42")
    sent = fake.requests[-1].headers["authorization"]
    assert sent.startswith("Basic ")
    assert base64.b64decode(sent[6:]).decode().startswith(f"{API_KEY_ID}:")


@pytest.mark.parametrize("missing", list(REQUIRED_PARAMS))
async def test_both_query_params_required_on_every_request(fake: FakeSoar, missing: str):
    params = {k: v for k, v in REQUIRED_PARAMS.items() if k != missing}
    async with httpx.AsyncClient(
        base_url=BASE_URL, auth=(API_KEY_ID, fake_secret()), params=params
    ) as c:
        r = await c.get(f"{ORG}/incidents/42")
    assert r.status_code == 400
    assert missing in r.json()["message"]


def fake_secret() -> str:
    from tests.fake_soar import API_KEY_SECRET

    return API_KEY_SECRET


# ------------------------------------------------------------------ session


async def test_session_is_forbidden_to_api_keys_by_default(fake: FakeSoar, raw_client):
    r = await raw_client.get("/rest/session")
    assert r.status_code == 403


async def test_session_when_permitted_lists_orgs(raw_client):
    import respx

    engine = FakeSoar(session_status=200)
    with respx.mock(base_url=BASE_URL, assert_all_mocked=True) as router:
        router.route().mock(side_effect=engine.handler)
        r = await raw_client.get("/rest/session")
    assert r.status_code == 200
    assert r.json()["orgs"][0]["id"] == 201


# -------------------------------------------------------------- query_paged


async def test_query_paged_requires_return_level_normal(fake: FakeSoar, raw_client):
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json={"filters": []})
    assert r.status_code == 400
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json={"filters": []}, params=QP)
    assert r.status_code == 200


async def test_query_paged_response_shape(fake: FakeSoar, raw_client):
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json={"filters": []}, params=QP)
    body = r.json()
    assert set(body) == {"recordsTotal", "recordsFiltered", "data"}
    assert body["recordsTotal"] == 1 and body["data"][0]["id"] == 42


async def _seed(raw_client, n: int = 4) -> None:
    for i in range(n):
        r = await raw_client.post(
            f"{ORG}/incidents",
            json={
                "name": f"seed {i}",
                "discovered_date": 1758000000000 + i,
                "severity_code": "High" if i % 2 else "Low",
            },
        )
        assert r.status_code == 200


async def test_conditions_within_one_filter_are_anded(fake: FakeSoar, raw_client):
    await _seed(raw_client)
    body = {
        "filters": [
            {
                "conditions": [
                    {"field_name": "plan_status", "method": "equals", "value": "A"},
                    {"field_name": "severity_code", "method": "equals", "value": "High"},
                ]
            }
        ]
    }
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json=body, params=QP)
    ids = [i["id"] for i in r.json()["data"]]
    assert ids == [10002, 10004]  # only the High ones, all active


async def test_separate_filters_are_ored(fake: FakeSoar, raw_client):
    await _seed(raw_client)
    body = {
        "filters": [
            {"conditions": [{"field_name": "id", "method": "equals", "value": 42}]},
            {"conditions": [{"field_name": "id", "method": "equals", "value": 10003}]},
        ]
    }
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json=body, params=QP)
    assert sorted(i["id"] for i in r.json()["data"]) == [42, 10003]
    assert r.json()["recordsFiltered"] == 2


async def test_plan_status_a_and_c(fake: FakeSoar, raw_client):
    fake.incident["plan_status"] = "C"
    body = {
        "filters": [
            {"conditions": [{"field_name": "plan_status", "method": "equals", "value": "C"}]}
        ]
    }
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json=body, params=QP)
    assert [i["id"] for i in r.json()["data"]] == [42]
    body["filters"][0]["conditions"][0]["value"] = "A"
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json=body, params=QP)
    assert r.json()["data"] == []


async def test_custom_fields_are_addressed_as_properties_dot_name(fake: FakeSoar, raw_client):
    body = {
        "filters": [
            {
                "conditions": [
                    {
                        "field_name": "properties.threat_source",
                        "method": "equals",
                        "value": "unknown",
                    }
                ]
            }
        ]
    }
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json=body, params=QP)
    assert [i["id"] for i in r.json()["data"]] == [42]


async def test_query_paged_start_length_and_sort(fake: FakeSoar, raw_client):
    await _seed(raw_client, 5)
    body = {"filters": [], "sorts": [{"field_name": "id", "type": "desc"}], "start": 1, "length": 2}
    r = await raw_client.post(f"{ORG}/incidents/query_paged", json=body, params=QP)
    assert [i["id"] for i in r.json()["data"]] == [10004, 10003]
    assert r.json()["recordsTotal"] == 6


# ------------------------------------------------------------ incident CRUD


async def test_get_incident_carries_version_and_properties(fake: FakeSoar, raw_client):
    r = await raw_client.get(f"{ORG}/incidents/42")
    inc = r.json()
    assert inc["vers"] == 3
    assert inc["properties"]["threat_source"] == "unknown"
    assert (await raw_client.get(f"{ORG}/incidents/999")).status_code == 404


async def test_create_requires_name_and_discovered_date(fake: FakeSoar, raw_client):
    assert (
        await raw_client.post(f"{ORG}/incidents", json={"discovered_date": 1})
    ).status_code == 400
    assert (await raw_client.post(f"{ORG}/incidents", json={"name": "x"})).status_code == 400
    r = await raw_client.post(f"{ORG}/incidents", json={"name": "x", "discovered_date": 1})
    assert r.status_code == 200 and r.json()["vers"] == 1 and r.json()["plan_status"] == "A"


# ------------------------------------------------------------------- PATCH


async def test_patch_is_optimistic_concurrency_stale_version_is_success_false(
    fake: FakeSoar, raw_client
):
    r = await raw_client.patch(f"{ORG}/incidents/42", json=_patch(2, description=("x", "y")))
    assert r.status_code == 200  # NOT an HTTP error
    assert r.json()["success"] is False
    assert "modified" in r.json()["message"]
    assert fake.incident["vers"] == 3


async def test_patch_old_value_mismatch_reports_field_failures(fake: FakeSoar, raw_client):
    r = await raw_client.patch(f"{ORG}/incidents/42", json=_patch(3, severity_code=("Low", "High")))
    body = r.json()
    assert body["success"] is False
    assert body["field_failures"][0] == {
        "field": "severity_code",
        "your_original_value": "Low",
        "actual_current_value": "Medium",
    }


async def test_patch_success_applies_and_bumps_version(fake: FakeSoar, raw_client):
    r = await raw_client.patch(
        f"{ORG}/incidents/42", json=_patch(3, severity_code=("Medium", "High"))
    )
    assert r.json() == {
        "success": True,
        "title": None,
        "message": None,
        "hints": [],
        "field_failures": [],
    }
    assert fake.incident["severity_code"] == "High" and fake.incident["vers"] == 4


async def test_patch_custom_field_uses_bare_name_and_lands_under_properties(
    fake: FakeSoar, raw_client
):
    r = await raw_client.patch(
        f"{ORG}/incidents/42", json=_patch(3, triage_summary=(None, "Benign."))
    )
    assert r.json()["success"] is True
    assert fake.incident["properties"]["triage_summary"] == "Benign."
    assert "triage_summary" not in fake.incident


async def test_patch_unknown_field_is_400(fake: FakeSoar, raw_client):
    r = await raw_client.patch(f"{ORG}/incidents/42", json=_patch(3, nonexistent=(None, 1)))
    assert r.status_code == 400


# ------------------------------------------------------------------- close


async def test_close_needs_plan_status_resolution_and_summary_together(fake: FakeSoar, raw_client):
    fake.incident["properties"]["root_cause"] = "credential reuse"
    r = await raw_client.patch(f"{ORG}/incidents/42", json=_patch(3, plan_status=("A", "C")))
    assert r.json()["success"] is False
    assert "resolution_id" in r.json()["message"] and "resolution_summary" in r.json()["message"]
    assert fake.incident["plan_status"] == "A"


async def test_close_fails_when_a_close_required_custom_field_is_empty(fake: FakeSoar, raw_client):
    r = await raw_client.patch(
        f"{ORG}/incidents/42",
        json=_patch(
            3,
            plan_status=("A", "C"),
            resolution_id=(None, "Resolved"),
            resolution_summary=(None, "done"),
        ),
    )
    assert r.json()["success"] is False
    assert r.json()["field_failures"][0]["field"] == "properties.root_cause"


async def test_close_succeeds_with_everything_present(fake: FakeSoar, raw_client):
    r = await raw_client.patch(
        f"{ORG}/incidents/42",
        json=_patch(
            3,
            plan_status=("A", "C"),
            resolution_id=(None, "Resolved"),
            resolution_summary=(None, "done"),
            root_cause=(None, "credential reuse"),
        ),
    )
    assert r.json()["success"] is True
    assert fake.incident["plan_status"] == "C" and fake.incident["end_date"] is not None


# ------------------------------------------------------ comments / artifacts


async def test_comments_tree_and_text_content_dto(fake: FakeSoar, raw_client):
    r = await raw_client.get(f"{ORG}/incidents/42/comments")
    assert r.json()[1]["children"][0]["id"] == 7003
    bad = await raw_client.post(f"{ORG}/incidents/42/comments", json={"text": "plain string"})
    assert bad.status_code == 400
    ok = await raw_client.post(
        f"{ORG}/incidents/42/comments", json={"text": {"format": "text", "content": "hi"}}
    )
    assert ok.status_code == 200 and ok.json()["text"] == "hi"


async def test_artifacts_list_and_add(fake: FakeSoar, raw_client):
    r = await raw_client.get(f"{ORG}/incidents/42/artifacts")
    assert r.json()[0]["type"] == "IP Address"
    ok = await raw_client.post(
        f"{ORG}/incidents/42/artifacts", json={"type": "URL", "value": "https://x.example.com/"}
    )
    assert ok.status_code == 200 and ok.json()["value"] == "https://x.example.com/"
    assert (
        await raw_client.post(f"{ORG}/incidents/42/artifacts", json={"type": "URL"})
    ).status_code == 400


# ------------------------------------------------------------------- tasks


async def test_tasks_carry_no_version(fake: FakeSoar, raw_client):
    """Verified on 51.0.9.0.20848 (docs/soar-api-verified.md §3 D2)."""
    rows = (await raw_client.get(f"{ORG}/incidents/42/tasks")).json()
    single = (await raw_client.get(f"{ORG}/tasks/9001")).json()
    assert {t["id"] for t in rows} == {9001, 9002}
    for task in [*rows, single]:
        assert not {"vers", "version"} & set(task)


async def test_task_patch_is_not_modelled(fake: FakeSoar, raw_client):
    """D1: PATCH was the Phase-1 assumption; 51.0.9 documents no PATCH on a task."""
    r = await raw_client.patch(f"{ORG}/tasks/9001", json=_patch(2, status=("O", "C")))
    assert r.status_code == 404 and r.json()["message"] == "fake_soar: no route"
    assert fake.tasks[9001]["status"] == "O"


@pytest.fixture
async def task_client() -> AsyncIterator[httpx.AsyncClient]:
    """The form P2-00b verified: the two format controls as headers, no query string."""
    async with httpx.AsyncClient(
        base_url=BASE_URL, auth=(API_KEY_ID, fake_secret()), headers=TASK_FORMAT_HEADERS
    ) as c:
        yield c


async def test_task_status_put_contract(fake: FakeSoar, raw_client, task_client):
    """docs/soar-api-verified.md §3.1: the whole GET object back, status the only change;
    a StatusDTO answer; closed_date set and cleared by the server."""
    task = (await task_client.get(f"{ORG}/tasks/9001")).json()
    assert len(task) == 41 and task["status"] == "O" and task["closed_date"] is None
    assert task["task_layout"] == [] and not {"vers", "version"} & set(task)
    assert isinstance(task["phase_id"], int)  # handle_format: ids

    r = await task_client.put(f"{ORG}/tasks/9001", json={**task, "status": "C"})
    assert r.status_code == 200
    assert r.json() == {"success": True, "title": None, "message": None, "hints": []}
    closed = (await task_client.get(f"{ORG}/tasks/9001")).json()
    assert {k for k in task if task[k] != closed[k]} == {"status", "closed_date"}
    assert closed["status"] == "C" and closed["closed_date"] == TASK_CLOSED_AT

    r = await task_client.put(f"{ORG}/tasks/9001", json={**closed, "status": "O"})
    assert r.status_code == 200
    assert (await task_client.get(f"{ORG}/tasks/9001")).json() == task  # nothing differs
    rows = (await raw_client.get(f"{ORG}/incidents/42/tasks")).json()
    assert {t["id"]: t["status"] for t in rows} == {9001: "O", 9002: "C"}


@pytest.mark.parametrize(
    "body",
    [
        {"id": 9001, "status": "C"},
        {"status": "C"},
        {"version": 1, "changes": []},
    ],
    ids=["reduced", "status_only", "patch_dto"],
)
async def test_task_put_refuses_anything_but_the_whole_object(
    fake: FakeSoar, task_client, body: dict
):
    """Stricter than anything observed on the appliance, on purpose: an invented body
    must not be able to pass offline."""
    r = await task_client.put(f"{ORG}/tasks/9001", json=body)
    assert r.status_code == 400 and r.json()["message"].startswith("fake_soar:")
    assert fake.task_objects[9001]["status"] == "O"


async def test_task_put_is_modelled_in_the_verified_form_only(fake: FakeSoar, raw_client):
    task = dict(fake.task_objects[9001])
    r = await raw_client.put(f"{ORG}/tasks/9001", json={**task, "status": "C"})  # query form
    assert r.status_code == 400 and r.json()["message"].startswith("fake_soar:")
    assert fake.task_objects[9001]["status"] == "O"


# -------------------------------------------------------------- attachments


async def test_attachments_metadata_only_no_contents_route(fake: FakeSoar, raw_client):
    r = await raw_client.get(f"{ORG}/incidents/42/attachments")
    assert r.json()[0]["name"] == "signin-export.csv"
    assert (
        await raw_client.get(f"{ORG}/incidents/42/attachments/5001/contents")
    ).status_code == 404


# ---------------------------------------------------------- users / fields


async def test_users_list(fake: FakeSoar, raw_client):
    r = await raw_client.get(f"{ORG}/users")
    assert [u["display_name"] for u in r.json()] == ["Analyst One", "Analyst Two"]


async def test_incident_fields_expose_prefix_and_close_required(fake: FakeSoar, raw_client):
    r = await raw_client.get(f"{ORG}/types/incident/fields")
    by_name = {f["name"]: f for f in r.json()}
    assert by_name["root_cause"]["prefix"] == "properties"
    assert by_name["root_cause"]["required"] == "close"
    assert "prefix" not in by_name["severity_code"]
    assert by_name["resolution_id"]["values"][0]["label"] == "Not an Issue"


# ------------------------------------------------------------------ actions


async def test_the_incident_object_carries_its_actions(fake: FakeSoar, raw_client):
    """Verified on 51.0.9.0.20848: incident, task and artifact objects carry ``actions`` (D3)."""
    inc = (await raw_client.get(f"{ORG}/incidents/42")).json()
    assert {a["name"] for a in inc["actions"]} >= {"Firewall — Block IP", "Send Analyst Digest"}
    # The org-level collection is the rule list (P2-01), not an incident's actions.
    assert "entities" in (await raw_client.get(f"{ORG}/actions")).json()


async def test_incident_actions_route_is_a_500_as_on_the_verified_appliance(
    fake: FakeSoar, raw_client
):
    r = await raw_client.get(f"{ORG}/incidents/42/actions")
    assert r.status_code == 500 and r.json()["message"] == "Internal Server Error"


async def test_there_is_no_invocation_route(fake: FakeSoar, raw_client):
    """The invocation contract is unverified on 51.0.9.0.20848 (D4); nothing is modelled."""
    r = await raw_client.post(f"{ORG}/incidents/42/action_invocations", json={"action_id": 48})
    assert r.status_code == 404 and r.json()["message"] == "fake_soar: no route"


# ------------------------------------------- P2-01 discovery reads (08 §25)
# The wrappers differ per collection, exactly as docs/soar-api-verified.md §2 records.


@pytest.mark.parametrize(
    "path",
    ["/functions", "/actions", "/scripts", "/workflows", "/message_destinations", "/phases"],
)
async def test_entities_collections(fake: FakeSoar, raw_client, path: str):
    body = (await raw_client.get(f"{ORG}{path}")).json()
    assert list(body) == ["entities"] and isinstance(body["entities"], list)


@pytest.mark.parametrize(
    "path",
    ["/groups", "/types/__function/fields", "/types/task/fields", "/types/artifact/fields"],
)
async def test_bare_list_collections(fake: FakeSoar, raw_client, path: str):
    body = (await raw_client.get(f"{ORG}{path}")).json()
    assert isinstance(body, list) and all(isinstance(row, dict) for row in body)


@pytest.mark.parametrize("path", ["/types", "/incident_types"])
async def test_name_keyed_map_collections(fake: FakeSoar, raw_client, path: str):
    body = (await raw_client.get(f"{ORG}{path}")).json()
    assert isinstance(body, dict) and "entities" not in body
    assert all(isinstance(row, dict) and "id" in row for row in body.values())


async def test_data_tables_are_types_with_type_id_8(fake: FakeSoar, raw_client):
    types = (await raw_client.get(f"{ORG}/types")).json()
    tables = {name for name, row in types.items() if row["type_id"] == 8}
    assert tables == {"table_1", "table_2"}
    assert all(types[name]["parent_types"] for name in tables)
    assert (await raw_client.get(f"{ORG}/datatables")).status_code == 404  # no such collection


async def test_function_inputs_are_view_items_joined_to_function_fields(fake: FakeSoar, raw_client):
    listing = (await raw_client.get(f"{ORG}/functions")).json()["entities"]
    assert all(row["view_items"] == [] for row in listing)  # the list row carries none
    single = (await raw_client.get(f"{ORG}/functions/{listing[0]['id']}")).json()
    uuids = {f["uuid"] for f in (await raw_client.get(f"{ORG}/types/__function/fields")).json()}
    assert single["view_items"] and {i["content"] for i in single["view_items"]} <= uuids
    assert (await raw_client.get(f"{ORG}/functions/999999")).status_code == 404


async def test_a_script_body_is_script_text_of_the_single_script_only(fake: FakeSoar, raw_client):
    """P2-02 (08 §26): the verified shapes of ``scripts.json`` and ``script.json``."""
    listing = (await raw_client.get(f"{ORG}/scripts")).json()["entities"]
    assert all("script_text" not in row for row in listing)  # the list row carries no body
    single = (await raw_client.get(f"{ORG}/scripts/{listing[0]['id']}")).json()
    assert isinstance(single["script_text"], str) and single["script_text"]
    assert set(single) - set(listing[0]) == {"script_text"}
    assert {k: single[k] for k in listing[0]} == listing[0]
    assert (await raw_client.get(f"{ORG}/scripts/999999")).status_code == 404


async def test_the_server_version_is_in_rest_const(fake: FakeSoar, raw_client):
    body = (await raw_client.get("/rest/const")).json()
    assert body["server_version"]["version"] == "51.0.9.0.20848"


async def test_playbooks_are_listed_by_a_criteria_only_paged_post(fake: FakeSoar, raw_client):
    body = {"filters": [], "start": 0, "length": 1}
    r = await raw_client.post(f"{ORG}/playbooks/query_paged", params=QP, json=body)
    page = r.json()
    assert r.status_code == 200 and set(page) == {"data", "recordsTotal", "recordsFiltered"}
    assert len(page["data"]) == 1 and page["recordsTotal"] == 2
    # Verified: no GET collection (500), and a GET treats the segment as a handle (404).
    assert (await raw_client.get(f"{ORG}/playbooks")).status_code == 500
    assert (await raw_client.get(f"{ORG}/playbooks/query_paged")).status_code == 404
    # The fake is stricter than the appliance: return_level and the exact body are required.
    assert (await raw_client.post(f"{ORG}/playbooks/query_paged", json=body)).status_code == 400
    for other in (
        {"filters": [{"conditions": []}], "start": 0, "length": 1},
        {"filters": [], "start": 0, "length": 1, "sorts": []},
        {"start": 0, "length": 1},
    ):
        r = await raw_client.post(f"{ORG}/playbooks/query_paged", params=QP, json=other)
        assert r.status_code == 400 and "criteria-only" in r.json()["message"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "path", ["/functions", "/scripts", "/scripts/400", "/types", "/groups", "/functions/200"]
)
async def test_the_discovery_collections_are_read_only(
    fake: FakeSoar, raw_client, method: str, path: str
):
    r = await raw_client.request(method, f"{ORG}{path}", json={})
    assert r.status_code == 405


# -------------------------------------------------------- still not modelled


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/incidents/42/table_data/x"),
        ("POST", "/configurations/exports"),
        ("GET", "/configurations/exports/history"),
        ("POST", "/configurations/imports"),
        ("GET", "/playbooks/1000"),
        ("GET", "/actions/300"),
        ("GET", "/workflows/1"),
        ("POST", "/playbooks/execution/query_paged"),
        ("GET", "/incidents/42/tasktree"),
    ],
)
async def test_unverified_privileged_and_unused_calls_have_no_route(
    fake: FakeSoar, raw_client, method: str, path: str
):
    """Nothing P2-01 does not use is modelled, the configuration export least of all."""
    r = await raw_client.request(method, f"{ORG}{path}", json={})
    assert r.status_code == 404 and r.json()["message"] == "fake_soar: no route"


# ------------------------------------------------------- harness self-test


async def test_fault_injection_transport_and_body(fake: FakeSoar, raw_client):
    fake.fault("GET", r"/incidents/42$", exc=httpx.ReadTimeout)
    with pytest.raises(httpx.ReadTimeout):
        await raw_client.get(f"{ORG}/incidents/42")
    fake.faults.clear()
    fake.fault("GET", r"/incidents/42$", status=200, raw_body=b"{not json")
    r = await raw_client.get(f"{ORG}/incidents/42")
    with pytest.raises(ValueError):
        r.json()
    fake.fault("GET", r"/incidents/42$", status=200, raw_body=b'{"pad": 1}', chunked=True)
    r = await raw_client.get(f"{ORG}/incidents/42")
    assert "content-length" not in r.headers and r.json() == {"pad": 1}
