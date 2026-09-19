"""P1-01 (08 §2.1): the documented Phase-1 REST semantics, in executable form.

These tests drive the fake with a bare httpx client. They are the contract the
project's client (P1-04) must satisfy; they do not depend on it.

Source of truth: docs/design/05-SOAR-API-SURFACE.md §1 and §1.1, except for tasks
and manual actions, where docs/soar-api-verified.md (QRadar SOAR 51.0.9.0.20848)
wins (P1-CORR-01; 08 §21).
"""

from __future__ import annotations

import base64

import httpx
import pytest

from tests.fake_soar import API_KEY_ID, BASE_URL, REQUIRED_PARAMS, FakeSoar

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


@pytest.mark.parametrize(
    ("method", "body"),
    [
        ("PATCH", _patch(2, status=("O", "C"))),  # the Phase-1 assumption (D1)
        ("PUT", {"id": 9001, "status": "C"}),  # documented on 51.0.9; body unverified
    ],
    ids=["patch", "put"],
)
async def test_no_task_mutation_is_modelled(fake: FakeSoar, raw_client, method: str, body: dict):
    """PATCH is not documented and the PUT body is not verified, so the contract has
    neither: task status changes are disabled until P2-00b verifies the body (08 §21)."""
    r = await raw_client.request(method, f"{ORG}/tasks/9001", json=body)
    assert r.status_code == 404 and r.json()["message"] == "fake_soar: no route"
    assert fake.tasks[9001]["status"] == "O"


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
    assert (await raw_client.get(f"{ORG}/actions")).status_code == 404  # org-level is Phase 2


async def test_incident_actions_route_is_a_500_as_on_the_verified_appliance(
    fake: FakeSoar, raw_client
):
    r = await raw_client.get(f"{ORG}/incidents/42/actions")
    assert r.status_code == 500 and r.json()["message"] == "Internal Server Error"


async def test_there_is_no_invocation_route(fake: FakeSoar, raw_client):
    """The invocation contract is unverified on 51.0.9.0.20848 (D4); nothing is modelled."""
    r = await raw_client.post(f"{ORG}/incidents/42/action_invocations", json={"action_id": 48})
    assert r.status_code == 404 and r.json()["message"] == "fake_soar: no route"


# -------------------------------------------------------- phase-2 boundary


@pytest.mark.parametrize(
    "path",
    ["/types", "/functions", "/incidents/42/table_data/x", "/rest/const", "/playbooks", "/scripts"],
)
async def test_phase_two_endpoints_have_no_route(fake: FakeSoar, raw_client, path: str):
    full = path if path.startswith("/rest/") else f"{ORG}{path}"
    assert (await raw_client.get(full)).status_code == 404


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
