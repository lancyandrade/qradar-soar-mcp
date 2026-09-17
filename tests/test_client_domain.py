"""P1-04: the domain clients satisfy the P1-01 contract through SoarClient."""

from __future__ import annotations

import pytest

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.client.org import FieldDef, resolve_field
from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.errors import (
    SoarMalformedResponseError,
    SoarNotFoundError,
    SoarPatchRejectedError,
    SoarValidationError,
)
from tests.conftest import connection_env
from tests.fake_soar import FakeSoar

pytestmark = pytest.mark.contract


@pytest.fixture
async def client(fake: FakeSoar):
    async with SoarClient(Settings.load(connection_env(SOAR_MAX_RESULTS="7"))) as c:
        yield c


# ---------------------------------------------------------------- incidents


async def test_get_and_missing(client: SoarClient):
    inc = await client.incidents.get(42)
    assert inc["vers"] == 3 and inc["properties"]["threat_source"] == "unknown"
    with pytest.raises(SoarNotFoundError):
        await client.incidents.get(999)


async def test_search_sends_return_level_and_groups(client: SoarClient, fake: FakeSoar):
    out = await client.incidents.search(
        filters=[
            [
                {"field_name": "plan_status", "method": "equals", "value": "A"},
                {"field_name": "severity_code", "method": "equals", "value": "Medium"},
            ],
            [{"field_name": "id", "method": "equals", "value": 999}],
        ],
        sorts=[{"field_name": "id", "type": "desc"}],
        start=0,
        length=500,
    )
    rec = fake.requests[-1]
    assert rec.params["return_level"] == "normal"
    assert rec.json["filters"] == [
        {
            "conditions": [
                {"field_name": "plan_status", "method": "equals", "value": "A"},
                {"field_name": "severity_code", "method": "equals", "value": "Medium"},
            ]
        },
        {"conditions": [{"field_name": "id", "method": "equals", "value": 999}]},
    ]
    assert rec.json["length"] == 7  # capped by SOAR_MAX_RESULTS
    assert out["length"] == 7 and [i["id"] for i in out["items"]] == [42]


async def test_search_defaults_and_validation(client: SoarClient, fake: FakeSoar):
    out = await client.incidents.search()
    assert fake.requests[-1].json == {"filters": [], "sorts": [], "start": 0, "length": 7}
    assert out["total"] == 1
    with pytest.raises(SoarValidationError):
        await client.incidents.search(
            filters=[[{"field_name": "x", "method": "regex", "value": 1}]]
        )
    with pytest.raises(SoarValidationError):
        await client.incidents.search(filters=[[{"method": "equals", "value": 1}]])
    with pytest.raises(SoarValidationError):
        await client.incidents.search(sorts=[{"field_name": "id", "type": "sideways"}])
    fake.fault("POST", r"/query_paged$", status=200, body={"data": "nope"})
    with pytest.raises(SoarMalformedResponseError):
        await client.incidents.search()


async def test_create(client: SoarClient, fake: FakeSoar):
    inc = await client.incidents.create(
        name="Phish",
        discovered_date_ms=5,
        description="d",
        incident_type_ids=["Phishing"],
        severity_code="High",
        owner_id="analyst.one",
        properties={"threat_source": "email"},
    )
    assert inc["id"] > 10000
    assert fake.requests[-1].json == {
        "name": "Phish",
        "discovered_date": 5,
        "description": {"format": "text", "content": "d"},
        "incident_type_ids": ["Phishing"],
        "severity_code": "High",
        "owner_id": "analyst.one",
        "properties": {"threat_source": "email"},
    }
    with pytest.raises(SoarValidationError):
        await client.incidents.create(name="  ", discovered_date_ms=1)
    fake.fault("POST", r"/incidents$", status=200, body={"no": "id"})
    with pytest.raises(SoarMalformedResponseError):
        await client.incidents.create(name="n", discovered_date_ms=1)


async def test_apply_patch_get_build_patch_and_images(client: SoarClient, fake: FakeSoar):
    out = await client.incidents.apply_patch(
        42, {"severity_code": "High", "properties.triage_summary": "Benign."}
    )
    assert [r.method for r in fake.requests] == [
        "GET",
        "GET",
        "PATCH",
        "GET",
    ]  # fields, incident, patch, post-image
    assert out.version_before == 3
    assert out.pre_image["severity_code"] == "Medium" and out.post_image["severity_code"] == "High"
    assert (
        out.post_image["vers"] == 4 and out.post_image["properties"]["triage_summary"] == "Benign."
    )
    assert out.changes == {"severity_code": ("Medium", "High"), "triage_summary": (None, "Benign.")}
    change_names = [c["field"]["name"] for c in fake.requests[2].json["changes"]]
    assert change_names == ["severity_code", "triage_summary"]  # bare names, even for custom fields


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"nonexistent": 1}, "unknown incident field"),
        ({"properties.severity_code": "High"}, "unknown incident field"),
        ({"create_date": 0}, "read-only"),
        ({"severity_code": "Critical"}, "Low"),
        ({"incident_type_ids": ["Phishing", "Bogus"]}, "Bogus"),
        ({"threat_source": "a", "properties.threat_source": "b"}, "given twice"),
        ({}, "no changes"),
    ],
)
async def test_apply_patch_validates_before_sending(
    client: SoarClient, fake: FakeSoar, changes, match
):
    with pytest.raises(SoarValidationError, match=match):
        await client.incidents.apply_patch(42, changes)
    assert fake.mutating_requests == []


async def test_apply_patch_regression_is_caught(client: SoarClient, fake: FakeSoar, monkeypatch):
    """P1-01 AC: a deliberately introduced regression in apply_patch fails a test."""
    import qradar_soar_mcp.client.base as base

    original = base.SoarClient.patch_object

    async def broken(self, path, current, changes, **kw):
        # Regression: drop old_value (turns optimistic concurrency into a blind write).
        stripped = dict(current)
        stripped.pop("severity_code", None)
        return await original(self, path, stripped, changes, **kw)

    monkeypatch.setattr(base.SoarClient, "patch_object", broken)
    with pytest.raises(SoarPatchRejectedError):
        await client.incidents.apply_patch(42, {"severity_code": "High"})
    assert fake.incident["severity_code"] == "Medium"


async def test_stale_version_between_get_and_patch_is_rejected(client: SoarClient, fake: FakeSoar):
    fake.fault(
        "PATCH",
        r"/incidents/42$",
        status=200,
        body={
            "success": False,
            "message": "Incident has been modified by another user",
            "field_failures": [],
        },
    )
    with pytest.raises(SoarPatchRejectedError, match="modified by another user"):
        await client.incidents.apply_patch(42, {"description": "x"})
    assert fake.incident["description"] != "x"


async def test_assign(client: SoarClient, fake: FakeSoar):
    out = await client.incidents.assign(42, "analyst.two")
    assert out.changes == {"owner_id": ("analyst.one", "analyst.two")}
    with pytest.raises(SoarValidationError):
        await client.incidents.assign(42, " ")


async def test_close_requires_all_three_together_and_surfaces_close_required_fields(
    client: SoarClient, fake: FakeSoar
):
    with pytest.raises(SoarValidationError, match=r"05 §1\.1"):
        await client.incidents.close(42, resolution="Resolved", summary=" ")
    with pytest.raises(SoarValidationError, match="do not pass"):
        await client.incidents.close(
            42, resolution="Resolved", summary="s", extra_fields={"plan_status": "C"}
        )
    assert fake.mutating_requests == []
    with pytest.raises(SoarPatchRejectedError) as info:
        await client.incidents.close(42, resolution="Resolved", summary="done")
    assert info.value.to_dict()["fields"] == ["properties.root_cause"]
    assert fake.incident["plan_status"] == "A"
    out = await client.incidents.close(
        42,
        resolution="Resolved",
        summary="done",
        extra_fields={"properties.root_cause": "credential reuse"},
    )
    sent = fake.requests[-2].json["changes"]
    assert {c["field"]["name"] for c in sent} == {
        "plan_status",
        "resolution_id",
        "resolution_summary",
        "root_cause",
    }
    assert out.post_image["plan_status"] == "C" and out.post_image["end_date"] is not None


# -------------------------------------------------------------------- tasks


async def test_tasks_list_and_set_status_uses_patch(client: SoarClient, fake: FakeSoar):
    tasks = await client.tasks.list(42)
    assert {t["id"] for t in tasks} == {9001, 9002}
    out = await client.tasks.set_status(42, 9001, "closed")
    methods = [(r.method, r.path.rsplit("/", 2)[-2:]) for r in fake.requests[-2:]]
    assert methods[0][0] == "GET" and methods[1] == ("PATCH", ["tasks", "9001"])
    assert fake.requests[-1].json == {
        "version": 2,
        "changes": [
            {
                "field": {"name": "status"},
                "old_value": {"object": "O"},
                "new_value": {"object": "C"},
            }
        ],
    }
    assert out.changes == {"status": ("O", "C")} and out.post_image["status"] == "C"
    assert fake.tasks[9001]["status"] == "C"
    noop = await client.tasks.set_status(42, 9002, "C")
    assert noop.changes == {}
    assert fake.requests[-1].method == "GET"


async def test_tasks_errors(client: SoarClient, fake: FakeSoar):
    with pytest.raises(SoarValidationError):
        await client.tasks.set_status(42, 9001, "done")
    with pytest.raises(SoarNotFoundError):
        await client.tasks.set_status(42, 1, "closed")
    fake.tasks[9001].pop("vers")
    with pytest.raises(SoarValidationError, match="no integer 'vers'"):
        await client.tasks.set_status(42, 9001, "closed")
    fake.fault("GET", r"/tasks$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.tasks.list(42)


# ------------------------------------------------------ comments / artifacts


async def test_comments(client: SoarClient, fake: FakeSoar):
    assert (await client.comments.list(42))[1]["children"][0]["id"] == 7003
    created = await client.comments.add(42, "hi", parent_id=7002)
    assert fake.requests[-1].json == {
        "text": {"format": "text", "content": "hi"},
        "parent_id": 7002,
    }
    assert created["text"] == "hi"
    for bad in ("", "  ", "x" * 20_001):
        with pytest.raises(SoarValidationError):
            await client.comments.add(42, bad)
    fake.fault("GET", r"/comments$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.comments.list(42)
    fake.fault("POST", r"/comments$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.comments.add(42, "x")


async def test_artifacts(client: SoarClient, fake: FakeSoar):
    assert (await client.artifacts.list(42))[0]["type"] == "IP Address"
    created = await client.artifacts.add(42, "DNS Name", "bad.example.com", description="seen")
    assert fake.requests[-1].json == {
        "type": "DNS Name",
        "value": "bad.example.com",
        "description": {"format": "text", "content": "seen"},
    }
    assert created["value"] == "bad.example.com"
    for type_name, value in (("", "v"), ("IP Address", ""), ("IP Address", "x" * 4001)):
        with pytest.raises(SoarValidationError):
            await client.artifacts.add(42, type_name, value)
    fake.fault("POST", r"/artifacts$", status=200, body=[])
    with pytest.raises(SoarMalformedResponseError):
        await client.artifacts.add(42, "URL", "u")
    fake.fault("GET", r"/artifacts$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.artifacts.list(42)


# ------------------------------------------------------------- attachments


async def test_attachments_metadata_only(client: SoarClient, fake: FakeSoar):
    atts = await client.attachments.list(42)
    assert atts == [
        {
            "id": 5001,
            "name": "signin-export.csv",
            "size": 20480,
            "content_type": "text/csv",
            "created": 1758000200000,
        }
    ]
    fake.fault("GET", r"/attachments$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.attachments.list(42)


# --------------------------------------------------------------------- org


async def test_incident_fields_and_users(client: SoarClient, fake: FakeSoar):
    fields = await client.org.incident_fields()
    by_api = {f.api_name: f for f in fields}
    assert (
        by_api["properties.root_cause"].close_required
        and by_api["properties.root_cause"].to_dict()["custom"]
    )
    assert by_api["severity_code"].labels == ("Low", "Medium", "High")
    assert by_api["create_date"].read_only
    assert resolve_field(fields, "threat_source").api_name == "properties.threat_source"
    assert resolve_field(fields, "properties.severity_code") is None
    users = await client.org.users()
    assert users[0] == {
        "id": 7,
        "display_name": "Analyst One",
        "email": "analyst.one@soar.example.internal",
        "status": "A",
    }
    fake.fault("GET", r"/users$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.org.users()
    fake.fault("GET", r"/fields$", status=200, body="x")
    with pytest.raises(SoarMalformedResponseError):
        await client.org.incident_fields()


def test_field_def_tolerates_gaps():
    f = FieldDef.from_dto(
        {
            "name": "x",
            "values": [{"value": 1}, {"value": 2, "label": "Two", "enabled": False}, "junk"],
        }
    )
    assert f.text == "x" and f.input_type == "unknown" and f.values == () and not f.close_required
    assert "values" not in f.to_dict()


async def test_users_display_name_fallback(client: SoarClient, fake: FakeSoar):
    fake.users.append(
        {"id": 9, "fname": "Only", "lname": "Name", "email": "x@soar.example.internal"}
    )
    assert (await client.org.users())[-1]["display_name"] == "Only Name"


# ----------------------------------------------------------------- actions


async def test_actions_incident_scoped_list_and_exact_invoke_body(
    client: SoarClient, fake: FakeSoar
):
    actions = await client.actions.list_for_incident(42)
    assert {a["name"] for a in actions} >= {"Firewall — Block IP", "Send Analyst Digest"}
    assert all(set(a) == {"id", "name", "object_type", "enabled"} for a in actions)
    out = await client.actions.invoke(42, 48)
    assert out == {"incident_id": 42, "action_id": 48, "invoked": True}
    assert fake.requests[-1].json == {"action_id": 48}
    assert fake.action_invocations == [{"incident_id": 42, "action_id": 48}]
    with pytest.raises(SoarNotFoundError):
        await client.actions.invoke(42, 999)
    with pytest.raises(SoarValidationError):
        await client.actions.invoke(42, 0)
    fake.fault("GET", r"/actions$", status=200, body={})
    with pytest.raises(SoarMalformedResponseError):
        await client.actions.list_for_incident(42)
