"""P1-14: the approved tool surface (08 §3) behaves as documented and never returns raw DTOs."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from qradar_soar_mcp.client.incidents import SEARCH_METHODS as CLIENT_SEARCH_METHODS
from qradar_soar_mcp.security.approvals import load_private_key, sign_request
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, register_all, run_pipeline
from qradar_soar_mcp.tools.incidents import SEARCH_METHODS
from qradar_soar_mcp.tools.projection import (
    DESCRIPTION_LIMIT,
    INCIDENT_FIELDS,
    flatten_comments,
    summarise_incident,
    trim,
)
from tests.fake_soar import FakeSoar
from tests.tool_harness import audit_records, build_runtime, write_keys, write_policy

# The Phase-1 contract, verbatim from 08 §3.
APPROVED_TOOLS = {
    "soar_search_incidents": 0,
    "soar_get_incident": 0,
    "soar_list_artifacts": 0,
    "soar_list_tasks": 0,
    "soar_list_comments": 0,
    "soar_list_attachments": 0,
    "soar_list_users": 0,
    "soar_describe_incident_fields": 0,
    "soar_list_incident_actions": 0,
    "soar_check_approval": 0,
    "soar_get_incident_full": 0,
    "soar_find_similar_incidents": 0,
    "soar_add_comment": 1,
    "soar_add_artifact": 1,
    "soar_create_incident": 2,
    "soar_update_incident": 2,
    "soar_assign_incident": 2,
    "soar_close_incident": 2,
    "soar_update_task_status": 2,
    "soar_invoke_action": 3,
}

ALL_FLAGS = {
    "SOAR_ALLOW_COMMENTS": "true",
    "SOAR_ALLOW_ARTIFACTS": "true",
    "SOAR_ALLOW_INCIDENT_WRITES": "true",
    "SOAR_ALLOW_TASK_WRITES": "true",
    "SOAR_ALLOW_INCIDENT_CLOSE": "true",
}


@pytest.fixture
async def rt(fake: FakeSoar, tmp_path: Path):
    runtime = build_runtime(fake, tmp_path, **ALL_FLAGS)
    yield runtime
    await runtime.aclose()


async def call(rt: Runtime, tool: str, **args: Any) -> dict[str, Any]:
    return await run_pipeline(TOOL_REGISTRY[tool], rt, args)


async def ok(rt: Runtime, tool: str, **args: Any) -> Any:
    out = await call(rt, tool, **args)
    assert out["ok"] is True, out
    return out["data"]


# ---------------------------------------------------------------- surface


def test_registry_is_exactly_the_approved_surface():
    assert {n: int(s.tier) for n, s in TOOL_REGISTRY.items()} == APPROVED_TOOLS
    for spec in TOOL_REGISTRY.values():
        assert spec.description and spec.mutations <= 1


def test_search_methods_agree_with_the_client():
    assert SEARCH_METHODS == CLIENT_SEARCH_METHODS


async def test_tool_manifest_snapshot(tmp_path: Path, snapshot):
    """Names, tiers, capabilities, input schemas and annotations are the public contract."""
    rt = Runtime.build({"SOAR_AUDIT_LOG_PATH": str(tmp_path / "a.jsonl")})
    server = MCPServer("snapshot")
    register_all(server, rt)
    manifest = {}
    for tool in await server.list_tools():
        spec = TOOL_REGISTRY[tool.name]
        manifest[tool.name] = {
            "tier": int(spec.tier),
            "capability": spec.capability,
            "input_schema": tool.input_schema,
            "annotations": tool.annotations.model_dump(exclude_none=True)
            if tool.annotations
            else None,
        }
    assert manifest == snapshot


# ------------------------------------------------------------- projection


def test_projection_field_list_is_pinned(snapshot):
    assert list(INCIDENT_FIELDS) == snapshot


async def test_get_incident_is_projected(rt: Runtime, fake: FakeSoar, snapshot):
    data = await ok(rt, "soar_get_incident", incident_id=42)
    assert data == snapshot
    assert list(data) == list(INCIDENT_FIELDS)
    assert "properties" not in data and "custom_fields" not in data
    with_custom = await ok(
        rt, "soar_get_incident", incident_id=42, custom_fields=["threat_source", "nope"]
    )
    assert with_custom["custom_fields"] == {"threat_source": "unknown", "nope": None}
    assert "properties.threat_source" not in json.dumps(with_custom)


def test_trim_marks_the_cut():
    long = "x" * (DESCRIPTION_LIMIT + 10)
    out = trim(long, DESCRIPTION_LIMIT)
    assert out.startswith("x" * DESCRIPTION_LIMIT) and out.endswith("[truncated 10 chars]")
    assert trim({"format": "text", "content": "hi"}, 10) == "hi"
    assert trim(None, 5) is None and trim(7, 5) == 7
    inc = summarise_incident({"id": 1, "description": long, "properties": {"a": long}}, ["a"])
    assert "[truncated" in inc["description"] and "[truncated" in inc["custom_fields"]["a"]


def test_flatten_comments_keeps_threads():
    tree = [
        {
            "id": 1,
            "parent_id": None,
            "text": "a",
            "children": [{"id": 2, "parent_id": 1, "text": "b"}],
        },
        {"id": 3, "parent_id": None, "text": "c"},
    ]
    assert [(c["id"], c["parent_id"]) for c in flatten_comments(tree)] == [
        (1, None),
        (2, 1),
        (3, None),
    ]


# ------------------------------------------------------------------ reads


async def test_search_filters_sorts_and_caps(rt: Runtime, fake: FakeSoar):
    data = await ok(rt, "soar_search_incidents")
    assert data["count"] == 1 and data["incidents"][0]["id"] == 42
    assert list(data["incidents"][0]) == list(INCIDENT_FIELDS)
    data = await ok(
        rt,
        "soar_search_incidents",
        filters=[[{"field_name": "severity_code", "method": "equals", "value": "High"}]],
    )
    assert data["count"] == 0 and data["filtered"] == 0 and data["total"] == 1
    data = await ok(
        rt,
        "soar_search_incidents",
        filters=[
            [{"field_name": "plan_status", "method": "equals", "value": "A"}],
            [{"field_name": "properties.threat_source", "method": "has_a_value"}],
        ],
        sorts=[{"field_name": "create_date", "type": "desc"}],
        length=1000,
        custom_fields=["threat_source"],
    )
    assert data["count"] == 1 and data["incidents"][0]["custom_fields"] == {
        "threat_source": "unknown"
    }
    sent = fake.requests[-1]
    assert sent.params["return_level"] == "normal" and sent.json["length"] == 50  # SOAR_MAX_RESULTS
    assert "value" not in sent.json["filters"][1]["conditions"][0]
    out = await call(
        rt,
        "soar_search_incidents",
        filters=[[{"field_name": "name", "method": "like", "value": "x"}]],
    )
    assert out["ok"] is False and out["error"]["code"] == "internal"  # schema violation → generic
    out = await call(
        rt,
        "soar_search_incidents",
        filters=[[{"field_name": "name", "method": "equals", "value": "x", "extra": 1}]],
    )
    assert out["ok"] is False


async def test_collection_reads_are_projected(rt: Runtime):
    artifacts = await ok(rt, "soar_list_artifacts", incident_id=42)
    assert artifacts["count"] == 2
    assert artifacts["artifacts"][0] == {
        "id": 8001,
        "type": "IP Address",
        "value": "203.0.113.10",
        "description": "Source of the login",
        "created": 1758000180000,
        "hit_count": 0,
    }
    tasks = await ok(rt, "soar_list_tasks", incident_id=42)
    assert [(t["id"], t["status"], t["status_label"]) for t in tasks["tasks"]] == [
        (9001, "O", "open"),
        (9002, "C", "closed"),
    ]
    assert "inc_id" not in tasks["tasks"][0]
    comments = await ok(rt, "soar_list_comments", incident_id=42)
    assert [(c["id"], c["parent_id"]) for c in comments["comments"]] == [
        (7001, None),
        (7002, None),
        (7003, 7002),
    ]
    attachments = await ok(rt, "soar_list_attachments", incident_id=42)
    assert attachments["attachments"] == [
        {
            "id": 5001,
            "name": "signin-export.csv",
            "size": 20480,
            "content_type": "text/csv",
            "created": 1758000200000,
        }
    ]
    users = await ok(rt, "soar_list_users")
    assert [u["display_name"] for u in users["users"]] == ["Analyst One", "Analyst Two"]
    fields = await ok(rt, "soar_describe_incident_fields")
    by_name = {f["api_name"]: f for f in fields["fields"]}
    assert by_name["properties.root_cause"]["close_required"] is True
    assert by_name["severity_code"]["values"] == ["Low", "Medium", "High"]
    missing = await call(rt, "soar_list_tasks", incident_id=999)
    assert missing["error"]["code"] == "not_found"


# ----------------------------------------------------------------- writes


async def test_add_comment_and_artifact(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    data = await ok(rt, "soar_add_comment", incident_id=42, text="Reviewed by Claude.")
    assert data["comment_id"] and fake.mutating_requests[-1].json == {
        "text": {"format": "text", "content": "Reviewed by Claude."}
    }
    reply = await ok(rt, "soar_add_comment", incident_id=42, text="Ack", parent_id=7002)
    assert reply["comment_id"] != data["comment_id"]
    art = await ok(
        rt,
        "soar_add_artifact",
        incident_id=42,
        artifact_type="DNS Name",
        value="bad.example.com",
        description="from the digest",
    )
    assert art["artifact"]["type"] == "DNS Name" and art["artifact"]["value"] == "bad.example.com"
    bad = await call(rt, "soar_add_artifact", incident_id=42, artifact_type="DNS Name", value="  ")
    assert bad["error"]["code"] == "validation"
    events = [r["event"] for r in audit_records(tmp_path)]
    assert events == ["MUTATION_PENDING", "MUTATION_COMMITTED"] * 3 + [
        "MUTATION_PENDING",
        "MUTATION_FAILED",
    ]


async def test_create_incident(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    before = int(time.time() * 1000)
    data = await ok(
        rt,
        "soar_create_incident",
        name="Test from MCP",
        description="d",
        severity_code="Low",
        custom_fields={"threat_source": "test"},
    )
    assert data["id"] > 42 and data["name"] == "Test from MCP"
    assert data["custom_fields"] == {"threat_source": "test"}
    sent = fake.mutating_requests[-1].json
    assert sent["discovered_date"] >= before and sent["properties"] == {"threat_source": "test"}
    committed = audit_records(tmp_path)[-1]
    assert committed["event"] == "MUTATION_COMMITTED" and committed["target"] == {
        "incident_id": data["id"]
    }
    assert committed["post_image"]["name"] == "Test from MCP"


async def test_update_incident(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    data = await ok(rt, "soar_update_incident", incident_id=42, changes={"severity_code": "High"})
    assert data["changed"] == {"severity_code": {"from": "Medium", "to": "High"}}
    assert data["incident"]["severity_code"] == "High" and list(data["incident"]) == list(
        INCIDENT_FIELDS
    )
    patch = fake.mutating_requests[-1].json
    assert patch["version"] == 3 and patch["changes"][0]["old_value"] == {"object": "Medium"}
    # Closing fields are refused here without touching SOAR.
    n = len(fake.requests)
    out = await call(rt, "soar_update_incident", incident_id=42, changes={"plan_status": "C"})
    assert out["error"]["code"] == "validation" and "soar_close_incident" in out["error"]["message"]
    assert len(fake.requests) == n
    # A concurrent edit is reported, not overwritten.
    fake.fault(
        "PATCH",
        r"/incidents/42$",
        status=200,
        body={
            "success": False,
            "message": "stale",
            "field_failures": [{"field": "severity_code", "error": "changed"}],
        },
    )
    out = await call(rt, "soar_update_incident", incident_id=42, changes={"severity_code": "Low"})
    assert out["error"]["code"] == "patch_rejected" and out["error"]["fields"] == ["severity_code"]
    assert [r["event"] for r in audit_records(tmp_path)][-2:] == [
        "MUTATION_PENDING",
        "MUTATION_FAILED",
    ]


async def test_assign_and_close(rt: Runtime, fake: FakeSoar):
    data = await ok(rt, "soar_assign_incident", incident_id=42, owner="analyst.two")
    assert data["changed"] == {"owner_id": {"from": "analyst.one", "to": "analyst.two"}}
    out = await call(
        rt, "soar_close_incident", incident_id=42, resolution="Resolved", summary="Done"
    )
    assert out["error"]["code"] == "patch_rejected"  # root_cause is close-required and empty
    data = await ok(
        rt,
        "soar_close_incident",
        incident_id=42,
        resolution="Resolved",
        summary="Done",
        custom_fields={"root_cause": "credential stuffing"},
    )
    assert (
        data["incident"]["plan_status"] == "C" and data["incident"]["resolution_id"] == "Resolved"
    )
    assert set(data["changed"]) == {
        "plan_status",
        "resolution_id",
        "resolution_summary",
        "root_cause",
    }
    out = await call(rt, "soar_close_incident", incident_id=42, resolution="", summary="x")
    assert out["error"]["code"] == "validation"


async def test_update_task_status_is_refused_without_touching_soar(
    rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    """P1-CORR-01 D1: PUT /tasks/{id} is verified, its body is not, so nothing is sent."""
    outs = [
        await call(rt, "soar_update_task_status", incident_id=42, task_id=task_id, status=status)
        for task_id, status in ((9001, "closed"), (9002, "open"), (1, "closed"))
    ]
    assert outs[0]["ok"] is False and outs[0]["error"]["code"] == "DENY_UNSUPPORTED"
    assert "request body has not been verified" in outs[0]["error"]["message"]
    assert all(out["error"] == outs[0]["error"] for out in outs)  # same for every target
    assert fake.requests == []  # no GET, PUT or PATCH; not even a read
    assert fake.tasks[9001]["status"] == "O" and fake.tasks[9002]["status"] == "C"
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["DECISION_DENIED"] * 3  # never MUTATION_PENDING
    assert records[0]["decision"] == "DENY_UNSUPPORTED" and records[0]["tier"] == 2
    assert records[0]["tool"] == "soar_update_task_status"
    assert records[0]["target"] == {"incident_id": 42, "task_id": 9001}


# ---------------------------------------------------------------- actions


@pytest.fixture
async def rt_actions(fake: FakeSoar, tmp_path: Path):
    _, public = write_keys(tmp_path)
    runtime = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(write_policy(tmp_path)),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(public),
    )
    yield runtime
    await runtime.aclose()


async def test_list_incident_actions_annotates_policy(
    rt: Runtime, rt_actions: Runtime, fake: FakeSoar
):
    plain = await ok(rt, "soar_list_incident_actions", incident_id=42)
    assert plain["policy_loaded"] is False and plain["actions"][0]["policy"] is None
    data = await ok(rt_actions, "soar_list_incident_actions", incident_id=42)
    by_id = {a["id"]: a for a in data["actions"]}
    assert [a["id"] for a in data["actions"]] == [47, 48, 49, 50, 51, 52]
    for row in data["actions"]:
        assert set(row) == {"id", "name", "invocable", "policy"} and row["invocable"] is False
    assert by_id[47]["policy"]["tier"] == 3
    assert by_id[48]["policy"] == {
        "tier": 1,
        "decision": "allow",
        "destructive": False,
        "rule": "Send Analyst Digest",
    }
    assert by_id[50]["policy"]["rule"] == "default" and by_id[50]["policy"]["tier"] == 5
    # The object-carried list only (P1-CORR-01 D3).
    assert {(r.method, r.path) for r in fake.requests} == {("GET", "/rest/orgs/201/incidents/42")}


async def test_invoke_action_is_refused_before_approval_or_soar(
    rt_actions: Runtime, fake: FakeSoar, tmp_path: Path
):
    """P1-CORR-01 D4: the invocation contract is unverified, so every call is an ordinary
    audited denial: no request to SOAR, no approval requested or consumed, no PENDING."""
    rt = rt_actions
    outs = [
        await call(rt, "soar_invoke_action", incident_id=42, action_id=action_id)
        for action_id in (48, 49, 52, 999)
    ]
    assert outs[0]["error"]["code"] == "DENY_UNSUPPORTED"
    assert "not verified" in outs[0]["error"]["message"]
    assert all(out["ok"] is False and out["error"] == outs[0]["error"] for out in outs)
    assert all("approval_id" not in out and "plan" not in out for out in outs)
    assert fake.requests == []  # nothing reached SOAR, not even a read
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["DECISION_DENIED"] * 4
    assert {r["decision"] for r in records} == {"DENY_UNSUPPORTED"} and records[0]["tier"] == 3
    assert records[1]["target"] == {"incident_id": 42, "action_id": 49}
    assert rt.broker is not None
    assert not rt.broker.path.exists() or list(rt.broker.path.glob("*.request.json")) == []

    # An approval a human already granted is neither consumed nor looked at.
    args = {"incident_id": 42, "action_id": 49, "approval_id": None}
    request = rt.broker.request(
        tool="soar_invoke_action",
        tier=3,
        capability="SOAR_ALLOW_ACTIONS",
        args=args,
        target={"incident_id": 42, "action_id": 49},
        plan="Invoke manual action id 49 on incident 42",
        action={"id": 49, "name": None},
        transport="stdio",
        destructive=False,
        policy_rule=None,
    )
    signed = sign_request(
        request,
        private_key=load_private_key(tmp_path / "keys" / "approval.key"),
        approver="j.rossi",
        now=time.time(),
        ttl_seconds=300,
    )
    (rt.broker.path / f"{request.approval_id}.approved.json").write_text(
        json.dumps(signed), encoding="utf-8"
    )
    assert (await ok(rt, "soar_check_approval", approval_id=request.approval_id))[
        "state"
    ] == "approved"
    out = await call(rt, "soar_invoke_action", **{**args, "approval_id": request.approval_id})
    assert out["error"] == outs[0]["error"]
    assert (await ok(rt, "soar_check_approval", approval_id=request.approval_id))[
        "state"
    ] == "approved"
    assert (await ok(rt, "soar_check_approval", approval_id="nonsense"))["state"] == "invalid"
    events = [r["event"] for r in audit_records(tmp_path)]
    assert fake.requests == [] and set(events) == {"DECISION_DENIED"}  # nothing consumed


@pytest.mark.parametrize("mode", ["in_band", "disabled"])
async def test_invoke_is_refused_in_every_approval_mode(fake: FakeSoar, tmp_path: Path, mode):
    """Lab approval modes would otherwise hand out a token, or execute at once."""
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(write_policy(tmp_path)),
        SOAR_APPROVAL_MODE=mode,
        SOAR_LAB_MODE="true",
    )
    first = await call(rt, "soar_invoke_action", incident_id=42, action_id=48)
    second = await call(rt, "soar_invoke_action", incident_id=42, action_id=49, approval_id="t")
    assert first["error"]["code"] == "DENY_UNSUPPORTED" and second["error"] == first["error"]
    assert "approval_id" not in first and "disclaimer" not in first
    assert fake.requests == []
    assert [r["event"] for r in audit_records(tmp_path)] == ["DECISION_DENIED"] * 2
    await rt.aclose()


async def test_every_denial_is_one_audit_record(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    attempts = {
        "soar_add_comment": {"incident_id": 42, "text": "x"},
        "soar_update_incident": {"incident_id": 42, "changes": {"severity_code": "High"}},
        "soar_invoke_action": {"incident_id": 42, "action_id": 48},
    }
    for tool, args in attempts.items():
        out = await call(rt, tool, **args)
        assert out["error"]["code"] == "DENY_DISABLED"
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["DECISION_DENIED"] * 3
    assert [r["tool"] for r in records] == list(attempts)
    assert fake.mutating_requests == []
    await rt.aclose()
