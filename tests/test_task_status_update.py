"""P1-CORR-02: ``soar_update_task_status`` on the contract P2-00b verified (08 §24).

docs/soar-api-verified.md §3.1, QRadar SOAR 51.0.9.0.20848::

    GET /tasks/{task_id} -> deep copy -> change status only -> PUT /tasks/{task_id} -> GET

with the two format controls as headers and no query string. These tests pin, through
the real pipeline and against the offline fake: the request sequence and the exact
``PUT`` body (the whole ``GET`` object, no invented version, no client-made
``closed_date``), the verifying read, the refusals that send nothing, the failure
paths and their audit trail, and that the Tier-2 gates in front of the tool are the
ones every other Tier-2 tool has. Nothing here talks to an appliance.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from qradar_soar_mcp.client.base import TASK_FORMAT_HEADERS as CLIENT_FORMAT_HEADERS
from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.errors import SoarValidationError
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from qradar_soar_mcp.tools.projection import TASK_AUDIT_FIELDS
from tests.conftest import SENTINEL, connection_env
from tests.fake_soar import (
    BASE_URL,
    FIXTURES,
    TASK_CLOSED_AT,
    TASK_FORMAT_HEADERS,
    FakeSoar,
)
from tests.tool_harness import audit_records, base_env, build_runtime

pytestmark = pytest.mark.contract

TOOL = "soar_update_task_status"
ORG = "/rest/orgs/201"
CLOSE = {"incident_id": 42, "task_id": 9001, "status": "closed"}
REOPEN = {"incident_id": 42, "task_id": 9002, "status": "open"}
VERSION_LIKE = {"vers", "version", "ver", "lock", "etag", "token"}
RAW_ONLY_KEYS = ("perms", "creator_principal", "user_notes", "task_layout", "inc_owner_id")


@pytest.fixture
async def rt(fake: FakeSoar, tmp_path: Path):
    runtime = build_runtime(fake, tmp_path, SOAR_ALLOW_TASK_WRITES="true")
    assert runtime.usable, runtime.config_error
    yield runtime
    await runtime.aclose()


async def call(rt: Runtime, **args: Any) -> dict[str, Any]:
    return await run_pipeline(TOOL_REGISTRY[TOOL], rt, args)


def _calls(fake: FakeSoar) -> list[tuple[str, str]]:
    return [(r.method, r.path.removeprefix(ORG)) for r in fake.requests]


def _events(tmp_path: Path) -> list[str]:
    return [r["event"] for r in audit_records(tmp_path)]


def _status_ok() -> dict[str, Any]:
    return {"success": True, "title": None, "message": None, "hints": []}


# ------------------------------------------------------------------ the contract


def test_the_tool_keeps_its_security_contract():
    spec = TOOL_REGISTRY[TOOL]
    assert spec.tier is Tier.MODIFICATION and spec.capability == "SOAR_ALLOW_TASK_WRITES"
    assert spec.mutating and spec.mutations == 1 and spec.unsupported is None
    assert spec.classify is None and not spec.needs_approval_arg


def test_the_fake_and_the_client_agree_on_the_verified_request_form():
    assert (
        CLIENT_FORMAT_HEADERS
        == TASK_FORMAT_HEADERS
        == {
            "handle_format": "ids",
            "text_content_output_format": "objects_convert",
        }
    )
    # The fake's single-task object has the key set recorded from the appliance.
    shape = json.loads(
        (FIXTURES / "verified" / "p2_00b_designated_task_ui_formats.json").read_text("utf-8")
    )["shape"]
    for task in FakeSoar().task_objects.values():
        assert set(task) == set(shape) and len(task) == 41
        assert not VERSION_LIKE & set(task) and task["task_layout"] == []


async def test_closing_an_open_task(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    before = copy.deepcopy(fake.task_objects[9001])
    out = await call(rt, **CLOSE)
    assert out["ok"] is True, out
    data = out["data"]
    assert data["incident_id"] == 42 and data["task_id"] == 9001
    assert data["changed"] == {"status": {"from": "O", "to": "C"}}
    assert data["task"]["id"] == 9001 and data["task"]["status"] == "C"
    assert data["task"]["status_label"] == "closed"
    assert data["task"]["instructions"] == "Call the user on a known-good number."
    assert data["task"]["vers"] is None  # the projection's slot; tasks carry no version

    # GET -> PUT -> GET, all to /tasks/{task_id}, in the verified form.
    assert _calls(fake) == [("GET", "/tasks/9001"), ("PUT", "/tasks/9001"), ("GET", "/tasks/9001")]
    for rec in fake.requests:
        assert rec.params == {}, "the header form was verified without a query string"
        assert {k: rec.headers[k] for k in TASK_FORMAT_HEADERS} == TASK_FORMAT_HEADERS
    assert fake.requests[0].json is None and fake.requests[2].json is None

    # The PUT body is the whole GET object; status is the only difference.
    body = fake.requests[1].json
    assert body == {**before, "status": "C"}
    assert set(body) == set(before) and len(body) == 41
    assert {k for k in body if body[k] != before[k]} == {"status"}
    assert not VERSION_LIKE & set(body)
    assert body["closed_date"] is None  # the client does not stamp it...
    assert fake.task_objects[9001]["closed_date"] == TASK_CLOSED_AT  # ...the server did
    assert fake.tasks[9001]["status"] == "C"

    # Raw task data stays on the server; the audit images are the small fixed projection.
    rendered = json.dumps(out)
    assert not any(key in rendered for key in RAW_ONLY_KEYS)
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_COMMITTED"]
    assert {r["tool"] for r in records} == {TOOL} and {r["tier"] for r in records} == {2}
    assert {r["capability"] for r in records} == {"SOAR_ALLOW_TASK_WRITES"}
    assert records[0]["target"] == records[1]["target"] == {"incident_id": 42, "task_id": 9001}
    committed = records[1]
    assert set(committed["pre_image"]) == set(committed["post_image"]) == set(TASK_AUDIT_FIELDS)
    assert committed["pre_image"] == {
        "id": 9001,
        "inc_id": 42,
        "status": "O",
        "closed_date": None,
        "active": True,
        "frozen": False,
    }
    assert committed["post_image"] == {
        **committed["pre_image"],
        "status": "C",
        "closed_date": TASK_CLOSED_AT,
    }


async def test_reopening_a_closed_task(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    before = copy.deepcopy(fake.task_objects[9002])
    assert before["status"] == "C" and isinstance(before["closed_date"], int)
    out = await call(rt, **REOPEN)
    assert out["ok"] is True, out
    assert out["data"]["changed"] == {"status": {"from": "C", "to": "O"}}
    assert out["data"]["task"]["status_label"] == "open"
    assert _calls(fake) == [("GET", "/tasks/9002"), ("PUT", "/tasks/9002"), ("GET", "/tasks/9002")]
    body = fake.requests[1].json
    assert body == {**before, "status": "O"}
    assert body["closed_date"] == before["closed_date"]  # passed through, not cleared
    assert fake.task_objects[9002]["closed_date"] is None  # the server cleared it
    committed = audit_records(tmp_path)[-1]
    assert committed["event"] == "MUTATION_COMMITTED"
    assert committed["pre_image"]["closed_date"] == before["closed_date"]
    assert committed["post_image"]["status"] == "O"
    assert committed["post_image"]["closed_date"] is None


async def test_close_then_reopen_restores_the_task(rt: Runtime, fake: FakeSoar):
    baseline = copy.deepcopy(fake.task_objects[9001])
    assert (await call(rt, **CLOSE))["ok"] is True
    assert (await call(rt, **{**CLOSE, "status": "open"}))["ok"] is True
    assert fake.task_objects[9001] == baseline
    puts = [r for r in fake.requests if r.method == "PUT"]
    assert len(puts) == 2 and all(r.path == f"{ORG}/tasks/9001" for r in puts)
    # Each PUT is built from the read immediately before it, never from an older copy.
    assert puts[1].json["closed_date"] == TASK_CLOSED_AT


async def test_only_the_identified_task_changes(rt: Runtime, fake: FakeSoar):
    others = {k: copy.deepcopy(v) for k, v in fake.task_objects.items() if k != 9001}
    incident = copy.deepcopy(fake.incident)
    assert (await call(rt, **CLOSE))["ok"] is True
    assert {k: v for k, v in fake.task_objects.items() if k != 9001} == others
    assert fake.incident == incident
    assert len(fake.mutating_requests) == 1


async def test_the_fake_refuses_an_invented_body(fake: FakeSoar):
    """The offline model cannot be satisfied by a reduced DTO or a client-made closed_date."""
    stored = copy.deepcopy(fake.task_objects[9001])
    candidates: dict[str, Any] = {
        "status_only": {"id": 9001, "status": "C"},
        "client_closed_date": {**stored, "status": "C", "closed_date": 1758000000000},
        "invented_version": {**stored, "status": "C", "vers": 1},
        "normalised_layout": {**stored, "status": "C", "task_layout": None},
        "second_field": {**stored, "status": "C", "name": "renamed"},
        "dropped_key": {k: v for k, v in {**stored, "status": "C"}.items() if k != "user_notes"},
        "no_change": dict(stored),
        "unknown_status": {**stored, "status": "X"},
    }
    async with httpx.AsyncClient(
        base_url=BASE_URL, auth=("fake-key-id", SENTINEL), headers=TASK_FORMAT_HEADERS
    ) as raw:
        for name, body in candidates.items():
            r = await raw.put(f"{ORG}/tasks/9001", json=body)
            assert r.status_code == 400 and "fake_soar:" in r.json()["message"], name
        # The verified form with the query-string controls instead, or mixed in: not modelled.
        r = await raw.put(
            f"{ORG}/tasks/9001", json={**stored, "status": "C"}, params=TASK_FORMAT_HEADERS
        )
        assert r.status_code == 400
        assert fake.task_objects[9001] == stored
        ok = await raw.put(f"{ORG}/tasks/9001", json={**stored, "status": "C"})
        assert ok.status_code == 200 and ok.json() == _status_ok()
        assert (await raw.put(f"{ORG}/tasks/1", json={"status": "C"})).status_code == 404


# ------------------------------------------------------- refusals: nothing is written


async def test_a_missing_task_is_not_found(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    out = await call(rt, incident_id=42, task_id=1, status="closed")
    assert out["ok"] is False and out["error"]["code"] == "not_found"
    assert out["error"]["http_status"] == 404
    assert _calls(fake) == [("GET", "/tasks/1")] and fake.mutating_requests == []
    assert _events(tmp_path) == ["MUTATION_PENDING", "MUTATION_FAILED"]


async def test_a_task_of_another_incident_cannot_be_changed(
    rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    """9101 exists and belongs to incident 43: pairing it with incident 42 is refused."""
    before = copy.deepcopy(fake.task_objects[9101])
    out = await call(rt, incident_id=42, task_id=9101, status="closed")
    assert out["ok"] is False and out["error"]["code"] == "not_found"
    assert out["error"]["message"] == "Not found: task 9101 on incident 42"
    assert "http_status" not in out["error"]  # SOAR did not answer 404; this server refused
    assert "43" not in out["error"]["message"] and before["name"] not in json.dumps(out)
    assert fake.mutating_requests == [] and fake.task_objects[9101] == before
    # With its own incident id the same task is changed.
    assert (await call(rt, incident_id=43, task_id=9101, status="closed"))["ok"] is True
    assert _calls(fake)[0] == ("GET", "/tasks/9101") and len(fake.mutating_requests) == 1
    assert _events(tmp_path) == [
        "MUTATION_PENDING",
        "MUTATION_FAILED",
        "MUTATION_PENDING",
        "MUTATION_COMMITTED",
    ]


@pytest.mark.parametrize("status", ["C", "O", "done", "", "CLOSED", None, 1, ["closed"]])
async def test_an_invalid_status_sends_nothing(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, status: Any
):
    out = await call(rt, incident_id=42, task_id=9001, status=status)
    assert out["ok"] is False and out["error"]["code"] == "validation"
    assert fake.requests == []  # not even the read
    assert _events(tmp_path) == ["MUTATION_PENDING", "MUTATION_FAILED"]


async def test_the_mcp_schema_offers_only_open_and_closed(tmp_path: Path):
    from mcp.server.mcpserver import MCPServer

    from qradar_soar_mcp.tools import register_all

    server = MCPServer("schema")
    register_all(server, Runtime.build({"SOAR_AUDIT_LOG_PATH": str(tmp_path / "a.jsonl")}))
    tool = next(t for t in await server.list_tools() if t.name == TOOL)
    props = tool.input_schema["properties"]
    assert set(props) == {"incident_id", "task_id", "status"}  # no arbitrary task field
    assert props["status"]["enum"] == ["open", "closed"]
    assert set(tool.input_schema["required"]) == {"incident_id", "task_id", "status"}


async def test_an_extra_task_field_is_not_accepted(rt: Runtime, fake: FakeSoar):
    """Over MCP the schema above is the guard. Past it, the tool has no parameter to put
    such a field in: the call dies in the pipeline's crash path, before the client."""
    for extra in ({"name": "renamed"}, {"closed_date": 1}):
        out = await call(rt, **CLOSE, **extra)
        assert out["ok"] is False and out["error"]["code"] == "internal"
    assert fake.requests == [] and fake.task_objects[9001]["status"] == "O"


@pytest.mark.parametrize(
    ("task_id", "status", "patch", "code"),
    [
        (9001, "open", {}, "validation"),  # already open
        (9002, "closed", {}, "validation"),  # already closed
        (9001, "closed", {"active": False}, "validation"),
        (9001, "closed", {"frozen": True}, "validation"),
        (9001, "closed", {"active": None}, "validation"),
        (9001, "closed", {"frozen": None}, "validation"),
        (9001, "closed", {"status": "X"}, "malformed_response"),
        (9001, "closed", {"inc_id": None}, "malformed_response"),
        (9001, "closed", {"inc_id": "42"}, "malformed_response"),
        (9001, "closed", {"id": 9002}, "malformed_response"),
    ],
    ids=[
        "already_open",
        "already_closed",
        "inactive",
        "frozen",
        "active_unknown",
        "frozen_unknown",
        "unknown_status",
        "no_inc_id",
        "inc_id_not_an_id",
        "another_task_returned",
    ],
)
async def test_a_state_the_contract_was_not_verified_for_sends_no_put(
    rt: Runtime,
    fake: FakeSoar,
    tmp_path: Path,
    task_id: int,
    status: str,
    patch: dict[str, Any],
    code: str,
):
    fake.task_objects[task_id].update(patch)
    before = copy.deepcopy(fake.task_objects[task_id])
    out = await call(rt, incident_id=42, task_id=task_id, status=status)
    assert out["ok"] is False and out["error"]["code"] == code, out
    assert _calls(fake) == [("GET", f"/tasks/{task_id}")]
    assert fake.task_objects[task_id] == before
    assert _events(tmp_path) == ["MUTATION_PENDING", "MUTATION_FAILED"]


# ---------------------------------------------------------------- failure paths


@pytest.mark.parametrize(
    ("fault", "code"),
    [
        ({"status": 403, "body": {"message": f"no permission {SENTINEL}"}}, "forbidden"),
        ({"status": 409, "body": {"message": "Conflicting PUT operation"}}, "conflict"),
        ({"status": 400, "body": {"message": "bad task"}}, "validation"),
        ({"status": 500, "raw_body": f"<html>{SENTINEL}</html>".encode()}, "server_error"),
        ({"exc": httpx.ReadTimeout}, "timeout"),
        ({"exc": httpx.ConnectError}, "connection"),
        ({"status": 200, "body": {"success": False, "message": f"nope {SENTINEL}"}}, "validation"),
        ({"status": 200, "body": ["not", "a", "status"]}, "malformed_response"),
        ({"status": 200, "body": {"title": None}}, "malformed_response"),
        ({"status": 200, "raw_body": b'{"success": tru'}, "malformed_response"),
    ],
    ids=[
        "403",
        "409",
        "400",
        "500",
        "timeout",
        "refused",
        "success_false",
        "not_an_object",
        "no_success_flag",
        "not_json",
    ],
)
async def test_a_failed_put_is_a_failed_mutation(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, fault: dict[str, Any], code: str
):
    before = copy.deepcopy(fake.task_objects[9001])
    fake.fault("PUT", r"/tasks/9001$", **fault)
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == code, out
    assert set(out) == {"ok", "request_id", "error"}
    assert SENTINEL not in json.dumps(out)
    # One attempt: no retry, no alternate body, and no verifying read of a refused write.
    assert _calls(fake) == [("GET", "/tasks/9001"), ("PUT", "/tasks/9001")]
    assert fake.task_objects[9001] == before
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == code
    assert records[1].get("post_image") is None
    assert SENTINEL not in (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8")


async def test_an_unreflected_status_fails_the_mutation(
    rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    """SOAR says success but the task still reads open: reported and audited as failed."""
    fake.fault("PUT", r"/tasks/9001$", status=200, body=_status_ok())  # accepted, not applied
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == "unverified_write"
    assert "does not show status 'C'" in out["error"]["message"]
    assert "(O -> C)" in out["error"]["message"]  # the audit record says what was written
    assert "data" not in out and "http_status" not in out["error"]
    assert _calls(fake) == [("GET", "/tasks/9001"), ("PUT", "/tasks/9001"), ("GET", "/tasks/9001")]
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == "unverified_write"
    assert "(O -> C)" in records[1]["soar_response"]["message"]


@pytest.mark.parametrize(
    "fault",
    [
        {"status": 500, "body": {"message": f"boom {SENTINEL}"}},
        {"exc": httpx.ReadTimeout},
        {"status": 200, "body": []},
    ],
    ids=["500", "timeout", "not_a_task"],
)
async def test_an_unreadable_task_after_the_put_fails_the_mutation(
    tmp_path: Path, fault: dict[str, Any]
):
    """The write was accepted but cannot be verified: never reported as a success."""
    fake = FakeSoar()
    rt = Runtime.build(base_env(tmp_path, SOAR_ALLOW_TASK_WRITES="true"), transport="stdio")
    gets = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal gets
        if request.method == "GET":
            gets += 1
            if gets == 2:
                fake.fault("GET", r"/tasks/9001$", times=1, **fault)
        return fake.handler(request)

    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=handler)
        out = await call(rt, **CLOSE)
        await rt.aclose()
    assert out["ok"] is False and out["error"]["code"] == "unverified_write"
    assert "was accepted" in out["error"]["message"] and "unverified" in out["error"]["message"]
    assert "http_status" not in out["error"]  # the read's status is not the write's
    assert SENTINEL not in json.dumps(out)
    assert [r.method for r in fake.requests] == ["GET", "PUT", "GET"]
    assert fake.task_objects[9001]["status"] == "C"  # the write did happen; it is not retried
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert "(O -> C) was accepted" in records[1]["soar_response"]["message"]


# ------------------------------------------------------------------ the gates


async def test_pending_is_written_before_the_put_and_one_outcome_follows(tmp_path: Path):
    fake = FakeSoar()
    rt = Runtime.build(base_env(tmp_path, SOAR_ALLOW_TASK_WRITES="true"), transport="stdio")
    at_first_read: list[list[str]] = []
    at_put: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            at_put.append(_events(tmp_path))
        elif not at_first_read:
            at_first_read.append(_events(tmp_path))
        return fake.handler(request)

    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=handler)
        assert (await call(rt, **CLOSE))["ok"] is True
        assert (await call(rt, **CLOSE))["ok"] is False  # already closed now
        await rt.aclose()
    assert at_first_read == [["MUTATION_PENDING"]]  # before any SOAR traffic at all
    assert at_put == [["MUTATION_PENDING"]]
    assert _events(tmp_path) == [
        "MUTATION_PENDING",
        "MUTATION_COMMITTED",
        "MUTATION_PENDING",
        "MUTATION_FAILED",
    ]
    ids = [r["request_id"] for r in audit_records(tmp_path)]
    assert ids[0] == ids[1] != ids[2] == ids[3]


@pytest.mark.parametrize(
    ("setup", "code"),
    [
        ("flag_off", "DENY_DISABLED"),
        ("other_tier2_flags_only", "DENY_DISABLED"),
        ("kill_switch", "DENY_KILL_SWITCH"),
        ("bad_config", "DENY_CONFIG"),
    ],
)
async def test_a_denied_call_sends_nothing(fake: FakeSoar, tmp_path: Path, setup: str, code: str):
    flags = {"SOAR_ALLOW_TASK_WRITES": "true"}
    if setup == "flag_off":
        flags = {}
    elif setup == "other_tier2_flags_only":
        flags = {"SOAR_ALLOW_INCIDENT_WRITES": "true", "SOAR_ALLOW_INCIDENT_CLOSE": "true"}
    elif setup == "bad_config":
        flags |= {"SOAR_ALLOW_ACTIONS": "true", "SOAR_ACTION_POLICY_FILE": ""}
    rt = build_runtime(fake, tmp_path, **flags)
    if setup == "kill_switch":
        (tmp_path / "state" / "HALT").write_text("")
    before = copy.deepcopy(fake.task_objects)
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == code, out
    assert fake.requests == [] and fake.task_objects == before
    assert "MUTATION_PENDING" not in _events(tmp_path)
    await rt.aclose()


async def test_tier2_rate_limit_applies(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path, SOAR_ALLOW_TASK_WRITES="true", SOAR_MAX_TIER2_PER_HOUR="1")
    assert rt.usable, rt.config_error
    assert (await call(rt, **CLOSE))["ok"] is True
    n = len(fake.requests)
    out = await call(rt, **REOPEN)
    assert out["ok"] is False and out["error"]["code"] == "DENY_RATE_LIMIT"
    assert len(fake.requests) == n and fake.task_objects[9002]["status"] == "C"
    await rt.aclose()


async def test_tier2_runs_over_http_like_the_other_tier2_tools(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(
        fake,
        tmp_path,
        "streamable-http",
        SOAR_ALLOW_TASK_WRITES="true",
        SOAR_HTTP_AUTH_TOKEN="t" * 32,
    )
    assert rt.usable, rt.config_error
    assert (await call(rt, **CLOSE))["ok"] is True
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_COMMITTED"]
    assert {r["transport"] for r in records} == {"streamable-http"}
    await rt.aclose()


async def test_three_failures_trip_the_breaker(rt: Runtime, fake: FakeSoar, tmp_path: Path):
    fake.fault("PUT", r"/tasks/9001$", status=500, body={"message": "boom"})
    for _ in range(3):
        assert (await call(rt, **CLOSE))["error"]["code"] == "server_error"
    n = len(fake.requests)
    out = await call(rt, **CLOSE)
    assert out["error"]["code"] == "DENY_BREAKER" and len(fake.requests) == n
    assert "BREAKER_TRIPPED" in _events(tmp_path)


# ------------------------------------------------------------ the transport layer


async def test_put_is_transport_support_for_the_task_update_only(fake: FakeSoar):
    async with SoarClient(Settings.load(connection_env())) as client:
        for path in (
            f"{ORG}/incidents/42",
            f"{ORG}/tasks",
            f"{ORG}/tasks/9001/attachments",
            f"{ORG}/incidents/42/tasks/9001",
            "/rest/orgs/201x/tasks/9001",
            "/rest/session",
        ):
            with pytest.raises(SoarValidationError, match="tasks"):
                await client.request("PUT", path, json_body={}, format_headers=TASK_FORMAT_HEADERS)
        # The right path in any other form: the query-parameter form, a query beside the
        # headers, another org, a non-ASCII digit.
        task = f"{ORG}/tasks/9001"
        with pytest.raises(SoarValidationError, match="verified form"):
            await client.request("PUT", task, json_body={})
        with pytest.raises(SoarValidationError, match="verified form"):
            await client.request(
                "PUT", task, json_body={}, params={"x": "1"}, format_headers=TASK_FORMAT_HEADERS
            )
        for path in ("/rest/orgs/202/tasks/9001", f"{ORG}/tasks/\u0669"):
            with pytest.raises(SoarValidationError, match="verified form"):
                await client.request("PUT", path, json_body={}, format_headers=TASK_FORMAT_HEADERS)
        for headers in (
            {"handle_format": "ids"},
            {**TASK_FORMAT_HEADERS, "X-Other": "1"},
            {"Authorization": "x", "Host": "y"},
            {**TASK_FORMAT_HEADERS, "handle_format": "names"},
            {**TASK_FORMAT_HEADERS, "handle_format": 1},
        ):
            with pytest.raises(SoarValidationError, match="format controls"):
                await client.get(task, format_headers=headers)
        with pytest.raises(SoarValidationError, match="not part of the Phase-1 contract"):
            await client.request("DELETE", f"{ORG}/tasks/9001")
        assert fake.requests == []
