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
#
# Three outcomes of the one PUT, kept apart (08 §24):
#   not sent     - reliable local evidence that the request never left this process: the
#                  error is returned as it is, and nothing needs reading back;
#   rejected     - SOAR's own application-level refusal, HTTP 200 + StatusDTO with
#                  success: false: the error is returned, and nothing is read back;
#   ambiguous    - anything else once the PUT may have reached SOAR, EVERY HTTP error
#                  status included (no status is evidence that the task was left alone).
#                  The verifying GET is made exactly once and alone decides; the PUT is
#                  never sent again.
#   (accepted    - success: true, then the same verifying GET.)

GET_ONLY = [("GET", "/tasks/9001")]
GET_PUT = [("GET", "/tasks/9001"), ("PUT", "/tasks/9001")]
GET_PUT_GET = [*GET_PUT, ("GET", "/tasks/9001")]

# No connection was ever established, so no request was written to one.
NOT_SENT: dict[str, tuple[type[httpx.HTTPError], str]] = {
    "connect_refused": (httpx.ConnectError, "connection"),
    "connect_timeout": (httpx.ConnectTimeout, "timeout"),
    "pool_timeout": (httpx.PoolTimeout, "timeout"),
}

REJECTED: dict[str, dict[str, Any]] = {
    "message": {"success": False, "message": f"nope {SENTINEL}"},
    "status_dto": {
        "success": False,
        "title": None,
        "message": "Task cannot be closed",
        "hints": [],
        "error_code": "generic",
        "error_payload": None,
    },
    "bare": {"success": False},
}

# fault -> the reason the error names. Each leaves open whether SOAR processed the PUT.
AMBIGUOUS: dict[str, tuple[dict[str, Any], str]] = {
    # HTTP error statuses. The reference lists 400/401/403/404/409 (and 500/503) for this
    # call as boilerplate without meaning; 418, 422 and 429 are not listed at all. None is
    # evidence that the task was left alone, so none is allowed to skip the read-back.
    "400": ({"status": 400, "body": {"message": f"bad task {SENTINEL}"}}, "HTTP 400"),
    "401": ({"status": 401, "body": {"message": f"bad key {SENTINEL}"}}, "HTTP 401"),
    "403": ({"status": 403, "body": {"message": f"no permission {SENTINEL}"}}, "HTTP 403"),
    "404": ({"status": 404, "body": {"message": "gone"}}, "HTTP 404"),
    "409": ({"status": 409, "body": {"message": "Conflicting PUT operation"}}, "HTTP 409"),
    "418": ({"status": 418, "body": {"message": f"teapot {SENTINEL}"}}, "HTTP 418"),
    "422": ({"status": 422, "body": {"message": f"invalid {SENTINEL}"}}, "HTTP 422"),
    "429": ({"status": 429, "body": {"message": "slow down"}}, "HTTP 429"),
    "403_generic_error_object": (
        {
            "status": 403,
            "body": {
                "success": False,
                "title": None,
                "message": f"Forbidden {SENTINEL}",
                "hints": [],
                "error_code": "generic",
            },
        },
        "HTTP 403",
    ),
    "not_an_object": ({"status": 200, "body": ["not", "a", SENTINEL]}, "malformed_response"),
    "no_success_flag": ({"status": 200, "body": {"title": SENTINEL}}, "malformed_response"),
    "success_is_a_string": ({"status": 200, "body": {"success": "true"}}, "malformed_response"),
    "success_is_a_number": ({"status": 200, "body": {"success": 1}}, "malformed_response"),
    "success_is_null": ({"status": 200, "body": {"success": None}}, "malformed_response"),
    "empty_body": ({"status": 200}, "malformed_response"),
    "not_json": (
        {"status": 200, "raw_body": f'{{"success": tru {SENTINEL}'.encode()},
        "malformed_response",
    ),
    "oversized": (
        {"status": 200, "raw_body": b'{"pad": "' + SENTINEL.encode() * 20_000 + b'"}'},
        "response_too_large",
    ),
    "500": ({"status": 500, "raw_body": f"<html>{SENTINEL}</html>".encode()}, "HTTP 500"),
    "502": ({"status": 502, "body": {"message": f"bad gateway {SENTINEL}"}}, "HTTP 502"),
    "503": ({"status": 503, "body": {"message": "unavailable"}}, "HTTP 503"),
    "read_timeout": ({"exc": httpx.ReadTimeout}, "timeout"),
    "write_timeout": ({"exc": httpx.WriteTimeout}, "timeout"),
    "read_error": ({"exc": httpx.ReadError}, "connection"),
    "write_error": ({"exc": httpx.WriteError}, "connection"),
    "protocol_error": ({"exc": httpx.RemoteProtocolError}, "connection"),
}


def _no_leak(out: dict[str, Any], tmp_path: Path) -> None:
    assert SENTINEL not in json.dumps(out) and "Basic " not in json.dumps(out)
    assert SENTINEL not in (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8")


def _one_put(fake: FakeSoar) -> None:
    assert [r.method for r in fake.requests].count("PUT") == 1
    assert len(fake.mutating_requests) == 1


@pytest.mark.parametrize("name", sorted(NOT_SENT))
async def test_a_put_that_was_never_sent_fails_without_a_read_back(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, name: str
):
    """No connection, so no request: nothing reached SOAR and nothing needs verifying."""
    exc, code = NOT_SENT[name]
    before = copy.deepcopy(fake.task_objects[9001])
    fake.fault("PUT", r"/tasks/9001$", exc=exc)
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == code, out
    assert set(out) == {"ok", "request_id", "error"}
    assert _calls(fake) == GET_ONLY  # no PUT arrived, and no GET was spent on verifying
    assert fake.mutating_requests == [] and fake.task_objects[9001] == before
    assert "was sent" not in out["error"]["message"]
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == code
    _no_leak(out, tmp_path)


async def test_not_sent_is_the_only_failure_that_rules_the_write_out():
    """The classification itself: no HTTP status, 4xx included, skips the read-back."""
    from qradar_soar_mcp.client.tasks import _rules_out_the_write
    from qradar_soar_mcp.errors import from_httpx, from_status

    path = f"{ORG}/tasks/9001"
    for status in range(400, 600):
        assert _rules_out_the_write(from_status(status, "PUT", path)) is False, status
    sent_or_unknown = (
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.ReadError,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.DecodingError,
        httpx.TooManyRedirects,
        httpx.ProxyError,
        httpx.UnsupportedProtocol,
    )
    for exc in sent_or_unknown:
        assert _rules_out_the_write(from_httpx(exc("x"), "PUT", path)) is False, exc
    for exc in (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
        assert _rules_out_the_write(from_httpx(exc("x"), "PUT", path)) is True, exc


async def test_a_client_side_refusal_of_the_put_is_not_sent(fake: FakeSoar):
    from qradar_soar_mcp.client.tasks import _rules_out_the_write

    async with SoarClient(Settings.load(connection_env())) as client:
        with pytest.raises(SoarValidationError) as info:
            await client.request("PUT", f"{ORG}/tasks/9001", json_body={})
    assert _rules_out_the_write(info.value) is True and fake.requests == []


@pytest.mark.parametrize("name", sorted(REJECTED))
async def test_an_explicitly_rejected_put_is_a_failed_mutation_and_nothing_is_read_back(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, name: str
):
    """HTTP 200 + StatusDTO success: false is SOAR's own answer that it refused."""
    before = copy.deepcopy(fake.task_objects[9001])
    fake.fault("PUT", r"/tasks/9001$", status=200, body=REJECTED[name])
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == "validation", out
    assert out["error"]["message"].startswith("Task update rejected on PUT ")
    assert set(out) == {"ok", "request_id", "error"}
    # One attempt: no retry, no alternate body, and no claim that anything was written.
    assert _calls(fake) == GET_PUT
    _one_put(fake)
    assert "was sent" not in out["error"]["message"]
    assert fake.task_objects[9001] == before
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == "validation"
    assert records[1].get("post_image") is None
    _no_leak(out, tmp_path)


@pytest.mark.parametrize("status", [402, 405, 410, 412, 418, 423, 451, 499])
async def test_an_unclassified_4xx_never_means_the_task_is_unchanged(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, status: int
):
    """Regression (PR #6 review 2): lying between 400 and 499 proves nothing. Here SOAR
    applied the write and answered with a 4xx this project has no contract for: the
    read-back finds the change, and the call must not end as a bare client error."""
    fake.fault("PUT", r"/tasks/9001$", processed=True, status=status, body={"message": "no"})
    out = await call(rt, **CLOSE)
    assert out["ok"] is True, out
    assert _calls(fake) == GET_PUT_GET
    _one_put(fake)
    committed = audit_records(tmp_path)[-1]
    assert committed["event"] == "MUTATION_COMMITTED"
    assert committed["soar_response"] == {"put": f"unconfirmed (HTTP {status})"}
    # The same answer with the task left as it was: unverified, never "soar_error".
    fake.faults.clear()
    fake.fault("PUT", r"/tasks/9002$", status=status, body={"message": "no"})
    out = await call(rt, **REOPEN)
    assert out["ok"] is False and out["error"]["code"] == "unverified_write", out
    assert f"(HTTP {status})" in out["error"]["message"]
    assert [r.method for r in fake.requests[3:]] == ["GET", "PUT", "GET"]


async def test_an_accepted_put_that_is_not_reflected_fails_the_mutation(
    rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    """SOAR says success but the task still reads open: reported and audited as failed."""
    fake.fault("PUT", r"/tasks/9001$", status=200, body=_status_ok())  # accepted, not applied
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == "unverified_write"
    assert "does not show status 'C'" in out["error"]["message"]
    assert "(O -> C) was accepted" in out["error"]["message"]
    assert "data" not in out and "http_status" not in out["error"]
    assert _calls(fake) == GET_PUT_GET
    _one_put(fake)
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == "unverified_write"
    assert "(O -> C)" in records[1]["soar_response"]["message"]


@pytest.mark.parametrize("name", sorted(AMBIGUOUS))
async def test_an_ambiguous_put_that_took_effect_is_verified_by_the_read_back(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, name: str
):
    """The answer establishes nothing, the write happened: one GET settles it as a success."""
    fault, reason = AMBIGUOUS[name]
    before = copy.deepcopy(fake.task_objects[9001])
    fake.fault("PUT", r"/tasks/9001$", processed=True, **fault)
    rt.require_client().max_response_bytes = 100_000
    out = await call(rt, **CLOSE)
    assert out["ok"] is True, out
    assert out["data"]["changed"] == {"status": {"from": "O", "to": "C"}}
    assert out["data"]["task"]["status"] == "C"
    assert _calls(fake) == GET_PUT_GET
    _one_put(fake)
    assert fake.requests[1].json == {**before, "status": "C"}
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_COMMITTED"]
    # The audit record says the change was established by the read-back, not by SOAR's answer.
    assert records[1]["soar_response"] == {"put": f"unconfirmed ({reason})"}
    assert records[1]["post_image"]["status"] == "C"
    assert records[1]["post_image"]["closed_date"] == TASK_CLOSED_AT
    _no_leak(out, tmp_path)


@pytest.mark.parametrize("name", sorted(AMBIGUOUS))
async def test_an_ambiguous_put_that_is_not_reflected_is_an_unverified_write(
    rt: Runtime, fake: FakeSoar, tmp_path: Path, name: str
):
    """The answer establishes nothing and the task still reads open: never "unchanged",
    never the bare transport or parsing error, and never a second PUT."""
    fault, reason = AMBIGUOUS[name]
    before = copy.deepcopy(fake.task_objects[9001])
    fake.fault("PUT", r"/tasks/9001$", **fault)
    rt.require_client().max_response_bytes = 100_000
    out = await call(rt, **CLOSE)
    assert out["ok"] is False and out["error"]["code"] == "unverified_write", out
    message = out["error"]["message"]
    assert "(O -> C) was sent" in message and f"({reason})" in message
    assert "does not show status 'C'" in message and "unverified" in message
    # Never a success, never "unchanged", and a 409 is quoted as a status, not as a conflict.
    assert "accepted" not in message and "conflict" not in message.lower()
    assert "unchanged" not in message
    assert set(out) == {"ok", "request_id", "error"} and "http_status" not in out["error"]
    assert _calls(fake) == GET_PUT_GET
    _one_put(fake)
    assert fake.task_objects[9001] == before
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == "unverified_write"
    assert records[1].get("post_image") is None
    _no_leak(out, tmp_path)


def _fail_the_second_get(fake: FakeSoar, fault: dict[str, Any]):
    gets = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal gets
        if request.method == "GET":
            gets += 1
            if gets == 2:
                fake.fault("GET", r"/tasks/9001$", times=1, **fault)
        return fake.handler(request)

    return handler


READ_BACK_FAULTS: dict[str, dict[str, Any]] = {
    "500": {"status": 500, "body": {"message": f"boom {SENTINEL}"}},
    "timeout": {"exc": httpx.ReadTimeout},
    "not_a_task": {"status": 200, "body": []},
    "another_task": {"status": 200, "body": {"id": 9002, "status": "C"}},
    "not_json": {"status": 200, "raw_body": f"<html>{SENTINEL}".encode()},
}


@pytest.mark.parametrize("read_back", sorted(READ_BACK_FAULTS))
@pytest.mark.parametrize("put", ["accepted", "no_success_flag", "not_json", "read_timeout", "500"])
async def test_an_unreadable_task_after_the_put_is_an_unverified_write(
    tmp_path: Path, put: str, read_back: str
):
    """The write went through (explicitly, or behind an unusable answer) but cannot be
    read back: never reported as a success, never retried."""
    fake = FakeSoar()
    rt = Runtime.build(base_env(tmp_path, SOAR_ALLOW_TASK_WRITES="true"), transport="stdio")
    if put != "accepted":
        fake.fault("PUT", r"/tasks/9001$", processed=True, **AMBIGUOUS[put][0])
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=_fail_the_second_get(fake, READ_BACK_FAULTS[read_back]))
        out = await call(rt, **CLOSE)
        await rt.aclose()
    assert out["ok"] is False and out["error"]["code"] == "unverified_write", out
    message = out["error"]["message"]
    assert "could not be read back" in message and "unverified" in message
    assert ("(O -> C) was accepted" in message) is (put == "accepted")
    assert ("(O -> C) was sent" in message) is (put != "accepted")
    assert "http_status" not in out["error"]  # the read's status is not the write's
    assert [r.method for r in fake.requests] == ["GET", "PUT", "GET"]
    _one_put(fake)
    assert fake.task_objects[9001]["status"] == "C"  # the write did happen; it is not retried
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    assert records[1]["soar_response"]["code"] == "unverified_write"
    _no_leak(out, tmp_path)


async def test_the_unconfirmed_answer_is_kept_for_the_log_only(fake: FakeSoar):
    """``detail`` carries the scrubbed answer for the redacting logger; MCP output does not."""
    from qradar_soar_mcp.errors import SoarUnverifiedWriteError

    fake.fault("PUT", r"/tasks/9001$", status=200, body={"title": f"odd {SENTINEL}", "x": 1})
    async with SoarClient(Settings.load(connection_env())) as client:
        with pytest.raises(SoarUnverifiedWriteError) as info:
            await client.tasks.set_status(42, 9001, "closed")
    err = info.value
    assert err.__cause__ is None and err.__context__ is None
    assert err.detail and '"x": 1' in err.detail and SENTINEL not in err.detail
    assert "odd" not in json.dumps(err.to_dict()) and "[REDACTED]" in err.detail
    assert err.status is None and err.not_sent is False


async def test_the_audit_record_of_a_confirmed_put_says_so(
    rt: Runtime, fake: FakeSoar, tmp_path: Path
):
    assert (await call(rt, **CLOSE))["ok"] is True
    assert audit_records(tmp_path)[-1]["soar_response"] == {"put": "success"}


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
        # A 5xx does not rule the write out: read back, found unchanged, still a failure.
        assert (await call(rt, **CLOSE))["error"]["code"] == "unverified_write"
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
            with pytest.raises(SoarValidationError, match="format controls") as info:
                await client.get(task, format_headers=headers)
            assert info.value.not_sent is True
        with pytest.raises(SoarValidationError, match="not part of the Phase-1 contract"):
            await client.request("DELETE", f"{ORG}/tasks/9001")
        assert fake.requests == []


@pytest.mark.parametrize(
    ("method", "path", "params"),
    [
        ("GET", f"{ORG}/incidents/42", None),
        ("GET", f"{ORG}/users", None),
        ("GET", f"{ORG}/incidents/42/tasks", None),
        ("GET", f"{ORG}/incidents/42/tasktree", None),
        ("GET", f"{ORG}/types/incident/fields", None),
        ("GET", f"{ORG}/tasks", None),
        ("GET", f"{ORG}/tasks/9001/attachments", None),
        ("GET", "/rest/orgs/202/tasks/9001", None),
        ("GET", "/rest/session", None),
        ("GET", f"{ORG}/tasks/9001", {"return_level": "normal"}),
        ("GET", f"{ORG}/tasks/9001", {"handle_format": "names"}),
        ("POST", f"{ORG}/tasks/9001", None),
        ("PATCH", f"{ORG}/tasks/9001", None),
        ("POST", f"{ORG}/incidents/query_paged", {"return_level": "normal"}),
        ("POST", f"{ORG}/incidents/42/comments", None),
        ("PATCH", f"{ORG}/incidents/42", None),
    ],
)
async def test_the_task_representation_cannot_leave_the_single_task_calls(
    fake: FakeSoar, method: str, path: str, params: dict[str, str] | None
):
    """The ids / objects_convert header form is verified for GET and PUT /tasks/{id} and
    nowhere else: asking for it anywhere else is refused before any I/O."""
    async with SoarClient(Settings.load(connection_env())) as client:
        with pytest.raises(SoarValidationError, match="GET and PUT /tasks/") as info:
            await client.request(
                method,
                path,
                params=params,
                json_body=None if method == "GET" else {},
                format_headers=TASK_FORMAT_HEADERS,
            )
        assert info.value.not_sent is True and fake.requests == []
        # The same calls in the ordinary Phase-1 form are untouched by this restriction.
        if method == "GET" and path in (f"{ORG}/incidents/42", f"{ORG}/users"):
            await client.get(path)
            rec = fake.requests[-1]
            assert rec.params == {
                "handle_format": "names",
                "text_content_output_format": "always_text",
            }
            assert "handle_format" not in rec.headers


async def test_the_two_single_task_calls_still_take_the_task_representation(fake: FakeSoar):
    async with SoarClient(Settings.load(connection_env())) as client:
        task = await client.get(f"{ORG}/tasks/9001", format_headers=TASK_FORMAT_HEADERS)
        assert len(task) == 41 and fake.requests[-1].params == {}
        answer = await client.put(
            f"{ORG}/tasks/9001",
            json_body={**task, "status": "C"},
            format_headers=TASK_FORMAT_HEADERS,
        )
        assert answer == _status_ok() and fake.requests[-1].params == {}
