"""P1-CORR-01: Phase 1 reconciled with the verified QRadar SOAR 51.0.9 API.

``docs/soar-api-verified.md`` §3 recorded four discrepancies (D1-D4); 08 §21
records the correction. These tests pin each one through the real pipeline:

* D1 - the method/path is corrected from the invalid ``PATCH`` to the verified
  ``PUT /tasks/{id}``, but its request body is unverified, so task mutation is
  disabled: ``soar_update_task_status`` stays registered and is refused, and no
  GET, PUT or PATCH is ever sent to a task;
* D2 - no task version is required or invented anywhere;
* D3 - manual actions come from the list the incident object carries, and a
  malformed list fails closed without any other route being tried;
* D4 - invocation is refused the same way, with its tier, flag and approval
  contract intact.

Both refusals are ordinary ``enforce()`` denials (``DENY_UNSUPPORTED``): audited
as ``DECISION_DENIED``, never ``MUTATION_PENDING``, no approval requested or
consumed, nothing sent to SOAR.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import pytest
import respx

import qradar_soar_mcp
from qradar_soar_mcp.errors import SoarUnsupportedError
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from qradar_soar_mcp.tools.actions import INVOCATION_UNVERIFIED
from qradar_soar_mcp.tools.investigation import TASK_UPDATE_UNVERIFIED
from tests.conftest import SENTINEL
from tests.fake_soar import BASE_URL, FakeSoar
from tests.test_permission_matrix import MINIMAL_ARGS
from tests.tool_harness import audit_records, base_env, build_runtime, write_keys, write_policy

pytestmark = pytest.mark.contract

PKG = Path(qradar_soar_mcp.__file__).parent
ORG = "/rest/orgs/201"
TASK_ARGS = {"incident_id": 42, "task_id": 9001, "status": "closed"}
UNSUPPORTED = {
    "soar_update_task_status": TASK_UPDATE_UNVERIFIED,
    "soar_invoke_action": INVOCATION_UNVERIFIED,
}
# Calls no tool may make on this API profile; None = any method.
FORBIDDEN: tuple[tuple[str | None, re.Pattern[str]], ...] = (
    (None, re.compile(r"/tasks/\d+")),  # no GET, PUT or PATCH to a single task (D1)
    ("GET", re.compile(r"/incidents/\d+/actions$")),  # D3
    (None, re.compile(r"/action_invocations")),  # D4
)
ALL_ON = {
    "SOAR_ALLOW_COMMENTS": "true",
    "SOAR_ALLOW_ARTIFACTS": "true",
    "SOAR_ALLOW_INCIDENT_WRITES": "true",
    "SOAR_ALLOW_TASK_WRITES": "true",
    "SOAR_ALLOW_INCIDENT_CLOSE": "true",
    "SOAR_ALLOW_ACTIONS": "true",
    "SOAR_ALLOW_DESTRUCTIVE_ACTIONS": "true",
    "SOAR_APPROVAL_MODE": "disabled",  # lab only: Tier 3 would execute at once
    "SOAR_LAB_MODE": "true",
}


def _calls(fake: FakeSoar) -> list[tuple[str, str]]:
    return [(r.method, r.path.removeprefix(ORG)) for r in fake.requests]


def _forbidden(fake: FakeSoar) -> list[tuple[str, str]]:
    return [
        (r.method, r.path)
        for r in fake.requests
        for method, pattern in FORBIDDEN
        if (method is None or r.method == method) and pattern.search(r.path)
    ]


# --------------------------------------------------- D1 / D4: kept, and refused


def test_the_catalog_keeps_both_tools_with_their_security_contract():
    assert len(TOOL_REGISTRY) == 20
    task, invoke = (TOOL_REGISTRY[name] for name in UNSUPPORTED)
    assert task.tier is Tier.MODIFICATION and task.capability == "SOAR_ALLOW_TASK_WRITES"
    assert invoke.tier is Tier.CONTROL and invoke.capability == "SOAR_ALLOW_ACTIONS"
    assert invoke.needs_approval_arg and invoke.describe is not None
    assert task.mutating and invoke.mutating and task.mutations == invoke.mutations == 1
    assert {n: s.unsupported for n, s in TOOL_REGISTRY.items() if s.unsupported} == UNSUPPORTED


@pytest.mark.parametrize("tool", sorted(UNSUPPORTED))
async def test_refusal_is_a_deterministic_audited_denial(fake: FakeSoar, tmp_path: Path, tool: str):
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_TASK_WRITES="true",
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(write_policy(tmp_path)),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(write_keys(tmp_path)[1]),
    )
    assert rt.usable, rt.config_error
    spec = TOOL_REGISTRY[tool]
    variants: list[dict[str, Any]] = (
        [TASK_ARGS, {**TASK_ARGS, "status": "open"}, {**TASK_ARGS, "task_id": 1, "incident_id": 7}]
        if tool == "soar_update_task_status"
        else [
            {"incident_id": i, "action_id": a} for i, a in ((42, 47), (42, 49), (42, 999), (7, 1))
        ]
    )
    outs = [await run_pipeline(spec, rt, dict(args)) for args in variants]
    assert all(out["ok"] is False for out in outs)
    assert {json.dumps(out["error"], sort_keys=True) for out in outs} == {
        json.dumps({"code": "DENY_UNSUPPORTED", "message": UNSUPPORTED[tool]}, sort_keys=True)
    }
    assert all(set(out) == {"ok", "request_id", "error"} for out in outs)  # no approval, no plan
    assert fake.requests == []  # zero traffic: no GET, PUT, PATCH or POST
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["DECISION_DENIED"] * len(variants)
    assert {r["decision"] for r in records} == {"DENY_UNSUPPORTED"}
    assert {r["tool"] for r in records} == {tool} and records[0]["tier"] == int(spec.tier)
    assert rt.broker is not None
    assert not rt.broker.path.exists() or list(rt.broker.path.iterdir()) == []
    await rt.aclose()


@pytest.mark.parametrize(
    ("setup", "tool", "code"),
    [
        ("flag_off", "soar_update_task_status", "DENY_DISABLED"),
        ("flag_off", "soar_invoke_action", "DENY_DISABLED"),
        ("http", "soar_invoke_action", "DENY_TRANSPORT"),
        ("http", "soar_update_task_status", "DENY_UNSUPPORTED"),
        ("kill_switch", "soar_update_task_status", "DENY_UNSUPPORTED"),
    ],
)
async def test_the_earlier_gates_still_come_first(
    fake: FakeSoar, tmp_path: Path, setup: str, tool: str, code: str
):
    flags: dict[str, str] = {}
    if setup != "flag_off":
        flags = {
            "SOAR_ALLOW_TASK_WRITES": "true",
            "SOAR_ALLOW_ACTIONS": "true",
            "SOAR_ACTION_POLICY_FILE": str(write_policy(tmp_path)),
        }
    transport = "stdio"
    if setup == "http":
        transport, flags["SOAR_HTTP_AUTH_TOKEN"] = "streamable-http", "t" * 32
    rt = build_runtime(fake, tmp_path, transport, **flags)
    assert rt.usable, rt.config_error
    if setup == "kill_switch":
        (tmp_path / "state" / "HALT").write_text("")
    out = await run_pipeline(TOOL_REGISTRY[tool], rt, dict(MINIMAL_ARGS[tool]))
    assert out["ok"] is False and out["error"]["code"] == code
    assert fake.requests == []
    assert [r["event"] for r in audit_records(tmp_path)] == ["DECISION_DENIED"]
    await rt.aclose()


@pytest.mark.parametrize("tool", sorted(UNSUPPORTED))
async def test_the_tool_body_refuses_too_if_ever_reached(fake: FakeSoar, tmp_path: Path, tool: str):
    """Defence in depth: even a pipeline that skipped enforce() could not reach SOAR."""
    rt = build_runtime(fake, tmp_path)
    with pytest.raises(SoarUnsupportedError) as info:
        await TOOL_REGISTRY[tool].func(rt, **dict(MINIMAL_ARGS[tool]))
    err = info.value
    assert err.safe_message == UNSUPPORTED[tool] == str(err) and err.status is None
    # The log-only detail never reaches the MCP-facing shape.
    assert err.detail and err.detail not in json.dumps(err.to_dict())
    assert err.to_dict() == {"code": "unsupported", "message": UNSUPPORTED[tool]}
    assert fake.requests == []
    await rt.aclose()


def test_no_task_mutation_payload_exists_in_production_code():
    """D1/D2: nothing in src/ builds, names or sends a task change of any shape."""
    tasks_client = (PKG / "client" / "tasks.py").read_text(encoding="utf-8")
    tree = ast.parse(tasks_client)
    assert [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not n.name.startswith("_")
    ] == ["list"]
    for node in ast.walk(tree):  # outside docstrings, no verb but GET and no payload
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"put", "patch", "patch_object", "post", "request"}, node.attr
        if isinstance(node, ast.keyword):
            assert node.arg != "json_body"
    for path in sorted(PKG.rglob("*.py")):
        source = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(source):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"set_status", "put"}, f"{path.name}: .{node.attr}"
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.name not in {"set_status", "put"}, f"{path.name}: def {node.name}"
    # The task tool's body is a refusal and nothing else: it never asks for the client.
    tool_source = ast.parse((PKG / "tools" / "investigation.py").read_text(encoding="utf-8"))
    body = next(
        n
        for n in ast.walk(tool_source)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "soar_update_task_status"
    )
    statements = [s for s in body.body if not isinstance(s, ast.Expr)]  # drop the docstring
    assert len(statements) == 1 and isinstance(statements[0], ast.Raise)


# ------------------------------------------------------------- D3 discovery


async def test_action_discovery_reads_only_the_incident_object(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    spec = TOOL_REGISTRY["soar_list_incident_actions"]
    out = await run_pipeline(spec, rt, {"incident_id": 42})
    assert out["ok"] is True and out["data"]["count"] == 6
    assert _calls(fake) == [("GET", "/incidents/42")]
    await rt.aclose()


@pytest.mark.parametrize(
    "actions",
    ["missing", None, [{"id": 48}], [{"id": 48, "name": f"x {SENTINEL}"}, "not an object"]],
    ids=["missing", "null", "no_name", "bad_element"],
)
async def test_action_discovery_fails_closed_on_malformed_metadata(
    fake: FakeSoar, tmp_path: Path, actions: Any
):
    rt = build_runtime(fake, tmp_path)
    if actions == "missing":
        fake.incident.pop("actions")
    else:
        fake.incident["actions"] = actions
    spec = TOOL_REGISTRY["soar_list_incident_actions"]
    first = await run_pipeline(spec, rt, {"incident_id": 42})
    second = await run_pipeline(spec, rt, {"incident_id": 42})
    assert first["ok"] is False and first["error"]["code"] == "malformed_response"
    assert first["error"] == second["error"]  # deterministic, and echoes no content
    assert SENTINEL not in json.dumps(first)
    assert _calls(fake) == [("GET", "/incidents/42")] * 2  # no guessed route is tried
    await rt.aclose()


# ---------------------------------------------------------- the whole surface


async def test_no_tool_reaches_a_forbidden_call_even_with_everything_enabled(tmp_path: Path):
    env = base_env(tmp_path, SOAR_ACTION_POLICY_FILE=str(write_policy(tmp_path)), **ALL_ON)
    rt = Runtime.build(env, transport="stdio")
    assert rt.usable, rt.config_error
    fake = FakeSoar()
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=fake.handler)
        for name, spec in sorted(TOOL_REGISTRY.items()):
            out = await run_pipeline(spec, rt, dict(MINIMAL_ARGS[name]))
            expected = "DENY_UNSUPPORTED" if name in UNSUPPORTED else None
            assert (out.get("error") or {}).get("code") == expected, (name, out)
        await rt.aclose()
    assert _forbidden(fake) == []
    assert {r.method for r in fake.requests} <= {"GET", "POST", "PATCH"}  # never PUT
    assert not any("/tasks/" in r.path for r in fake.requests)
    assert fake.tasks[9001]["status"] == "O"
