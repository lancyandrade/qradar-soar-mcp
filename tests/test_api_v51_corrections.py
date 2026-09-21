"""P1-CORR-01 and P1-CORR-02: Phase 1 reconciled with the verified QRadar SOAR 51.0.9 API.

``docs/soar-api-verified.md`` §3 recorded four discrepancies (D1-D4); 08 §21 and
§24 record the corrections. These tests pin each one through the real pipeline:

* D1 - task status is changed with the verified ``PUT /tasks/{id}``, never the
  invalid ``PATCH``. P1-CORR-01 disabled the tool while the ``PUT`` body was
  unverified; P2-00b verified it and P1-CORR-02 implements exactly that contract
  (its own suite is ``test_task_status_update.py``). Here: the task write surface
  is that one call and nothing else, and no other tool touches a single task;
* D2 - no task version is required or invented anywhere;
* D3 - manual actions come from the list the incident object carries, and a
  malformed list fails closed without any other route being tried;
* D4 - invocation is still refused, with its tier, flag and approval contract
  intact: its contract is unverified.

The refusal is an ordinary ``enforce()`` denial (``DENY_UNSUPPORTED``): audited
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
from tests.conftest import SENTINEL
from tests.fake_soar import BASE_URL, FakeSoar
from tests.test_permission_matrix import MINIMAL_ARGS
from tests.tool_harness import audit_records, base_env, build_runtime, write_keys, write_policy

pytestmark = pytest.mark.contract

PKG = Path(qradar_soar_mcp.__file__).parent
ORG = "/rest/orgs/201"
TASK_TOOL = "soar_update_task_status"
UNSUPPORTED = {"soar_invoke_action": INVOCATION_UNVERIFIED}
# Calls no tool may make on this API profile; None = any method.
FORBIDDEN: tuple[tuple[str | None, re.Pattern[str]], ...] = (
    ("PATCH", re.compile(r"/tasks/\d+")),  # D1: the Phase-1 assumption, not on 51.0.9
    ("POST", re.compile(r"/tasks/\d+")),
    ("DELETE", re.compile(r".*")),
    (None, re.compile(r"/tasktree")),  # UI-internal and undocumented (08 §23)
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


# ------------------------------------ D1 enabled (P1-CORR-02); D4 kept, and refused


def test_the_catalog_keeps_both_tools_with_their_security_contract():
    assert len(TOOL_REGISTRY) == 21  # the 20 of Phase 1 and soar_refresh_catalog (P2-01)
    task, invoke = TOOL_REGISTRY[TASK_TOOL], TOOL_REGISTRY["soar_invoke_action"]
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
    variants: list[dict[str, Any]] = [
        {"incident_id": i, "action_id": a} for i, a in ((42, 47), (42, 49), (42, 999), (7, 1))
    ]
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
        ("kill_switch", "soar_update_task_status", "DENY_KILL_SWITCH"),
        ("kill_switch", "soar_invoke_action", "DENY_UNSUPPORTED"),
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


def _code_strings(tree: ast.AST) -> set[str]:
    """Every string constant outside docstrings."""
    scopes = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, scopes) and node.body and isinstance(node.body[0], ast.Expr)
    }
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        if id(node) not in docstrings
    }


def test_the_task_write_surface_is_exactly_the_verified_call():
    """D1/D2 after P1-CORR-02: one PUT, to one task, built from the GET and nothing else."""
    tasks_client = (PKG / "client" / "tasks.py").read_text(encoding="utf-8")
    tree = ast.parse(tasks_client)
    assert [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not n.name.startswith("_")
    ] == ["list", "get", "set_status"]
    attrs = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
    assert attrs.count("put") == 1  # a single write, never retried with another body
    assert not {"patch", "patch_object", "post", "request"} & set(attrs)
    assert [n.arg for n in ast.walk(tree) if isinstance(n, ast.keyword)].count("json_body") == 1
    # The body is a deep copy with one assignment; the client names no other task field
    # it could set: no version, no closed_date, no task_layout.
    assert "deepcopy" in attrs
    stores = [
        n.slice.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Subscript)
        and isinstance(n.ctx, ast.Store)
        and isinstance(n.slice, ast.Constant)
    ]
    assert stores == ["status"]
    assert not {"update", "pop", "popitem", "setdefault", "clear"} & set(attrs)
    assert not any(isinstance(n, ast.Delete) for n in ast.walk(tree))
    strings = _code_strings(tree)
    assert not {"vers", "version", "closed_date", "task_layout"} & strings
    assert not any("tasktree" in text for text in strings)
    # PUT is reachable from that one place: nothing else in the package calls or defines it.
    for path in sorted(PKG.rglob("*.py")):
        source = ast.parse(path.read_text(encoding="utf-8"))
        where = path.relative_to(PKG).as_posix()
        for node in ast.walk(source):
            if isinstance(node, ast.Attribute) and node.attr == "put":
                assert where == "client/tasks.py", f"{where}: .put"
            if isinstance(node, ast.Attribute) and node.attr == "set_status":
                assert where == "tools/investigation.py", f"{where}: .set_status"
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "put":
                assert where == "client/base.py", f"{where}: def put"
    # The tool reaches the client through that one method, inside its @soar_tool body.
    tool_source = ast.parse((PKG / "tools" / "investigation.py").read_text(encoding="utf-8"))
    body = next(
        n
        for n in ast.walk(tool_source)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == TASK_TOOL
    )
    awaited = [n for n in ast.walk(body) if isinstance(n, ast.Await)]
    assert len(awaited) == 1
    call = awaited[0].value
    assert isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
    assert call.func.attr == "set_status"


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
        by_tool: dict[str, list[tuple[str, str]]] = {}
        for name, spec in sorted(TOOL_REGISTRY.items()):
            seen = len(fake.requests)
            out = await run_pipeline(spec, rt, dict(MINIMAL_ARGS[name]))
            expected = "DENY_UNSUPPORTED" if name in UNSUPPORTED else None
            assert (out.get("error") or {}).get("code") == expected, (name, out)
            by_tool[name] = [(r.method, r.path.removeprefix(ORG)) for r in fake.requests[seen:]]
        await rt.aclose()
    assert _forbidden(fake) == []
    assert {r.method for r in fake.requests} <= {"GET", "POST", "PATCH", "PUT"}
    # A single task is touched by one tool only, with the verified sequence, and PUT goes
    # nowhere else.
    single_task = re.compile(r"/tasks/\d+$")
    assert by_tool.pop(TASK_TOOL) == [
        ("GET", "/tasks/9001"),
        ("PUT", "/tasks/9001"),
        ("GET", "/tasks/9001"),
    ]
    for name, calls in by_tool.items():
        assert not [c for c in calls if c[0] == "PUT" or single_task.search(c[1])], name
    assert by_tool["soar_invoke_action"] == []
    assert fake.tasks[9001]["status"] == "C" and fake.tasks[9002]["status"] == "C"
