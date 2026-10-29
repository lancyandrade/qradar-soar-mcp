"""P1-14: the tools the MCP server exposes cannot bypass the chokepoint (06 P1-14; 01 §4).

The permission matrix and the default-config spy (test_permission_matrix.py,
test_chokepoint.py) drive ``run_pipeline`` directly. These tests close the gap
between that and what a client can reach: every call here goes through
``build_server(rt).call_tool``, the same entry point stdio and HTTP use.

1. Every tool the server lists is bound to ``run_pipeline`` with its own spec,
   and the server reaches nothing else.
2. A mutating tool body runs exactly when the permission matrix says ALLOW, in
   every config state and on both transports; otherwise it never runs.
3. Under default config, nothing mutating reaches SOAR through the server.
4. With mutations enabled, an unwritable or missing audit log refuses every
   mutation before its body runs, and a forged approval is refused.
5. Static: tools reach the MCP server only through ``register_all``, and the
   mutating tools live only in incidents / investigation / actions.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.server.mcpserver import MCPServer

import qradar_soar_mcp
from qradar_soar_mcp.security.audit import AuditError
from qradar_soar_mcp.security.tiers import APPROVAL_REQUIRED_FROM, Tier
from qradar_soar_mcp.server import build_server
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, ToolResult, ToolSpec, register_all
from qradar_soar_mcp.tools import registry as registry_module
from tests.fake_soar import BASE_URL, FakeSoar
from tests.test_permission_matrix import CONFIG_STATES, EXPECTED, MINIMAL_ARGS, TRANSPORTS
from tests.test_permission_matrix import build_state as matrix_state
from tests.tool_harness import audit_records

pytestmark = pytest.mark.contract

PKG = Path(qradar_soar_mcp.__file__).parent
MUTATING = sorted(name for name, spec in TOOL_REGISTRY.items() if spec.mutating)
PHASE1_MUTATION_MODULES = {
    "qradar_soar_mcp.tools.incidents",
    "qradar_soar_mcp.tools.investigation",
    "qradar_soar_mcp.tools.actions",
}


def _payload(result: Any) -> dict[str, Any]:
    """The pipeline's response dict, as the MCP client receives it."""
    return json.loads(result.content[0].text)


def _soar_mutations(fake: FakeSoar) -> list[tuple[str, str]]:
    # POST incidents/query_paged is a read (05 §1).
    return [
        (r.method, r.path) for r in fake.mutating_requests if not r.path.endswith("/query_paged")
    ]


@pytest.fixture
def soar() -> Iterator[FakeSoar]:
    """Every outbound request is answered by the fake; an unmocked one fails the test."""
    fake = FakeSoar()
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=fake.handler)
        yield fake


def test_there_are_mutating_tools_to_guard():
    # A vacuous MUTATING list would make every test below pass trivially.
    assert MUTATING == [
        "soar_add_artifact",
        "soar_add_comment",
        "soar_assign_incident",
        "soar_close_incident",
        "soar_create_incident",
        "soar_invoke_action",
        "soar_update_incident",
        "soar_update_task_status",
    ]


# ------------------------------------------------------------ 1. binding


async def test_every_server_tool_runs_through_run_pipeline(
    tmp_path: Path, soar: FakeSoar, monkeypatch: pytest.MonkeyPatch
):
    """Replace the pipeline with a spy: each listed tool reaches it once, with its own spec,
    and with the pipeline gone nothing reaches SOAR at all."""
    seen: list[tuple[ToolSpec, dict[str, Any]]] = []

    async def spy(spec: ToolSpec, rt: Runtime, args: dict[str, Any]) -> dict[str, Any]:
        seen.append((spec, dict(args)))
        return {"ok": False, "request_id": "spy", "error": {"code": "SPY", "message": "spy"}}

    monkeypatch.setattr(registry_module, "run_pipeline", spy)
    rt, _ = matrix_state(tmp_path, "tier2", "stdio")  # writes enabled: no gate to hide behind
    server = build_server(rt)
    listed = {t.name: t for t in await server.list_tools()}
    assert set(listed) == set(TOOL_REGISTRY)

    for name in sorted(listed):
        assert _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))["error"] == {
            "code": "SPY",
            "message": "spy",
        }
    await rt.aclose()

    assert [spec.name for spec, _ in seen] == sorted(listed)
    for spec, args in seen:
        assert spec is TOOL_REGISTRY[spec.name], f"{spec.name} is bound to a copy of its spec"
        assert "rt" not in args, f"{spec.name}: the runtime leaked into the public arguments"
    assert soar.requests == [], [(r.method, r.path) for r in soar.requests]

    for name in MUTATING:
        hints = listed[name].annotations
        assert hints is not None and hints.read_only_hint is False, name
        assert hints.destructive_hint is (TOOL_REGISTRY[name].tier >= APPROVAL_REQUIRED_FROM), name


# --------------------------------------------- 2. bodies run only on ALLOW


def _tripwired(fired: list[str]) -> dict[str, ToolSpec]:
    """The real registry with every mutating body replaced by a recorder.

    ``functools.wraps`` keeps the public signature, so the server builds the same
    schema and the pipeline the same decision; only the effect is swapped."""
    reg: dict[str, ToolSpec] = {}
    for name, spec in TOOL_REGISTRY.items():
        if not spec.mutating:
            reg[name] = spec
            continue

        @functools.wraps(spec.func)
        async def tripwire(rt: Runtime, _name: str = name, **_: Any) -> ToolResult:
            fired.append(_name)
            return ToolResult(data={"tripwire": _name})

        reg[name] = dataclasses.replace(spec, func=tripwire)
    return reg


def _cases() -> Iterator[Any]:
    for state in CONFIG_STATES:
        for transport in TRANSPORTS:
            yield pytest.param(state, transport, id=f"{state}-{transport}")


@pytest.mark.parametrize(("state", "transport"), list(_cases()))
async def test_mutating_bodies_run_exactly_when_the_matrix_allows(
    state: str, transport: str, tmp_path: Path, soar: FakeSoar
):
    fired: list[str] = []
    rt, _ = matrix_state(tmp_path, state, transport)
    server: MCPServer[Any] = MCPServer("p1-14-tripwire")
    register_all(server, rt, _tripwired(fired))

    allowed: list[str] = []
    for name in MUTATING:
        expected = EXPECTED[name][state][transport]
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        if expected == "ALLOW":
            allowed.append(name)
            assert out["ok"] is True and out["data"] == {"tripwire": name}, out
        else:
            assert out["ok"] is False and out["error"]["code"] == expected, (name, out)
    await rt.aclose()

    assert fired == allowed, f"{state}/{transport}: bodies ran {fired}, matrix allows {allowed}"
    assert _soar_mutations(soar) == []


# ------------------------------------------------- 3. default config, real


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_default_config_sends_no_mutation_through_the_server(
    transport: str, tmp_path: Path, soar: FakeSoar
):
    """Every tool, real bodies, called the way a client calls it: SOAR sees no write,
    and each mutating tool's refusal is audited."""
    rt, _ = matrix_state(tmp_path, "default", transport)
    server = build_server(rt)
    for name in sorted(TOOL_REGISTRY):
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        if name in MUTATING:
            assert out["ok"] is False and out["error"]["code"] == "DENY_DISABLED", (name, out)
    await rt.aclose()

    assert _soar_mutations(soar) == []
    denied = [r["tool"] for r in audit_records(tmp_path) if r["event"] == "DECISION_DENIED"]
    assert sorted(denied) == MUTATING
    events = {r["event"] for r in audit_records(tmp_path)}
    assert not events & {"MUTATION_PENDING", "MUTATION_COMMITTED", "MUTATION_FAILED"}


# ------------------------------------------------ 4. fail closed, enabled

# Everything on except Tier >= 4; invoke still refuses as DENY_UNSUPPORTED (08 §21).
ALL_WRITES = "actions_destructive"


def _writes_runtime(tmp_path: Path) -> Runtime:
    rt, _ = matrix_state(tmp_path, "tier2", "stdio")
    return rt


async def test_unwritable_audit_refuses_every_mutation_through_the_server(
    tmp_path: Path, soar: FakeSoar, monkeypatch: pytest.MonkeyPatch
):
    rt = _writes_runtime(tmp_path)
    assert rt.audit is not None

    def broken(*_: Any, **__: Any) -> None:
        raise AuditError("read-only filesystem")

    monkeypatch.setattr(rt.audit, "append", broken)
    server = build_server(rt)
    for name in MUTATING:
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        expected = "DENY_AUDIT" if EXPECTED[name]["tier2"]["stdio"] == "ALLOW" else None
        assert out["ok"] is False, (name, out)
        if expected:
            assert out["error"]["code"] == expected, (name, out)
    await rt.aclose()
    assert _soar_mutations(soar) == []


async def test_missing_audit_log_refuses_every_mutation_through_the_server(
    tmp_path: Path, soar: FakeSoar
):
    rt = _writes_runtime(tmp_path)
    rt.audit = None  # what Runtime.build leaves when the log cannot open, audit not required
    server = build_server(rt)
    for name in MUTATING:
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        assert out["ok"] is False, (name, out)
        if EXPECTED[name]["tier2"]["stdio"] == "ALLOW":
            assert out["error"]["code"] == "DENY_AUDIT", (name, out)
    # Reads keep working: only mutations need the log.
    assert _payload(await server.call_tool("soar_get_incident", {"incident_id": 42}))["ok"] is True
    await rt.aclose()
    assert _soar_mutations(soar) == []


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_forged_approval_never_reaches_the_body(
    transport: str, tmp_path: Path, soar: FakeSoar
):
    """Every Tier >= 3 tool, every enabling flag on, a made-up approval id: refused,
    no approval consumed, body never run."""
    fired: list[str] = []
    rt, _ = matrix_state(tmp_path, ALL_WRITES, transport)
    server: MCPServer[Any] = MCPServer("p1-14-approval")
    register_all(server, rt, _tripwired(fired))
    approval_tools = [n for n in MUTATING if TOOL_REGISTRY[n].tier >= Tier.CONTROL]
    assert approval_tools, "no Tier >= 3 tool to test"
    for name in approval_tools:
        args = dict(MINIMAL_ARGS[name], approval_id="APR-2026-1029-forged")
        out = _payload(await server.call_tool(name, args))
        assert out["ok"] is False and out["error"]["code"].startswith("DENY_"), (name, out)
    await rt.aclose()

    assert fired == []
    assert not {r["event"] for r in audit_records(tmp_path)} & {
        "APPROVAL_CONSUMED",
        "MUTATION_PENDING",
    }
    assert _soar_mutations(soar) == []


# ------------------------------------------------------------- 5. static


def _calls_to(tree: ast.AST, attr: str) -> int:
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attr
    )


def _sources() -> Iterator[tuple[str, ast.AST]]:
    for path in sorted(PKG.rglob("*.py")):
        rel = path.relative_to(PKG).as_posix()
        yield rel, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_tools_reach_the_mcp_server_only_through_register_all():
    """No ``server.add_tool`` / ``@server.tool()`` outside the registry, and no second
    MCP server anywhere: a tool registered any other way would skip the pipeline."""
    offenders = []
    for rel, tree in _sources():
        for attr in ("add_tool", "tool"):
            count = _calls_to(tree, attr)
            allowed = 1 if (rel, attr) == ("tools/registry.py", "add_tool") else 0
            if count != allowed:
                offenders.append(f"{rel}: {count} call(s) to .{attr}()")
        constructs = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"MCPServer", "FastMCP"}
        )
        if constructs != (1 if rel == "server.py" else 0):
            offenders.append(f"{rel}: constructs {constructs} MCP server(s)")
    assert offenders == []

    server_tree = ast.parse((PKG / "server.py").read_text(encoding="utf-8"))
    called = {
        node.func.id
        for node in ast.walk(server_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "register_all" in called


def test_mutating_tools_live_in_the_phase1_tool_modules():
    """The organisation P1-14 asks for: writes in incidents / investigation / actions;
    every other tools module (discovery) is Tier 0 only."""
    for name, spec in TOOL_REGISTRY.items():
        module = spec.func.__module__
        if spec.mutating:
            assert module in PHASE1_MUTATION_MODULES, f"{name} is a write in {module}"
        else:
            assert spec.tier is Tier.READ and spec.capability is None, name
