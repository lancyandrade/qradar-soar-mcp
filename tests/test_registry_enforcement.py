"""P1-14: the tools the MCP server exposes cannot bypass the chokepoint (06 P1-14; 01 §4).

Every call here goes through ``build_server(rt).call_tool`` (or ``register_all`` on a
fresh server), the entry point stdio and HTTP use, never ``run_pipeline`` directly.

The expected authorisation is **not** taken from test_permission_matrix.py. It is
written below from the design documents (``DOC_*`` and :func:`doc_allows`), over
config states chosen here, mostly one flag at a time, so a flag wired to the wrong
tool or tier fails on its own. The two suites agree only if the implementation
and the documents agree.

1. Binding: every listed tool reaches ``run_pipeline`` with its own spec.
2. Authorisation: each mutating body runs exactly when the documents allow it.
3. Default config: nothing mutating reaches SOAR.
4. Audit: a failure before the mutation refuses it; a failure after a mutation
   SOAR applied still reports it as applied, never retries it, and does not
   reset the hourly budget on restart.
5. Approvals: a genuine approval runs its call once; it is bound to the tool and
   its arguments, single-use, time-limited and signature-checked.
6. Static: tools reach the server only through ``register_all``; writes live only
   in incidents / investigation / actions.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
import json
import logging
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.server.mcpserver import MCPServer

import qradar_soar_mcp
from qradar_soar_mcp.security.approvals import generate_keypair, load_private_key, sign_request
from qradar_soar_mcp.security.audit import AuditError
from qradar_soar_mcp.security.tiers import APPROVAL_REQUIRED_FROM, Tier
from qradar_soar_mcp.server import build_server
from qradar_soar_mcp.tools import (
    TOOL_REGISTRY,
    Runtime,
    ToolResult,
    ToolSpec,
    register_all,
    soar_tool,
)
from qradar_soar_mcp.tools import registry as registry_module
from tests.fake_soar import BASE_URL, FakeSoar
from tests.test_permission_matrix import MINIMAL_ARGS  # call arguments only, no decisions
from tests.tool_harness import (
    _classify_action,
    _describe_action,
    audit_records,
    base_env,
    make_local_registry,
    write_keys,
    write_policy,
)

pytestmark = pytest.mark.contract

PKG = Path(qradar_soar_mcp.__file__).parent
TRANSPORTS = ("stdio", "streamable-http")
MUTATING = sorted(name for name, spec in TOOL_REGISTRY.items() if spec.mutating)
PHASE1_MUTATION_MODULES = {
    "qradar_soar_mcp.tools.incidents",
    "qradar_soar_mcp.tools.investigation",
    "qradar_soar_mcp.tools.actions",
}

# ===================================================== the documented contract
# 08 §3 "Approved Phase-1 tool contract": every write tool, its tier and the flag
# that enables it. soar_invoke_action is "per policy (1-5)"; with no verified
# invocation contract it is declared at Tier 3 and "every call is refused" (08 §21).
DOC_WRITE_TOOLS: dict[str, tuple[Tier, str]] = {
    "soar_add_comment": (Tier.DOCUMENTATION, "SOAR_ALLOW_COMMENTS"),
    "soar_add_artifact": (Tier.DOCUMENTATION, "SOAR_ALLOW_ARTIFACTS"),
    "soar_create_incident": (Tier.MODIFICATION, "SOAR_ALLOW_INCIDENT_WRITES"),
    "soar_update_incident": (Tier.MODIFICATION, "SOAR_ALLOW_INCIDENT_WRITES"),
    "soar_assign_incident": (Tier.MODIFICATION, "SOAR_ALLOW_INCIDENT_WRITES"),
    "soar_close_incident": (Tier.MODIFICATION, "SOAR_ALLOW_INCIDENT_CLOSE"),
    "soar_update_task_status": (Tier.MODIFICATION, "SOAR_ALLOW_TASK_WRITES"),
    "soar_invoke_action": (Tier.CONTROL, "SOAR_ALLOW_ACTIONS"),
}
DOC_ALWAYS_REFUSED = {"soar_invoke_action"}  # 08 §3 / §21
# 02 §2.1: the legacy flag maps to these five and deliberately NOT to actions.
DOC_LEGACY_WRITES = {
    "SOAR_ALLOW_COMMENTS",
    "SOAR_ALLOW_ARTIFACTS",
    "SOAR_ALLOW_INCIDENT_WRITES",
    "SOAR_ALLOW_TASK_WRITES",
    "SOAR_ALLOW_INCIDENT_CLOSE",
}
DOC_PHASE1_FLAGS = sorted(DOC_LEGACY_WRITES | {"SOAR_ALLOW_ACTIONS"})
DOC_TIER4_FLAGS = [  # 02 §2: no Phase-1 tool is Tier 4 (08 §3)
    "SOAR_ALLOW_PLAYBOOK_DRAFT",
    "SOAR_ALLOW_PLAYBOOK_EXPORT",
    "SOAR_ALLOW_PLAYBOOK_CREATE",
    "SOAR_ALLOW_PLAYBOOK_MODIFY",
    "SOAR_ALLOW_PLAYBOOK_DEPLOY",
    "SOAR_ALLOW_PLAYBOOK_ENABLE",
]


@dataclasses.dataclass(frozen=True)
class State:
    env: Mapping[str, str]
    policy: bool = False  # write an action policy file (02 §3)
    kill_switch: bool = False  # create SOAR_KILL_SWITCH_FILE (02 §5)


def _on(*flags: str) -> dict[str, str]:
    return dict.fromkeys(flags, "true")


STATES: dict[str, State] = {
    "default": State({}),
    # One flag at a time: a flag wired to the wrong tool shows up here and nowhere else.
    **{f"only_{f.removeprefix('SOAR_ALLOW_').lower()}": State(_on(f)) for f in DOC_LEGACY_WRITES},
    "only_actions": State(_on("SOAR_ALLOW_ACTIONS"), policy=True),
    "only_destructive_actions": State(_on("SOAR_ALLOW_DESTRUCTIVE_ACTIONS"), policy=True),
    "every_phase1_flag": State(
        _on(*DOC_PHASE1_FLAGS, "SOAR_ALLOW_DESTRUCTIVE_ACTIONS"), policy=True
    ),
    "legacy_allow_writes": State(_on("SOAR_ALLOW_WRITES")),
    "every_tier4_flag": State(_on(*DOC_TIER4_FLAGS)),
    "kill_switch": State(
        _on(*DOC_PHASE1_FLAGS, "SOAR_ALLOW_DESTRUCTIVE_ACTIONS"), policy=True, kill_switch=True
    ),
    # 02 §2: the policy file is REQUIRED when actions are on.
    "actions_without_policy": State(
        {**_on(*DOC_LEGACY_WRITES, "SOAR_ALLOW_ACTIONS"), "SOAR_ACTION_POLICY_FILE": ""}
    ),
    # 02 §4.1: actions with in_band approval refuse to start outside lab mode.
    "actions_in_band_outside_lab": State(
        {**_on(*DOC_LEGACY_WRITES, "SOAR_ALLOW_ACTIONS"), "SOAR_APPROVAL_MODE": "in_band"},
        policy=True,
    ),
}


def _enabled(env: Mapping[str, str]) -> set[str]:
    """Flags in force per 02 §2 ("absent, empty or unparseable => false") and §2.1."""
    on = {k for k, v in env.items() if v == "true"}
    if "SOAR_ALLOW_WRITES" in on:
        on |= DOC_LEGACY_WRITES
    return on


def _refuses_to_start(state: State) -> bool:
    on = _enabled(state.env)
    if "SOAR_ALLOW_ACTIONS" not in on:
        return False
    no_policy = not state.policy or state.env.get("SOAR_ACTION_POLICY_FILE") == ""
    in_band_outside_lab = (
        state.env.get("SOAR_APPROVAL_MODE") == "in_band"
        and state.env.get("SOAR_LAB_MODE") != "true"
    )
    return no_policy or in_band_outside_lab


def doc_allows(tool: str, state: State, transport: str) -> tuple[bool, str | None]:
    """(allowed, the flag a denial must name) for a write tool, from the documents only."""
    tier, flag = DOC_WRITE_TOOLS[tool]
    if _refuses_to_start(state):
        return False, None  # P1-02: an unusable runtime denies every call
    if tool in DOC_ALWAYS_REFUSED:
        return False, None
    if state.kill_switch:
        return False, None  # 02 §5: "exists => all tiers >= 1 deny"
    if flag not in _enabled(state.env):
        return False, flag  # P1-05: the denial names the exact env var
    if tier >= Tier.CONTROL and transport == "streamable-http":
        return False, None  # P1-11: Tier >= 3 hard-disabled over HTTP
    return True, None


def build_runtime(
    tmp_path: Path, state: State, transport: str, now: Callable[[], float] | None = None
) -> Runtime:
    env = base_env(tmp_path)
    _, public = write_keys(tmp_path)
    env["SOAR_APPROVAL_PUBLIC_KEY_FILE"] = str(public)
    if state.policy:
        env["SOAR_ACTION_POLICY_FILE"] = str(write_policy(tmp_path))
    if transport == "streamable-http":
        env["SOAR_HTTP_AUTH_TOKEN"] = "t" * 32
    if state.kill_switch:
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        (tmp_path / "state" / "HALT").write_text("")
    env.update(state.env)
    if now is None:
        return Runtime.build(env, transport=transport)
    return Runtime.build(env, transport=transport, now=now)


WRITES_ON = STATES["every_phase1_flag"]


# ================================================================== helpers


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


# ======================================================= 0. the contract itself


def test_the_registry_declares_what_the_documents_say():
    """Every write tool, and only those, with its documented tier and flag."""
    assert sorted(DOC_WRITE_TOOLS) == MUTATING, "write tools differ from 08 §3"
    for name, (tier, flag) in DOC_WRITE_TOOLS.items():
        spec = TOOL_REGISTRY[name]
        assert (spec.tier, spec.capability) == (tier, flag), name
    assert TOOL_REGISTRY["soar_invoke_action"].unsupported, "08 §21: invoke must refuse"


# ================================================================ 1. binding


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
    rt = build_runtime(tmp_path, WRITES_ON, "stdio")  # writes enabled: no gate to hide behind
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


# ================================================ 2. documented authorisation


def _cases() -> Iterator[Any]:
    for state in STATES:
        for transport in TRANSPORTS:
            yield pytest.param(state, transport, id=f"{state}-{transport}")


@pytest.mark.parametrize(("state_name", "transport"), list(_cases()))
async def test_mutating_bodies_run_exactly_when_the_documents_allow(
    state_name: str, transport: str, tmp_path: Path, soar: FakeSoar
):
    state = STATES[state_name]
    fired: list[str] = []
    rt = build_runtime(tmp_path, state, transport)
    assert rt.usable is not _refuses_to_start(state), f"{state_name}: startup refusal differs"
    server: MCPServer[Any] = MCPServer("p1-14-tripwire")
    register_all(server, rt, _tripwired(fired))

    allowed: list[str] = []
    for name in MUTATING:
        ok, flag = doc_allows(name, state, transport)
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        if ok:
            allowed.append(name)
            assert out["ok"] is True and out["data"] == {"tripwire": name}, (name, out)
        else:
            assert out["ok"] is False and out["error"]["code"].startswith("DENY_"), (name, out)
            if flag is not None:
                assert flag in out["error"]["message"], (name, flag, out)
    await rt.aclose()

    assert fired == allowed, f"{state_name}/{transport}: ran {fired}, documents allow {allowed}"
    assert _soar_mutations(soar) == []


async def test_incident_writes_cannot_close_an_incident(tmp_path: Path, soar: FakeSoar):
    """08 P1-14 note: soar_update_incident refuses the close fields, so the write flag
    cannot stand in for SOAR_ALLOW_INCIDENT_CLOSE. Real body, real (fake) SOAR."""
    rt = build_runtime(tmp_path, STATES["only_incident_writes"], "stdio")
    server = build_server(rt)
    for field_name, value in (
        ("plan_status", "C"),
        ("resolution_id", "Resolved"),
        ("resolution_summary", "closed by a side door"),
    ):
        args = {"incident_id": 42, "changes": {field_name: value}}
        out = _payload(await server.call_tool("soar_update_incident", args))
        assert out["ok"] is False, (field_name, out)
    await rt.aclose()
    assert _soar_mutations(soar) == []


# ====================================================== 3. default, real bodies


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_default_config_sends_no_mutation_through_the_server(
    transport: str, tmp_path: Path, soar: FakeSoar
):
    """Every tool, real bodies, called the way a client calls it: SOAR sees no write,
    each write is refused naming its flag, and each refusal is audited once."""
    rt = build_runtime(tmp_path, STATES["default"], transport)
    server = build_server(rt)
    for name in sorted(TOOL_REGISTRY):
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        if name in MUTATING:
            assert out["ok"] is False, (name, out)
            assert DOC_WRITE_TOOLS[name][1] in out["error"]["message"], (name, out)
    await rt.aclose()

    assert _soar_mutations(soar) == []
    denied = [r["tool"] for r in audit_records(tmp_path) if r["event"] == "DECISION_DENIED"]
    assert sorted(denied) == MUTATING
    events = {r["event"] for r in audit_records(tmp_path)}
    assert not events & {"MUTATION_PENDING", "MUTATION_COMMITTED", "MUTATION_FAILED"}


# ================================================================== 4. audit

EXECUTABLE = [n for n in MUTATING if n not in DOC_ALWAYS_REFUSED]


def _break_audit(rt: Runtime, *, keep: frozenset[str] = frozenset()) -> None:
    """Every audit append raises, except for the events in ``keep``."""
    assert rt.audit is not None
    original = rt.audit.append

    def append(event: str, **fields: Any) -> Any:
        if event in keep:
            return original(event, **fields)
        raise AuditError("read-only filesystem")

    rt.audit.append = append  # type: ignore[method-assign]


async def test_unwritable_audit_refuses_every_mutation_before_it_starts(
    tmp_path: Path, soar: FakeSoar
):
    rt = build_runtime(tmp_path, WRITES_ON, "stdio")
    _break_audit(rt)
    server = build_server(rt)
    for name in MUTATING:
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        assert out["ok"] is False, (name, out)
        if name in EXECUTABLE:
            assert out["error"]["code"] == "DENY_AUDIT", (name, out)
    await rt.aclose()
    assert _soar_mutations(soar) == []


async def test_missing_audit_log_refuses_every_mutation_before_it_starts(
    tmp_path: Path, soar: FakeSoar
):
    rt = build_runtime(tmp_path, WRITES_ON, "stdio")
    rt.audit = None  # what Runtime.build leaves when the log cannot open, audit not required
    server = build_server(rt)
    for name in MUTATING:
        out = _payload(await server.call_tool(name, dict(MINIMAL_ARGS[name])))
        assert out["ok"] is False, (name, out)
        if name in EXECUTABLE:
            assert out["error"]["code"] == "DENY_AUDIT", (name, out)
    # Reads keep working: only mutations need the log.
    assert _payload(await server.call_tool("soar_get_incident", {"incident_id": 42}))["ok"] is True
    await rt.aclose()
    assert _soar_mutations(soar) == []


async def _one_call(
    directory: Path, name: str, *, audit_dies_after_pending: bool
) -> tuple[dict[str, Any], list[tuple[str, str]], list[dict[str, Any]]]:
    fake = FakeSoar()
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=fake.handler)
        rt = build_runtime(directory, WRITES_ON, "stdio")
        if audit_dies_after_pending:
            _break_audit(rt, keep=frozenset({"MUTATION_PENDING"}))
        out = _payload(await build_server(rt).call_tool(name, dict(MINIMAL_ARGS[name])))
        await rt.aclose()
    return out, _soar_mutations(fake), audit_records(directory)


@pytest.mark.parametrize("name", EXECUTABLE)
async def test_audit_failure_after_an_applied_mutation_reports_it_applied_and_never_retries(
    name: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    """SOAR has already applied the change when MUTATION_COMMITTED cannot be written.

    The existing contract (02 §6; registry ``_finish``): the terminal record is
    best-effort, so the caller is told the truth (ok, with the result), the write
    is sent exactly as often as in a healthy run (no retry), the failure reaches
    the operator log, and the chain keeps the PENDING record that names the call."""
    (tmp_path / "healthy").mkdir()
    (tmp_path / "broken").mkdir()
    healthy, healthy_writes, _ = await _one_call(
        tmp_path / "healthy", name, audit_dies_after_pending=False
    )
    assert healthy["ok"] is True, healthy
    with caplog.at_level(logging.ERROR):
        out, writes, records = await _one_call(
            tmp_path / "broken", name, audit_dies_after_pending=True
        )

    # Same shape of answer as the healthy run (ids and timestamps differ between runs).
    assert out["ok"] is True and _keys(out["data"]) == _keys(healthy["data"]), out
    assert writes == healthy_writes and writes, "the mutation was resent or not sent"
    pending = [r for r in records if r["event"] == "MUTATION_PENDING"]
    assert [r["tool"] for r in pending] == [name]
    assert pending[0]["request_id"] == out["request_id"]
    assert not [r for r in records if r["event"] in {"MUTATION_COMMITTED", "MUTATION_FAILED"}]
    assert any("audit write failed (MUTATION_COMMITTED)" in r.getMessage() for r in caplog.records)


def _keys(data: Any) -> Any:
    return sorted(data) if isinstance(data, dict) else type(data).__name__


async def test_lost_answer_after_soar_applied_the_write_is_not_retried(
    tmp_path: Path, soar: FakeSoar, caplog: pytest.LogCaptureFixture
):
    """SOAR applies the comment but the answer is lost (5xx), and MUTATION_FAILED cannot
    be written either. The call fails, is sent once, and the PENDING record stays."""
    before = len(soar.comments[42])
    soar.fault("POST", r"/incidents/42/comments$", status=503, processed=True)
    rt = build_runtime(tmp_path, WRITES_ON, "stdio")
    _break_audit(rt, keep=frozenset({"MUTATION_PENDING"}))
    with caplog.at_level(logging.ERROR):
        out = _payload(
            await build_server(rt).call_tool(
                "soar_add_comment", dict(MINIMAL_ARGS["soar_add_comment"])
            )
        )
    await rt.aclose()

    assert out["ok"] is False, out
    assert len(soar.comments[42]) == before + 1, "the fake must have applied the write"
    writes = _soar_mutations(soar)
    assert len(writes) == 1 and writes[0][1].endswith("/incidents/42/comments"), writes
    # The caller gets SOAR's own error, not a claim that nothing changed (see the PR's
    # remaining-risks note: the response cannot say the write may have landed).
    assert out["error"]["code"] == "server_error" and out["error"]["http_status"] == 503, out
    events = [r["event"] for r in audit_records(tmp_path)]
    assert events.count("MUTATION_PENDING") == 1 and "MUTATION_COMMITTED" not in events
    assert any("audit write failed (MUTATION_FAILED)" in r.getMessage() for r in caplog.records)


async def test_an_unrecorded_mutation_still_counts_against_the_hourly_cap_after_restart(
    tmp_path: Path, soar: FakeSoar
):
    """02 §5: "a restart must not reset the budget". A Tier-2 write SOAR applied whose
    MUTATION_COMMITTED was lost must still consume its slot when the process restarts."""
    state = State({**WRITES_ON.env, "SOAR_MAX_TIER2_PER_HOUR": "1"}, policy=True)
    args = {"incident_id": 42, "changes": {"severity_code": "High"}}

    rt = build_runtime(tmp_path, state, "stdio")
    _break_audit(rt, keep=frozenset({"MUTATION_PENDING"}))
    first = _payload(await build_server(rt).call_tool("soar_update_incident", args))
    await rt.aclose()
    assert first["ok"] is True, first

    restarted = build_runtime(tmp_path, state, "stdio")
    second = _payload(await build_server(restarted).call_tool("soar_update_incident", args))
    await restarted.aclose()
    assert second["ok"] is False and second["error"]["code"] == "DENY_RATE_LIMIT", second
    assert len([m for m in _soar_mutations(soar) if m[0] == "PATCH"]) == 1


# ============================================================== 5. approvals
# The only real Tier >= 3 tool (soar_invoke_action) refuses every call (08 §21), so the
# approval lifecycle runs on the harness invoke tool: the real broker, the real
# pipeline, the real MCP binding; only the effect is recorded instead of sent.

APPROVAL_ENV = State(
    _on("SOAR_ALLOW_ACTIONS", "SOAR_ALLOW_DESTRUCTIVE_ACTIONS"), policy=True
)  # out_of_band is the default (02 §4.1)
ISOLATE = {"incident_id": 42, "action_id": 49, "targets": ["host-4471"]}  # Tier 3, approval


class Clock:
    def __init__(self) -> None:
        import time

        self.t = time.time()

    def __call__(self) -> float:
        return self.t


@dataclasses.dataclass
class ApprovalRig:
    rt: Runtime
    server: MCPServer[Any]
    effects: list[dict[str, Any]]
    twin_effects: list[dict[str, Any]]
    clock: Clock
    private_key_path: Path
    tmp_path: Path

    async def call(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        return _payload(await self.server.call_tool(tool, dict(args)))

    async def request(self, tool: str = "soar_t_invoke", args: Mapping[str, Any] = ISOLATE) -> str:
        out = await self.call(tool, args)
        assert out["error"]["code"] == "REQUIRE_APPROVAL", out
        return str(out["approval_id"])

    def approve(self, approval_id: str, *, key: Path | None = None, **tamper: Any) -> None:
        """What qradar-soar-approve writes once a human has typed the reference back."""
        assert self.rt.broker is not None
        request = self.rt.broker.load_request(approval_id)
        assert request is not None
        approved = sign_request(
            request,
            private_key=load_private_key(key or self.private_key_path),
            approver="j.rossi",
            now=self.clock(),
            ttl_seconds=300,
        )
        approved.update(tamper)
        path = self.rt.broker.path / f"{approval_id}.approved.json"
        path.write_text(json.dumps(approved), encoding="utf-8")

    def state(self, approval_id: str) -> str:
        assert self.rt.broker is not None
        return str(self.rt.broker.status(approval_id)["state"])


@pytest.fixture
async def rig(tmp_path: Path, soar: FakeSoar) -> Any:
    effects: list[dict[str, Any]] = []
    twin_effects: list[dict[str, Any]] = []
    reg = make_local_registry(effects)

    @soar_tool(
        name="soar_t_invoke_twin",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        classify=_classify_action,
        describe=_describe_action,
        registry=reg,
    )
    async def twin(
        rt: Runtime,
        incident_id: int,
        action_id: int,
        targets: list[str] | None = None,
        approval_id: str | None = None,
    ) -> ToolResult:
        """the same arguments under another tool name"""
        twin_effects.append({"incident_id": incident_id, "action_id": action_id})
        return ToolResult(data={"twin": True}, target={"incident_id": incident_id})

    clock = Clock()
    rt = build_runtime(tmp_path, APPROVAL_ENV, "stdio", now=clock)
    assert rt.usable, rt.config_error
    server: MCPServer[Any] = MCPServer("p1-14-approvals")
    register_all(server, rt, reg)
    private_key = tmp_path / "keys" / "approval.key"  # written by build_runtime
    yield ApprovalRig(rt, server, effects, twin_effects, clock, private_key, tmp_path)
    await rt.aclose()


async def test_a_genuine_approval_runs_the_call_once_and_cannot_be_replayed(rig: ApprovalRig):
    approval_id = await rig.request()
    assert rig.effects == [] and rig.state(approval_id) == "pending"
    # Not yet approved: still waiting, nothing ran, nothing consumed.
    waiting = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert waiting["error"]["code"] == "REQUIRE_APPROVAL" and rig.effects == []

    rig.approve(approval_id)
    done = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert done["ok"] is True and done["approval"] == {
        "approval_id": approval_id,
        "approver": "j.rossi",
    }
    assert rig.effects == [{"incident_id": 42, "action_id": 49}]
    assert rig.state(approval_id) == "consumed"

    replay = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert replay["error"]["code"] == "DENY_APPROVAL", replay
    assert len(rig.effects) == 1
    events = [r["event"] for r in audit_records(rig.tmp_path)]
    assert events.count("APPROVAL_CONSUMED") == 1 and events.count("MUTATION_COMMITTED") == 1


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        pytest.param("soar_t_invoke", {**ISOLATE, "targets": ["host-9999"]}, id="other-target"),
        pytest.param("soar_t_invoke", {**ISOLATE, "targets": []}, id="no-target"),
        pytest.param("soar_t_invoke_twin", ISOLATE, id="other-tool-same-args"),
    ],
)
async def test_an_approval_authorises_only_its_own_tool_and_arguments(
    rig: ApprovalRig, tool: str, args: dict[str, Any]
):
    approval_id = await rig.request()
    rig.approve(approval_id)
    misuse = await rig.call(tool, {**args, "approval_id": approval_id})
    assert misuse["ok"] is False and misuse["error"]["code"] == "DENY_APPROVAL", misuse
    assert rig.effects == [] and rig.twin_effects == []
    # A mismatch spends nothing: the intended call still runs, once.
    assert rig.state(approval_id) == "approved"
    done = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert done["ok"] is True and len(rig.effects) == 1


async def test_an_expired_approval_is_refused(rig: ApprovalRig):
    approval_id = await rig.request()
    rig.approve(approval_id)  # signed with a 300 s lifetime
    rig.clock.t += 301
    out = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert out["error"]["code"] == "DENY_APPROVAL" and "expired" in out["error"]["message"], out
    assert rig.effects == []


async def test_an_expired_request_is_refused_even_if_signed_in_time(rig: ApprovalRig):
    approval_id = await rig.request()
    rig.approve(approval_id)
    assert rig.rt.settings is not None
    rig.clock.t += rig.rt.settings.approval_ttl_seconds + 1
    out = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert out["error"]["code"] == "DENY_APPROVAL" and "expired" in out["error"]["message"], out
    assert rig.effects == []


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param({"approver": "someone.else"}, id="edited-approver"),
        pytest.param({"expires_at": "2099-01-01T00:00:00Z"}, id="extended-expiry"),
        pytest.param({"signature": "AAAA"}, id="bad-signature"),
        pytest.param({"arguments_hash": "sha256:" + "0" * 64}, id="other-arguments"),
    ],
)
async def test_an_altered_approval_file_is_refused(rig: ApprovalRig, tamper: dict[str, Any]):
    approval_id = await rig.request()
    rig.approve(approval_id, **tamper)
    out = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert out["error"]["code"] == "DENY_APPROVAL", out
    assert rig.effects == []


async def test_an_approval_signed_with_another_key_is_refused(rig: ApprovalRig, tmp_path: Path):
    other_private, other_public = tmp_path / "other.key", tmp_path / "other.pub"
    generate_keypair(other_private, other_public)
    approval_id = await rig.request()
    rig.approve(approval_id, key=other_private)
    out = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert out["error"]["code"] == "DENY_APPROVAL" and "signature" in out["error"]["message"]
    assert rig.effects == []


async def test_an_approval_spent_on_an_audit_refusal_cannot_be_reused(rig: ApprovalRig):
    """Consumption precedes MUTATION_PENDING (registry step 8 before 9). If PENDING
    cannot be written the call fails closed and the approval is gone: a human must
    approve again. Nothing ran either time."""
    approval_id = await rig.request()
    rig.approve(approval_id)
    original = rig.rt.audit
    _break_audit(rig.rt)
    refused = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert refused["error"]["code"] == "DENY_AUDIT", refused
    rig.rt.audit = original
    assert rig.state(approval_id) == "consumed"
    again = await rig.call("soar_t_invoke", {**ISOLATE, "approval_id": approval_id})
    assert again["error"]["code"] == "DENY_APPROVAL" and rig.effects == []


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_forged_approval_never_reaches_a_real_tool_body(
    transport: str, tmp_path: Path, soar: FakeSoar
):
    """The real Tier >= 3 tools, every action flag on, a made-up approval id: refused,
    no approval consumed, body never run."""
    fired: list[str] = []
    rt = build_runtime(tmp_path, WRITES_ON, transport)
    server: MCPServer[Any] = MCPServer("p1-14-forged")
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


# ================================================================ 6. static


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
