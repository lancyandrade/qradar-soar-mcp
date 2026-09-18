"""P1-13: the chokepoint runs every stage of 01 §4 in order and never leaks."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from qradar_soar_mcp.security.approvals import (
    IN_BAND_DISCLAIMER,
    load_private_key,
    sign_request,
)
from qradar_soar_mcp.security.audit import AuditError
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import (
    Runtime,
    ToolResult,
    ToolSpec,
    register_all,
    run_pipeline,
    soar_tool,
)
from qradar_soar_mcp.tools.registry import INTERNAL_ERROR_MESSAGE, ToolDefinitionError, bind
from tests.conftest import SENTINEL
from tests.fake_soar import FakeSoar
from tests.tool_harness import (
    audit_records,
    base_env,
    build_runtime,
    make_local_registry,
    write_keys,
    write_policy,
)

pytestmark = pytest.mark.contract


@pytest.fixture
def reg() -> dict[str, ToolSpec]:
    return make_local_registry()


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    return write_policy(tmp_path)


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    return write_keys(tmp_path)


def _events(tmp_path: Path) -> list[tuple[str, Any]]:
    return [(r["event"], r["decision"]) for r in audit_records(tmp_path)]


# ------------------------------------------------------------ declaration


def test_decorator_rejects_bad_declarations():
    reg: dict[str, ToolSpec] = {}

    async def ok(rt: Runtime) -> ToolResult:
        """d"""
        return ToolResult(data={})

    async def with_approval(rt: Runtime, approval_id: str | None = None) -> ToolResult:
        """d"""
        return ToolResult(data={})

    cases = [
        (dict(name="get_incident", tier=Tier.READ), "start with soar_", ok),
        (dict(name="soar_Get", tier=Tier.READ), "lower-case", ok),
        (
            dict(name="soar_x", tier=Tier.READ, capability="SOAR_ALLOW_COMMENTS"),
            "read tools declare no capability",
            ok,
        ),
        (dict(name="soar_x", tier=Tier.DOCUMENTATION), "must declare a capability", ok),
        (
            dict(name="soar_x", tier=Tier.DOCUMENTATION, capability="SOAR_ALLOW_NOPE"),
            "unknown capability",
            ok,
        ),
        (
            dict(name="soar_x", tier=Tier.DOCUMENTATION, capability="SOAR_ALLOW_ACTIONS"),
            "is tier 3",
            ok,
        ),
        (
            dict(name="soar_x", tier=Tier.HIGH_RISK, capability="SOAR_ALLOW_ACTIONS"),
            "Tier 5 tools do not exist",
            ok,
        ),
        (
            dict(
                name="soar_x",
                tier=Tier.CONTROL,
                capability="SOAR_ALLOW_ACTIONS",
                describe=lambda a, p: {},
            ),
            "must accept approval_id",
            ok,
        ),
        (
            dict(name="soar_x", tier=Tier.CONTROL, capability="SOAR_ALLOW_ACTIONS"),
            "describe",
            with_approval,
        ),
        (
            dict(
                name="soar_x",
                tier=Tier.DOCUMENTATION,
                capability="SOAR_ALLOW_COMMENTS",
                mutations=0,
            ),
            "at least one",
            ok,
        ),
        (dict(name="soar_x", tier=Tier.READ, mutations=1), "mutates nothing", ok),
    ]
    for kwargs, match, func in cases:
        with pytest.raises(ToolDefinitionError, match=match):
            soar_tool(registry=reg, **kwargs)(func)

    def sync(rt: Runtime) -> ToolResult:
        """d"""
        return ToolResult(data={})

    with pytest.raises(ToolDefinitionError, match="async"):
        soar_tool(name="soar_x", tier=Tier.READ, registry=reg)(sync)  # type: ignore[arg-type]

    async def no_rt(incident_id: int) -> ToolResult:
        """d"""
        return ToolResult(data={})

    with pytest.raises(ToolDefinitionError, match="'rt'"):
        soar_tool(name="soar_x", tier=Tier.READ, registry=reg)(no_rt)

    async def undocumented(rt: Runtime) -> ToolResult:
        return ToolResult(data={})

    with pytest.raises(ToolDefinitionError, match="description"):
        soar_tool(name="soar_x", tier=Tier.READ, registry=reg)(undocumented)
    soar_tool(name="soar_x", tier=Tier.READ, registry=reg)(ok)
    with pytest.raises(ToolDefinitionError, match="duplicate"):
        soar_tool(name="soar_x", tier=Tier.READ, registry=reg)(ok)
    assert ok.__soar_tool__.name == "soar_x" and reg["soar_x"].mutations == 0  # type: ignore[attr-defined]


# ---------------------------------------------------------------- runtime


def test_unusable_runtime_denies_everything(reg, tmp_path: Path):
    rt = Runtime.build({"SOAR_ALLOW_SCRIPT_WRITES": "true"})
    assert not rt.usable and "non-goal" in (rt.config_error or "")
    for spec in reg.values():
        out = run_pipeline_sync(spec, rt)
        assert out["ok"] is False and out["error"]["code"] == "DENY_CONFIG"
        assert "non-goal" in out["error"]["message"]
    assert rt.describe()["usable"] is False


def run_pipeline_sync(spec: ToolSpec, rt: Runtime) -> dict[str, Any]:
    import asyncio

    args = {
        "incident_id": 42,
        "verbose": False,
        "text": "t",
        "field_name": "description",
        "value": "v",
        "action_id": 48,
        "targets": None,
        "approval_id": None,
    }
    return asyncio.run(run_pipeline(spec, rt, args))


@pytest.mark.parametrize(
    ("env", "needle"),
    [
        ({"SOAR_MCP_TRANSPORT": "http"}, "SOAR_HTTP_AUTH_TOKEN"),
        ({"SOAR_ALLOW_ACTIONS": "true", "SOAR_ACTION_POLICY_FILE": "policy"}, "action policy"),
        ({"SOAR_APPROVAL_PUBLIC_KEY_FILE": "missing.pub"}, "approval public key"),
    ],
)
def test_startup_refusals(tmp_path: Path, env: dict[str, str], needle: str):
    if env.get("SOAR_ACTION_POLICY_FILE") == "policy":
        bad = tmp_path / "bad.yaml"
        bad.write_text("nonsense: 1\n", encoding="utf-8")
        env["SOAR_ACTION_POLICY_FILE"] = str(bad)
    if "SOAR_APPROVAL_PUBLIC_KEY_FILE" in env:
        env["SOAR_APPROVAL_PUBLIC_KEY_FILE"] = str(tmp_path / env["SOAR_APPROVAL_PUBLIC_KEY_FILE"])
    rt = Runtime.build(base_env(tmp_path, **env))
    assert not rt.usable and needle in (rt.config_error or "")


def test_audit_required_unwritable_refuses_start(tmp_path: Path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    rt = Runtime.build(base_env(tmp_path, SOAR_AUDIT_LOG_PATH=str(blocker / "audit.jsonl")))
    assert not rt.usable and "SOAR_AUDIT_REQUIRED=true" in (rt.config_error or "")
    rt2 = Runtime.build(
        base_env(
            tmp_path, SOAR_AUDIT_LOG_PATH=str(blocker / "audit.jsonl"), SOAR_AUDIT_REQUIRED="false"
        )
    )
    assert (
        rt2.usable
        and rt2.audit is None
        and any("mutations will be refused" in w for w in rt2.warnings)
    )


def test_runtime_describe_and_no_connection(tmp_path: Path):
    rt = Runtime.build(
        {
            "SOAR_AUDIT_LOG_PATH": str(tmp_path / "a.jsonl"),
            "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "b"),
        }
    )
    d = rt.describe()
    assert d["usable"] and not d["connection_configured"] and d["capabilities"] == []
    assert any("not configured" in w for w in d["warnings"])
    assert d["approvals"]["can_verify"] is False and d["audit"]["open"] is True


# ---------------------------------------------------------------- denials


async def test_disabled_tier_denied_with_var_and_audited(reg, fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "hi"})
    assert (
        out["error"]["code"] == "DENY_DISABLED"
        and "SOAR_ALLOW_COMMENTS=true" in out["error"]["message"]
    )
    assert fake.mutating_requests == []
    records = audit_records(tmp_path)
    assert (
        len(records) == 1
        and records[0]["event"] == "DECISION_DENIED"
        and records[0]["tool"] == "soar_t_comment"
    )
    assert records[0]["target"] == {"incident_id": 42}
    ok = await run_pipeline(reg["soar_t_read"], rt, {"incident_id": 42, "verbose": False})
    assert ok["ok"] is True and ok["data"]["id"] == 42
    assert len(audit_records(tmp_path)) == 1  # reads that succeed are not audited
    await rt.aclose()


async def test_kill_switch_breaker_and_bulk_cap(reg, fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(
        fake, tmp_path, SOAR_ALLOW_COMMENTS="true", SOAR_ALLOW_INCIDENT_WRITES="true"
    )
    (tmp_path / "state" / "HALT").write_text("")
    out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "hi"})
    assert out["error"]["code"] == "DENY_KILL_SWITCH"
    assert (await run_pipeline(reg["soar_t_read"], rt, {"incident_id": 42, "verbose": False}))["ok"]
    (tmp_path / "state" / "HALT").unlink()
    assert (await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "hi"}))["ok"]
    # Breaker: three consecutive Tier-2 failures.
    fake.fault("PATCH", r"/incidents/42$", status=500)
    for _ in range(3):
        out = await run_pipeline(
            reg["soar_t_update"], rt, {"incident_id": 42, "field_name": "description", "value": "x"}
        )
        assert out["error"]["code"] == "server_error"
    out = await run_pipeline(
        reg["soar_t_update"], rt, {"incident_id": 42, "field_name": "description", "value": "x"}
    )
    assert out["error"]["code"] == "DENY_BREAKER"
    assert ("BREAKER_TRIPPED", "DENY_BREAKER") in _events(tmp_path)
    assert (await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "still ok"}))[
        "ok"
    ]  # tier 1 unaffected
    await rt.aclose()


async def test_hourly_cap_and_persistence_across_restart(reg, fake: FakeSoar, tmp_path: Path):
    env = dict(SOAR_ALLOW_INCIDENT_WRITES="true", SOAR_MAX_TIER2_PER_HOUR="2")
    rt = build_runtime(fake, tmp_path, **env)
    for value in ("a", "b"):
        assert (
            await run_pipeline(
                reg["soar_t_update"],
                rt,
                {"incident_id": 42, "field_name": "description", "value": value},
            )
        )["ok"]
    out = await run_pipeline(
        reg["soar_t_update"], rt, {"incident_id": 42, "field_name": "description", "value": "c"}
    )
    assert out["error"]["code"] == "DENY_RATE_LIMIT"
    await rt.aclose()
    restarted = build_runtime(fake, tmp_path, **env)  # counters seeded from the audit log
    out = await run_pipeline(
        reg["soar_t_update"],
        restarted,
        {"incident_id": 42, "field_name": "description", "value": "d"},
    )
    assert out["error"]["code"] == "DENY_RATE_LIMIT"
    await restarted.aclose()


# ------------------------------------------------------------ mutations


async def test_mutation_produces_pending_and_committed_with_images(
    reg, fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path, SOAR_ALLOW_INCIDENT_WRITES="true")
    out = await run_pipeline(
        reg["soar_t_update"],
        rt,
        {"incident_id": 42, "field_name": "severity_code", "value": "High"},
    )
    assert out["ok"] and out["data"]["changed"] == {"severity_code": ["Medium", "High"]}
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_COMMITTED"]
    pending, committed = records
    assert pending["request_id"] == committed["request_id"]
    assert pending["capability"] == "SOAR_ALLOW_INCIDENT_WRITES" and pending["tier"] == 2
    assert (
        committed["pre_image"]["severity_code"] == "Medium"
        and committed["post_image"]["severity_code"] == "High"
    )
    assert committed["duration_ms"] >= 0 and committed["server_version"]
    assert "audit" not in json.dumps(out) and "pre_image" not in json.dumps(out)
    await rt.aclose()


async def test_soar_failure_is_structured_and_audited_failed(reg, fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path, SOAR_ALLOW_COMMENTS="true")
    out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 999, "text": "hi"})
    assert out["error"]["code"] == "not_found" and out["error"]["http_status"] == 404
    assert [r["event"] for r in audit_records(tmp_path)] == ["MUTATION_PENDING", "MUTATION_FAILED"]
    await rt.aclose()


async def test_crash_is_generic_and_never_leaks(reg, fake: FakeSoar, tmp_path: Path, caplog):
    rt = build_runtime(fake, tmp_path)
    with caplog.at_level(logging.ERROR):
        out = await run_pipeline(reg["soar_t_crash"], rt, {})
    assert out["error"] == {"code": "internal", "message": INTERNAL_ERROR_MESSAGE}
    assert SENTINEL not in json.dumps(out)
    await rt.aclose()


async def test_audit_write_failure_fails_closed(reg, fake: FakeSoar, tmp_path: Path, monkeypatch):
    rt = build_runtime(fake, tmp_path, SOAR_ALLOW_COMMENTS="true")

    def broken(*a, **k):
        raise AuditError("read-only filesystem")

    monkeypatch.setattr(rt.audit, "append", broken)
    out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "hi"})
    assert out["error"]["code"] == "DENY_AUDIT"
    assert fake.mutating_requests == []
    rt.audit = None
    out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "hi"})
    assert out["error"]["code"] == "DENY_AUDIT"
    assert (await run_pipeline(reg["soar_t_read"], rt, {"incident_id": 42, "verbose": False}))["ok"]
    await rt.aclose()


async def test_best_effort_audit_failure_does_not_mask_a_denial(
    reg, fake: FakeSoar, tmp_path: Path, monkeypatch, caplog
):
    rt = build_runtime(fake, tmp_path)

    def broken(*a, **k):
        raise AuditError("disk full")

    monkeypatch.setattr(rt.audit, "append", broken)
    with caplog.at_level(logging.ERROR):
        out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": "hi"})
    assert out["error"]["code"] == "DENY_DISABLED"
    assert any("audit write failed" in r.getMessage() for r in caplog.records)
    await rt.aclose()


def test_actions_without_public_key_warns(tmp_path: Path, policy: Path):
    rt = Runtime.build(
        base_env(tmp_path, SOAR_ALLOW_ACTIONS="true", SOAR_ACTION_POLICY_FILE=str(policy))
    )
    assert rt.usable and any("no approval can ever be verified" in w for w in rt.warnings)


async def test_not_configured_connection(reg, tmp_path: Path):
    rt = Runtime.build(
        {
            "SOAR_ALLOW_COMMENTS": "true",
            "SOAR_AUDIT_LOG_PATH": str(tmp_path / "a.jsonl"),
            "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "b"),
        }
    )
    out = await run_pipeline(reg["soar_t_read"], rt, {"incident_id": 42, "verbose": False})
    assert out["error"]["code"] == "not_configured"


# ---------------------------------------------------------------- invoke


async def test_invoke_uses_policy_tier_and_target_constraints(
    reg, fake: FakeSoar, tmp_path: Path, policy: Path, keys
):
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(policy),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(keys[1]),
    )
    # Tier-1 action: allowed outright, no approval.
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {"incident_id": 42, "action_id": 48, "targets": None, "approval_id": None},
    )
    assert out["ok"] and fake.action_invocations == [{"incident_id": 42, "action_id": 48}]
    # Explicit policy deny (Purge Mailbox); unclassified action (Enrich) falls to the
    # default Tier 5; unknown action: not_found; deny_values: DENY_TARGET.
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {"incident_id": 42, "action_id": 52, "targets": None, "approval_id": None},
    )
    assert out["error"]["code"] == "DENY_POLICY" and "Purge Mailbox" in out["error"]["message"]
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {"incident_id": 42, "action_id": 50, "targets": None, "approval_id": None},
    )
    assert out["error"]["code"] == "DENY_POLICY" and "matches no rule" in out["error"]["message"]
    assert "'default'" in out["error"]["message"]
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {"incident_id": 42, "action_id": 999, "targets": None, "approval_id": None},
    )
    assert out["error"]["code"] == "not_found"
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {
            "incident_id": 42,
            "action_id": 49,
            "targets": ["dc01.example.internal"],
            "approval_id": None,
        },
    )
    assert out["error"]["code"] == "DENY_TARGET"
    # Destructive without the destructive flag.
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {"incident_id": 42, "action_id": 49, "targets": ["host-4471"], "approval_id": None},
    )
    assert out["error"]["code"] == "DENY_DESTRUCTIVE"
    assert len(fake.action_invocations) == 1
    await rt.aclose()


async def test_out_of_band_approval_round_trip(
    reg, fake: FakeSoar, tmp_path: Path, policy: Path, keys
):
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(policy),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(keys[1]),
    )
    args = {"incident_id": 42, "action_id": 49, "targets": ["host-4471"], "approval_id": None}
    first = await run_pipeline(reg["soar_t_invoke"], rt, args)
    assert first["error"]["code"] == "REQUIRE_APPROVAL" and first["approval_id"].startswith("APR-")
    assert (
        "Do not retry" in first["error"]["message"]
        and "soar_check_approval" in first["error"]["message"]
    )
    assert fake.action_invocations == []
    approval_id = first["approval_id"]
    assert rt.broker is not None and rt.broker.status(approval_id)["state"] == "pending"
    pending = await run_pipeline(reg["soar_t_invoke"], rt, {**args, "approval_id": approval_id})
    assert pending["error"]["code"] == "REQUIRE_APPROVAL" and fake.action_invocations == []
    # A human approves in their environment.
    request = rt.broker.load_request(approval_id)
    approved = sign_request(
        request,
        private_key=load_private_key(keys[0]),
        approver="j.rossi",
        now=__import__("time").time(),
        ttl_seconds=300,
    )
    (rt.broker.path / f"{approval_id}.approved.json").write_text(
        json.dumps(approved), encoding="utf-8"
    )
    second = await run_pipeline(reg["soar_t_invoke"], rt, {**args, "approval_id": approval_id})
    assert second["ok"] and second["approval"] == {
        "approval_id": approval_id,
        "approver": "j.rossi",
    }
    assert fake.action_invocations == [{"incident_id": 42, "action_id": 49}]
    replay = await run_pipeline(reg["soar_t_invoke"], rt, {**args, "approval_id": approval_id})
    assert replay["error"]["code"] == "DENY_APPROVAL" and len(fake.action_invocations) == 1
    changed = await run_pipeline(
        reg["soar_t_invoke"], rt, {**args, "targets": ["other"], "approval_id": approval_id}
    )
    assert changed["error"]["code"] == "DENY_APPROVAL"
    events = _events(tmp_path)
    assert events[0] == ("APPROVAL_REQUESTED", "REQUIRE_APPROVAL")
    assert ("APPROVAL_CONSUMED", "ALLOW") in events and ("MUTATION_COMMITTED", "ALLOW") in events
    assert any(
        r["approver"] == "j.rossi" and r["event"] == "MUTATION_PENDING"
        for r in audit_records(tmp_path)
    )
    await rt.aclose()


async def test_in_band_mode_states_it_is_not_human_approval(
    reg, fake: FakeSoar, tmp_path: Path, policy: Path
):
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(policy),
        SOAR_APPROVAL_MODE="in_band",
        SOAR_LAB_MODE="true",
    )
    args = {"incident_id": 42, "action_id": 49, "targets": ["host-4471"], "approval_id": None}
    first = await run_pipeline(reg["soar_t_invoke"], rt, args)
    assert (
        first["error"]["code"] == "REQUIRE_APPROVAL" and first["disclaimer"] == IN_BAND_DISCLAIMER
    )
    token = first["approval_id"]
    second = await run_pipeline(reg["soar_t_invoke"], rt, {**args, "approval_id": token})
    assert (
        second["ok"]
        and second["disclaimer"] == IN_BAND_DISCLAIMER
        and "NOT HUMAN APPROVAL" in second["disclaimer"]
    )
    assert (await run_pipeline(reg["soar_t_invoke"], rt, {**args, "approval_id": token}))["error"][
        "code"
    ] == "DENY_APPROVAL"
    await rt.aclose()


async def test_disabled_mode_in_lab_executes_directly(
    reg, fake: FakeSoar, tmp_path: Path, policy: Path
):
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(policy),
        SOAR_APPROVAL_MODE="disabled",
        SOAR_LAB_MODE="true",
    )
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {"incident_id": 42, "action_id": 49, "targets": ["host-4471"], "approval_id": None},
    )
    assert out["ok"] and "approval" not in out
    await rt.aclose()


async def test_http_transport_denies_tier3_before_approval(
    reg, fake: FakeSoar, tmp_path: Path, policy: Path, keys
):
    rt = build_runtime(
        fake,
        tmp_path,
        "streamable-http",
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(policy),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(keys[1]),
        SOAR_HTTP_AUTH_TOKEN="t" * 32,
    )
    out = await run_pipeline(
        reg["soar_t_invoke"],
        rt,
        {
            "incident_id": 42,
            "action_id": 49,
            "targets": ["host-4471"],
            "approval_id": "APR-2026-0917-abcdef",
        },
    )
    assert out["error"]["code"] == "DENY_TRANSPORT" and fake.action_invocations == []
    assert (
        not list((tmp_path / "state" / "approvals").glob("*"))
        if (tmp_path / "state" / "approvals").exists()
        else True
    )
    await rt.aclose()


async def test_tier4_placeholder_requires_playbook_confirmation(
    reg, fake: FakeSoar, tmp_path: Path, keys
):
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_PLAYBOOK_DEPLOY="true",
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(keys[1]),
    )
    out = await run_pipeline(reg["soar_t_playbook"], rt, {"approval_id": None})
    assert out["error"]["code"] == "REQUIRE_APPROVAL"
    await rt.aclose()


# --------------------------------------------------------------- binding


async def test_bind_hides_runtime_and_registers_with_sdk(reg, fake: FakeSoar, tmp_path: Path):
    import inspect

    rt = build_runtime(fake, tmp_path)
    params = inspect.signature(bind(reg["soar_t_read"], rt)).parameters
    assert list(params) == ["incident_id", "verbose"] and params["incident_id"].annotation is int
    server = MCPServer("test")
    names = register_all(server, rt, reg)
    assert names == sorted(reg, key=lambda n: (int(reg[n].tier), n))
    tools = {t.name: t for t in await server.list_tools()}
    assert set(tools) == set(reg)
    assert (
        tools["soar_t_read"].annotations.read_only_hint is True
        and tools["soar_t_read"].output_schema is None
    )
    assert (
        tools["soar_t_invoke"].annotations.destructive_hint is True
        and tools["soar_t_comment"].annotations.destructive_hint is False
    )
    result = await server.call_tool("soar_t_read", {"incident_id": 42})
    assert json.loads(result.content[0].text)["data"]["id"] == 42
    with pytest.raises(ToolError):
        await server.call_tool("soar_t_read", {"incident_id": "forty-two"})
    await rt.aclose()


async def test_responses_are_redacted(reg, fake: FakeSoar, tmp_path: Path):
    """Step 12: even if SOAR echoed the credential into data, it never leaves the process."""
    rt = build_runtime(fake, tmp_path)
    fake.incident["name"] = f"leaky {SENTINEL}"
    out = await run_pipeline(reg["soar_t_read"], rt, {"incident_id": 42, "verbose": False})
    assert SENTINEL not in json.dumps(out) and "[REDACTED]" in out["data"]["name"]
    await rt.aclose()
