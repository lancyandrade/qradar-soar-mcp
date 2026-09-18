"""P1-13 keystone: every registered tool x every named config state x both transports.

Tools are enumerated FROM THE REGISTRY (``qradar_soar_mcp.tools.TOOL_REGISTRY``).
``EXPECTED`` is the hand-written decision table. A registered tool that is
missing from ``EXPECTED`` or from ``MINIMAL_ARGS`` **fails collection** (the
module-level check below raises at import), so a tool cannot be added without
deciding its permissions. Real tools arrive in P1-14 and fill the tables.

Config states are the fourteen named in 07 §3.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from tests.fake_soar import FakeSoar
from tests.tool_harness import base_env, write_keys, write_policy

CONFIG_STATES: dict[str, dict[str, str]] = {
    "default": {},
    "comments_only": {"SOAR_ALLOW_COMMENTS": "true"},
    "tier1": {"SOAR_ALLOW_COMMENTS": "true", "SOAR_ALLOW_ARTIFACTS": "true"},
    "tier2": {
        "SOAR_ALLOW_COMMENTS": "true",
        "SOAR_ALLOW_ARTIFACTS": "true",
        "SOAR_ALLOW_INCIDENT_WRITES": "true",
        "SOAR_ALLOW_TASK_WRITES": "true",
        "SOAR_ALLOW_INCIDENT_CLOSE": "true",
    },
    "tier2_no_close": {
        "SOAR_ALLOW_COMMENTS": "true",
        "SOAR_ALLOW_ARTIFACTS": "true",
        "SOAR_ALLOW_INCIDENT_WRITES": "true",
        "SOAR_ALLOW_TASK_WRITES": "true",
    },
    # ACTIONS without a policy cannot start (P1-02): the runtime is unusable.
    "actions_no_policy": {"SOAR_ALLOW_ACTIONS": "true", "SOAR_ACTION_POLICY_FILE": ""},
    "actions_with_policy": {"SOAR_ALLOW_ACTIONS": "true", "__policy__": "1"},
    "actions_destructive": {
        "SOAR_ALLOW_ACTIONS": "true",
        "SOAR_ALLOW_DESTRUCTIVE_ACTIONS": "true",
        "__policy__": "1",
    },
    "legacy_allow_writes": {"SOAR_ALLOW_WRITES": "true"},
    "playbook_draft": {"SOAR_ALLOW_PLAYBOOK_DRAFT": "true"},
    "playbook_export": {"SOAR_ALLOW_PLAYBOOK_DRAFT": "true", "SOAR_ALLOW_PLAYBOOK_EXPORT": "true"},
    "playbook_deploy": {"SOAR_ALLOW_PLAYBOOK_DEPLOY": "true", "SOAR_ALLOW_PLAYBOOK_CREATE": "true"},
    "playbook_enable": {"SOAR_ALLOW_PLAYBOOK_ENABLE": "true"},
    "kill_switch_active": {
        "SOAR_ALLOW_COMMENTS": "true",
        "SOAR_ALLOW_ARTIFACTS": "true",
        "SOAR_ALLOW_INCIDENT_WRITES": "true",
        "SOAR_ALLOW_TASK_WRITES": "true",
        "SOAR_ALLOW_INCIDENT_CLOSE": "true",
        "SOAR_ALLOW_ACTIONS": "true",
        "SOAR_ALLOW_DESTRUCTIVE_ACTIONS": "true",
        "__policy__": "1",
        "__kill_switch__": "1",
    },
}
TRANSPORTS = ("stdio", "streamable-http")

Cell = str | tuple[str, str]  # same on both transports, or (stdio, streamable-http)


def _row(**states: Cell) -> dict[str, dict[str, str]]:
    """One tool's decisions, named per state; both transports must be decided."""
    if set(states) != set(CONFIG_STATES):
        missing = sorted(set(CONFIG_STATES) - set(states))
        extra = sorted(set(states) - set(CONFIG_STATES))
        raise RuntimeError(f"EXPECTED row: missing states {missing}, unknown states {extra}")
    out: dict[str, dict[str, str]] = {}
    for state, cell in states.items():
        stdio, http = (cell, cell) if isinstance(cell, str) else cell
        out[state] = {"stdio": stdio, "streamable-http": http}
    return out


# Every Tier-0 tool: allowed everywhere except when the runtime refused to start.
_READ = _row(
    default="ALLOW",
    comments_only="ALLOW",
    tier1="ALLOW",
    tier2="ALLOW",
    tier2_no_close="ALLOW",
    actions_no_policy="DENY_CONFIG",
    actions_with_policy="ALLOW",
    actions_destructive="ALLOW",
    legacy_allow_writes="ALLOW",
    playbook_draft="ALLOW",
    playbook_export="ALLOW",
    playbook_deploy="ALLOW",
    playbook_enable="ALLOW",
    kill_switch_active="ALLOW",
)


def _flagged(flag_on_in: set[str]) -> dict[str, dict[str, str]]:
    """A Tier-1/2 tool gated by one flag: allowed only in the states that set it."""
    cells: dict[str, Cell] = {}
    for state in CONFIG_STATES:
        if state == "actions_no_policy":
            cells[state] = "DENY_CONFIG"
        elif state == "kill_switch_active":
            cells[state] = "DENY_KILL_SWITCH"
        elif state in flag_on_in:
            cells[state] = "ALLOW"
        else:
            cells[state] = "DENY_DISABLED"
    return _row(**cells)


_COMMENTS = _flagged({"comments_only", "tier1", "tier2", "tier2_no_close", "legacy_allow_writes"})
_ARTIFACTS = _flagged({"tier1", "tier2", "tier2_no_close", "legacy_allow_writes"})
_INCIDENT_WRITES = _flagged({"tier2", "tier2_no_close", "legacy_allow_writes"})
_TASK_WRITES = _flagged({"tier2", "tier2_no_close", "legacy_allow_writes"})
_INCIDENT_CLOSE = _flagged({"tier2", "legacy_allow_writes"})

# soar_invoke_action is exercised with action 49 ("EDR — Isolate Endpoint": Tier 3,
# require_approval, destructive in tests/tool_harness.POLICY_YAML). The flag alone is
# not enough: the destructive rule needs SOAR_ALLOW_DESTRUCTIVE_ACTIONS, then a human
# approval (REQUIRE_APPROVAL is the first-call result), and Tier 3 never runs over HTTP.
_INVOKE = _row(
    default="DENY_DISABLED",
    comments_only="DENY_DISABLED",
    tier1="DENY_DISABLED",
    tier2="DENY_DISABLED",
    tier2_no_close="DENY_DISABLED",
    actions_no_policy="DENY_CONFIG",
    actions_with_policy="DENY_DESTRUCTIVE",
    actions_destructive=("REQUIRE_APPROVAL", "DENY_TRANSPORT"),
    legacy_allow_writes="DENY_DISABLED",  # SOAR_ALLOW_WRITES never implies actions
    playbook_draft="DENY_DISABLED",
    playbook_export="DENY_DISABLED",
    playbook_deploy="DENY_DISABLED",
    playbook_enable="DENY_DISABLED",
    kill_switch_active=("DENY_KILL_SWITCH", "DENY_TRANSPORT"),
)

# EXPECTED[tool][state][transport] -> "ALLOW" or a decision code.
EXPECTED: dict[str, dict[str, dict[str, str]]] = {
    "soar_search_incidents": _READ,
    "soar_get_incident": _READ,
    "soar_list_artifacts": _READ,
    "soar_list_tasks": _READ,
    "soar_list_comments": _READ,
    "soar_list_attachments": _READ,
    "soar_list_users": _READ,
    "soar_describe_incident_fields": _READ,
    "soar_list_incident_actions": _READ,
    "soar_check_approval": _READ,
    "soar_get_incident_full": _READ,
    "soar_find_similar_incidents": _READ,
    "soar_add_comment": _COMMENTS,
    "soar_add_artifact": _ARTIFACTS,
    "soar_create_incident": _INCIDENT_WRITES,
    "soar_update_incident": _INCIDENT_WRITES,
    "soar_assign_incident": _INCIDENT_WRITES,
    "soar_close_incident": _INCIDENT_CLOSE,
    "soar_update_task_status": _TASK_WRITES,
    "soar_invoke_action": _INVOKE,
}
# Minimal valid arguments per tool, against the P1-01 fixtures (incident 42).
MINIMAL_ARGS: dict[str, dict[str, Any]] = {
    "soar_search_incidents": {},
    "soar_get_incident": {"incident_id": 42},
    "soar_list_artifacts": {"incident_id": 42},
    "soar_list_tasks": {"incident_id": 42},
    "soar_list_comments": {"incident_id": 42},
    "soar_list_attachments": {"incident_id": 42},
    "soar_list_users": {},
    "soar_describe_incident_fields": {},
    "soar_list_incident_actions": {"incident_id": 42},
    "soar_check_approval": {"approval_id": "APR-2026-0917-abcdef"},
    "soar_get_incident_full": {"incident_id": 42},
    "soar_find_similar_incidents": {"incident_id": 42},
    "soar_add_comment": {"incident_id": 42, "text": "matrix"},
    "soar_add_artifact": {
        "incident_id": 42,
        "artifact_type": "IP Address",
        "value": "198.51.100.7",
    },
    "soar_create_incident": {"name": "matrix", "discovered_date": 1758000000000},
    "soar_update_incident": {"incident_id": 42, "changes": {"severity_code": "High"}},
    "soar_assign_incident": {"incident_id": 42, "owner": "analyst.two"},
    "soar_close_incident": {
        "incident_id": 42,
        "resolution": "Resolved",
        "summary": "matrix",
        "custom_fields": {"root_cause": "matrix"},
    },
    "soar_update_task_status": {"incident_id": 42, "task_id": 9001, "status": "closed"},
    "soar_invoke_action": {"incident_id": 42, "action_id": 49},
}


def _collection_check() -> None:
    registered = set(TOOL_REGISTRY)
    missing_expected = registered - set(EXPECTED)
    missing_args = registered - set(MINIMAL_ARGS)
    extra = (set(EXPECTED) | set(MINIMAL_ARGS)) - registered
    problems = []
    if missing_expected:
        problems.append(f"tools without an EXPECTED entry: {sorted(missing_expected)}")
    if missing_args:
        problems.append(f"tools without MINIMAL_ARGS: {sorted(missing_args)}")
    if extra:
        problems.append(f"table entries for unregistered tools: {sorted(extra)}")
    for tool, states in EXPECTED.items():
        if set(states) != set(CONFIG_STATES):
            problems.append(f"{tool}: EXPECTED must name every config state")
        for state, per_transport in states.items():
            if set(per_transport) != set(TRANSPORTS):
                problems.append(f"{tool}/{state}: EXPECTED must name both transports")
    if problems:
        raise RuntimeError("permission matrix is incomplete: " + "; ".join(problems))


_collection_check()


def _cases():
    for tool in sorted(TOOL_REGISTRY):
        for state in CONFIG_STATES:
            for transport in TRANSPORTS:
                yield pytest.param(tool, state, transport, id=f"{tool}-{state}-{transport}")


def build_state(tmp_path: Path, state: str, transport: str) -> tuple[Runtime, FakeSoar]:
    spec = dict(CONFIG_STATES[state])
    env = base_env(tmp_path)
    if spec.pop("__policy__", None):
        env["SOAR_ACTION_POLICY_FILE"] = str(write_policy(tmp_path))
    if spec.pop("__kill_switch__", None):
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        (tmp_path / "state" / "HALT").write_text("")
    _, public = write_keys(tmp_path)
    env["SOAR_APPROVAL_PUBLIC_KEY_FILE"] = str(public)
    if transport == "streamable-http":
        env["SOAR_HTTP_AUTH_TOKEN"] = "t" * 32
    env.update(spec)
    fake = FakeSoar()
    return Runtime.build(env, transport=transport), fake


@pytest.mark.parametrize(("tool", "state", "transport"), list(_cases()))
async def test_decision(tool: str, state: str, transport: str, tmp_path: Path, monkeypatch):
    import respx

    from tests.fake_soar import BASE_URL

    rt, fake = build_state(tmp_path, state, transport)
    expected = EXPECTED[tool][state][transport]
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=fake.handler)
        out = await run_pipeline(TOOL_REGISTRY[tool], rt, dict(MINIMAL_ARGS[tool]))
        await rt.aclose()
    if expected == "ALLOW":
        assert out["ok"] is True, out
    else:
        assert out["ok"] is False, out
        assert out["error"]["code"] == expected, out
    # A denied call never mutates SOAR (POST to query_paged is a read).
    if expected != "ALLOW":
        assert [r for r in fake.mutating_requests if not r.path.endswith("/query_paged")] == [], (
            f"{tool} in {state}/{transport} was denied but reached SOAR"
        )


def minimal_valid_args(tool: str) -> Mapping[str, Any]:
    return MINIMAL_ARGS[tool]
