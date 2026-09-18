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

# EXPECTED[tool][state][transport] -> "ALLOW" or a decision code. Filled in P1-14/P1-15.
EXPECTED: dict[str, dict[str, dict[str, str]]] = {}
# Minimal valid arguments per tool, against the P1-01 fixtures. Filled in P1-14/P1-15.
MINIMAL_ARGS: dict[str, dict[str, Any]] = {}


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
