"""T4 — lab read-only (07 §2, §7.5; docs/lab-validation-plan.md §3).

Runs only when ``SOAR_TEST_ENABLE`` includes ``lab`` and the guard accepts the
target (see ``tests/lab/guard.py``). Against org 201 with a read-only key, under the
**default** configuration, every request through the read-only transport guard.

Never printed: response data. Assertion messages carry tool names, error codes and
request paths only, never incident content or a credential.
"""

from __future__ import annotations

import inspect
import json
from typing import Any

import pytest

from qradar_soar_mcp.config import CAPABILITY_FLAGS
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from tests.lab.guard import LabTarget, ReadOnlyTransport
from tests.test_permission_matrix import MINIMAL_ARGS

pytestmark = pytest.mark.lab


def _needs_arguments(name: str) -> bool:
    params = inspect.signature(TOOL_REGISTRY[name].func).parameters.values()
    return any(p.name != "rt" and p.default is inspect.Parameter.empty for p in params)


READ_TOOLS_NO_ARGS = sorted(
    n for n, s in TOOL_REGISTRY.items() if int(s.tier) == 0 and not _needs_arguments(n)
)
INCIDENT_READS = (
    "soar_get_incident",
    "soar_list_artifacts",
    "soar_list_tasks",
    "soar_list_comments",
    "soar_list_attachments",
    "soar_list_incident_actions",
    "soar_get_incident_full",
    "soar_find_similar_incidents",
)
MUTATING_TOOLS = sorted(n for n, s in TOOL_REGISTRY.items() if int(s.tier) >= 1)


async def _call(
    rt: Runtime, target: LabTarget, name: str, args: dict[str, Any] | None = None
) -> dict[str, Any]:
    out = await run_pipeline(TOOL_REGISTRY[name], rt, dict(args or {}))
    assert target.api_key_secret not in json.dumps(out), f"{name}: the API secret is in the output"
    return out


def _code(out: dict[str, Any]) -> str | None:
    return (out.get("error") or {}).get("code")


async def test_lab_runtime_is_deny_by_default(t4_runtime, lab_target: LabTarget):
    rt, _ = t4_runtime
    assert rt.settings is not None
    assert [f for f in CAPABILITY_FLAGS if rt.settings.capability_enabled(f)] == []


@pytest.mark.parametrize("name", READ_TOOLS_NO_ARGS)
async def test_read_tool_answers(name: str, t4_runtime, lab_target: LabTarget):
    rt, _ = t4_runtime
    out = await _call(rt, lab_target, name)
    assert out["ok"] is True, f"{name}: {_code(out)}"


async def test_incident_scoped_reads(t4_runtime, lab_target: LabTarget):
    rt, _ = t4_runtime
    found = await _call(rt, lab_target, "soar_search_incidents", {"length": 1})
    assert found["ok"] is True, _code(found)
    incidents = found["data"]["incidents"]
    assert incidents, "org has no incident to read; T4 needs the seeded lab data of org 201"
    incident_id = incidents[0]["id"]
    for name in INCIDENT_READS:
        out = await _call(rt, lab_target, name, {"incident_id": incident_id})
        assert out["ok"] is True, f"{name}: {_code(out)}"


@pytest.mark.parametrize("object_type", ["incident", "task", "artifact"])
async def test_field_definitions(object_type: str, t4_runtime, lab_target: LabTarget):
    rt, _ = t4_runtime
    out = await _call(rt, lab_target, "soar_list_fields", {"object_type": object_type})
    assert out["ok"] is True, f"soar_list_fields({object_type}): {_code(out)}"


async def test_every_mutating_tool_denies_and_sends_nothing(t4_runtime, lab_target: LabTarget):
    """The live counterpart of tests/test_chokepoint.py: default config, every Tier ≥ 1
    tool denied before any request, so the wire sees nothing from these calls."""
    rt, guard = t4_runtime
    sent_before = list(guard.sent)
    for name in MUTATING_TOOLS:
        out = await _call(rt, lab_target, name, dict(MINIMAL_ARGS[name]))
        assert out["ok"] is False and str(_code(out)).startswith("DENY_"), f"{name}: {_code(out)}"
    assert guard.sent == sent_before, (
        f"requests sent while denying: {guard.sent[len(sent_before) :]}"
    )
    assert guard.blocked == []


async def test_guard_is_installed(t4_runtime, lab_target: LabTarget):
    rt, guard = t4_runtime
    assert isinstance(guard, ReadOnlyTransport)
    assert rt.client is not None
