"""Manual actions and approvals (08 §3; 02 §1.1, §4).

``soar_invoke_action`` has no fixed tier: the action policy classifies the
*target* action on every call, and that classification is what ``enforce()``
gates on. Phase 1 invokes with the incident-scoped body ``{"action_id": N}``
only, so an action whose ``object_type`` is not ``incident`` is refused (an
artifact-scoped invocation is an open question, not a guess).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from qradar_soar_mcp.errors import SoarConfigError, SoarNotFoundError, SoarValidationError
from qradar_soar_mcp.security.permissions import PolicyResult
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools.registry import ToolResult, soar_tool
from qradar_soar_mcp.tools.runtime import Runtime

INVOCABLE_OBJECT_TYPE = "incident"


@soar_tool(name="soar_list_incident_actions", tier=Tier.READ)
async def soar_list_incident_actions(rt: Runtime, incident_id: int) -> ToolResult:
    """Manual actions available on one incident, each with its policy classification
    (tier, decision, destructive) when SOAR_ALLOW_ACTIONS is enabled. Only actions whose
    object_type is "incident" can be invoked in this release."""
    actions = await rt.require_client().actions.list_for_incident(incident_id)
    rows: list[dict[str, Any]] = []
    for action in actions:
        row = dict(action)
        row["invocable"] = action.get("object_type") == INVOCABLE_OBJECT_TYPE
        if rt.policy is not None:
            result = rt.policy.classify(
                action_name=str(action["name"]), action_id=int(action["id"])
            )
            row["policy"] = {
                "tier": int(result.tier),
                "decision": result.decision,
                "destructive": result.destructive,
                "rule": result.rule,
            }
        else:
            row["policy"] = None
        rows.append(row)
    return ToolResult(
        data={
            "incident_id": incident_id,
            "count": len(rows),
            "policy_loaded": rt.policy is not None,
            "actions": rows,
        }
    )


async def _classify_invoke(rt: Runtime, args: Mapping[str, Any]) -> PolicyResult:
    """Resolve the action on the incident and classify it (pipeline step 4)."""
    if rt.policy is None:
        raise SoarConfigError("SOAR_ALLOW_ACTIONS is enabled but no action policy is loaded")
    incident_id, action_id = int(args["incident_id"]), int(args["action_id"])
    actions = await rt.require_client().actions.list_for_incident(incident_id)
    action = next((a for a in actions if a.get("id") == action_id), None)
    if action is None:
        raise SoarNotFoundError(
            f"Not found: action {action_id} is not available on incident {incident_id}",
            status=404,
        )
    if action.get("object_type") != INVOCABLE_OBJECT_TYPE:
        raise SoarValidationError(
            f"action {action_id} is scoped to {action.get('object_type')!r}; only "
            "incident-scoped actions can be invoked in this release"
        )
    name = str(action["name"])
    return replace(rt.policy.classify(action_name=name, action_id=action_id), subject=name)


def _describe_invoke(args: Mapping[str, Any], policy: PolicyResult | None) -> dict[str, Any]:
    """The plan a human approves. Deliberately no incident text: names and
    descriptions are attacker-writable and the approver's terminal is not a
    place to render them."""
    incident_id, action_id = args.get("incident_id"), args.get("action_id")
    name = policy.subject if policy is not None else None
    label = f"{name!r} (id {action_id})" if name else f"id {action_id}"
    return {
        "target": {"incident_id": incident_id, "action_id": action_id},
        "action": {"id": action_id, "name": name},
        "plan": f"Invoke manual action {label} on incident {incident_id}",
    }


@soar_tool(
    name="soar_invoke_action",
    tier=Tier.CONTROL,
    capability="SOAR_ALLOW_ACTIONS",
    classify=_classify_invoke,
    describe=_describe_invoke,
)
async def soar_invoke_action(
    rt: Runtime, incident_id: int, action_id: int, approval_id: str | None = None
) -> ToolResult:
    """Invoke one manual action on an incident (ids from soar_list_incident_actions).
    The action policy sets the tier per action; Tier 3 needs a human approval: the first
    call returns an approval reference, a human approves it out of band, then repeat the
    identical call with ``approval_id``. Never retry in a loop. Not available over HTTP.
    SOAR runs the action asynchronously; its outcome is not observable here."""
    out = await rt.require_client().actions.invoke(incident_id, action_id)
    return ToolResult(
        data={**out, "note": "accepted by SOAR; the action runs asynchronously"},
        target={"incident_id": incident_id, "action_id": action_id},
        soar_response={"accepted": True},
    )


@soar_tool(name="soar_check_approval", tier=Tier.READ)
async def soar_check_approval(rt: Runtime, approval_id: str) -> ToolResult:
    """State of an approval reference (pending, approved, consumed, rejected, expired,
    unknown). Poll this instead of retrying the action; then repeat the identical call
    with ``approval_id`` once it is approved."""
    if rt.broker is None:
        raise SoarConfigError("approval broker unavailable")
    return ToolResult(data=rt.broker.status(approval_id))
