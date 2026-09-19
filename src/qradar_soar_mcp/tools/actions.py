"""Manual actions and approvals (08 §3; 02 §1.1, §4), reconciled with the verified
QRadar SOAR 51.0.9.0.20848 API by P1-CORR-01 (08 §21).

``soar_list_incident_actions`` lists the actions the incident object carries,
each with the operator policy's classification. None is invocable.

``soar_invoke_action`` keeps its tier, capability flag, ``describe()`` and
``approval_id`` parameter, but no verified invocation contract exists: the
Phase-1 ``POST /incidents/{id}/action_invocations`` is undocumented on that
version, and inventing a replacement is forbidden (08 §4). It is declared
``unsupported``, so ``enforce()`` refuses every call with ``DENY_UNSUPPORTED``
after the flag, config and transport gates and before approval: an ordinary
audited ``DECISION_DENIED``, with no approval requested or consumed and nothing
sent to SOAR. It declares no classifier, because there is no verified target to
classify and a classifier would run before that denial. The body refuses the
same way in case it is ever reached.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from qradar_soar_mcp.errors import SoarConfigError, SoarUnsupportedError
from qradar_soar_mcp.security.permissions import PolicyResult
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools.registry import ToolResult, soar_tool
from qradar_soar_mcp.tools.runtime import Runtime

INVOCATION_UNVERIFIED = (
    "Unsupported: manual-action invocation is not verified for the SOAR REST API this "
    "release targets (QRadar SOAR 51.0.9), so soar_invoke_action is unavailable. Nothing "
    "was sent to SOAR and no approval was requested. Do not retry; run the action from "
    "the SOAR UI."
)


INVOCATION_DETAIL = (
    "P1-CORR-01 D4: POST /incidents/{id}/action_invocations is undocumented on "
    "51.0.9.0.20848 and no verified replacement exists (docs/soar-api-verified.md §3)"
)


@soar_tool(name="soar_list_incident_actions", tier=Tier.READ)
async def soar_list_incident_actions(rt: Runtime, incident_id: int) -> ToolResult:
    """Manual actions the incident carries (id, name), each with its policy classification
    (tier, decision, destructive) when SOAR_ALLOW_ACTIONS is enabled. None can be invoked in
    this release (``invocable`` is always false; see soar_invoke_action)."""
    actions = await rt.require_client().actions.list_for_incident(incident_id)
    rows: list[dict[str, Any]] = []
    for action in actions:
        row: dict[str, Any] = {**action, "invocable": False}
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
    describe=_describe_invoke,
    unsupported=INVOCATION_UNVERIFIED,
)
async def soar_invoke_action(
    rt: Runtime, incident_id: int, action_id: int, approval_id: str | None = None
) -> ToolResult:
    """UNAVAILABLE in this release: every call is refused with DENY_UNSUPPORTED without
    contacting SOAR, because SOAR's manual-action invocation contract is not verified for
    the API this release targets. Do not retry; a human runs the action from the SOAR UI.
    The contract is kept for when invocation is verified: the action policy sets the tier
    per action, Tier 3 needs an out-of-band human approval, and it never runs over HTTP."""
    raise SoarUnsupportedError(INVOCATION_UNVERIFIED, detail=INVOCATION_DETAIL)


@soar_tool(name="soar_check_approval", tier=Tier.READ)
async def soar_check_approval(rt: Runtime, approval_id: str) -> ToolResult:
    """State of an approval reference (pending, approved, consumed, rejected, expired,
    unknown). Poll this instead of retrying the action; then repeat the identical call
    with ``approval_id`` once it is approved."""
    if rt.broker is None:
        raise SoarConfigError("approval broker unavailable")
    return ToolResult(data=rt.broker.status(approval_id))
