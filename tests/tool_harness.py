"""Shared helpers for the chokepoint, matrix and tool suites.

``LOCAL_REGISTRY`` is a test-local tool set — one representative tool per tier
plus an invoke-style tool with per-target classification — so the pipeline
can be proven before the real tools exist (08 §2.4). The real registry is
exercised in test_tools.py and test_permission_matrix.py.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from qradar_soar_mcp.security.approvals import generate_keypair
from qradar_soar_mcp.security.permissions import PolicyResult
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import Runtime, ToolResult, ToolSpec, soar_tool
from tests.conftest import connection_env
from tests.fake_soar import FakeSoar

POLICY_YAML = """\
version: 1
default: {tier: 5, decision: deny}
actions:
  - match: { name: "Send Analyst Digest" }
    tier: 1
    decision: allow
  - match: { name: "Escalate to Tier 2" }
    tier: 2
    decision: allow
  - match: { name: "EDR — Isolate Endpoint" }
    tier: 3
    decision: require_approval
    destructive: true
    constraints:
      deny_values: ["dc01.example.internal"]
  - match: { name: "Firewall — Block IP" }
    tier: 3
    decision: require_approval
    destructive: true
    constraints:
      artifact_types: ["IP Address"]
      deny_values: ["10.0.0.0/8"]
  - match: { name: "Purge Mailbox" }
    tier: 5
    decision: deny
"""


def write_policy(directory: Path) -> Path:
    path = directory / "action_policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return path


def write_keys(directory: Path) -> tuple[Path, Path]:
    private, public = directory / "keys" / "approval.key", directory / "keys" / "approval.pub"
    generate_keypair(private, public)
    return private, public


def base_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    """Connection + state paths under tmp_path; nothing enabled unless overridden."""
    env = connection_env(
        SOAR_AUDIT_LOG_PATH=str(tmp_path / "state" / "audit.jsonl"),
        SOAR_APPROVAL_BROKER_PATH=str(tmp_path / "state" / "approvals"),
        SOAR_KILL_SWITCH_FILE=str(tmp_path / "state" / "HALT"),
        SOAR_SNAPSHOT_DIR=str(tmp_path / "state" / "snapshots"),
    )
    env.update(overrides)
    return env


def build_runtime(
    fake: FakeSoar, tmp_path: Path, transport: str = "stdio", **overrides: str
) -> Runtime:
    return Runtime.build(base_env(tmp_path, **overrides), transport=transport)


def audit_records(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "state" / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# ----------------------------------------------------------- local tools
async def _classify_action(rt: Runtime, args: Mapping[str, Any]) -> PolicyResult:
    assert rt.policy is not None
    client = rt.require_client()
    actions = await client.actions.list_for_incident(int(args["incident_id"]))
    action = next((a for a in actions if a["id"] == int(args["action_id"])), None)
    if action is None:
        from qradar_soar_mcp.errors import SoarNotFoundError

        raise SoarNotFoundError(
            f"Not found: action {args['action_id']} on incident {args['incident_id']}", status=404
        )
    return rt.policy.classify(
        action_name=str(action["name"]),
        action_id=int(action["id"]),
        target_values=[str(v) for v in args.get("targets") or []],
    )


def _describe_action(args: Mapping[str, Any], policy: PolicyResult | None) -> dict[str, Any]:
    return {
        "target": {"incident_id": args.get("incident_id"), "action_id": args.get("action_id")},
        "action": {"id": args.get("action_id"), "name": policy.rule if policy else None},
        "plan": f"invoke action {args.get('action_id')} on incident {args.get('incident_id')}",
    }


def make_local_registry() -> dict[str, ToolSpec]:
    reg: dict[str, ToolSpec] = {}

    @soar_tool(name="soar_t_read", tier=Tier.READ, registry=reg)
    async def t_read(rt: Runtime, incident_id: int, verbose: bool = False) -> ToolResult:
        """read one incident"""
        inc = await rt.require_client().incidents.get(incident_id)
        return ToolResult(data={"id": inc["id"], "name": inc["name"]})

    @soar_tool(
        name="soar_t_comment",
        tier=Tier.DOCUMENTATION,
        capability="SOAR_ALLOW_COMMENTS",
        registry=reg,
    )
    async def t_comment(rt: Runtime, incident_id: int, text: str) -> ToolResult:
        """add a comment"""
        created = await rt.require_client().comments.add(incident_id, text)
        return ToolResult(
            data={"comment_id": created["id"]},
            target={"incident_id": incident_id},
            post_image=created,
        )

    @soar_tool(
        name="soar_t_update",
        tier=Tier.MODIFICATION,
        capability="SOAR_ALLOW_INCIDENT_WRITES",
        registry=reg,
    )
    async def t_update(rt: Runtime, incident_id: int, field_name: str, value: str) -> ToolResult:
        """update one field"""
        out = await rt.require_client().incidents.apply_patch(incident_id, {field_name: value})
        return ToolResult(
            data={"changed": out.changes},
            target={"incident_id": incident_id},
            pre_image=out.pre_image,
            post_image=out.post_image,
        )

    @soar_tool(
        name="soar_t_close",
        tier=Tier.MODIFICATION,
        capability="SOAR_ALLOW_INCIDENT_CLOSE",
        registry=reg,
    )
    async def t_close(rt: Runtime, incident_id: int) -> ToolResult:
        """close an incident"""
        out = await rt.require_client().incidents.close(
            incident_id,
            resolution="Resolved",
            summary="done",
            extra_fields={"properties.root_cause": "x"},
        )
        return ToolResult(
            data={"closed": True},
            target={"incident_id": incident_id},
            pre_image=out.pre_image,
            post_image=out.post_image,
        )

    @soar_tool(
        name="soar_t_invoke",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        classify=_classify_action,
        describe=_describe_action,
        registry=reg,
    )
    async def t_invoke(
        rt: Runtime,
        incident_id: int,
        action_id: int,
        targets: list[str] | None = None,
        approval_id: str | None = None,
    ) -> ToolResult:
        """invoke an action"""
        out = await rt.require_client().actions.invoke(incident_id, action_id)
        return ToolResult(
            data=out,
            target={"incident_id": incident_id, "action_id": action_id},
            soar_response={"invoked": True},
        )

    @soar_tool(
        name="soar_t_playbook",
        tier=Tier.AUTOMATION,
        capability="SOAR_ALLOW_PLAYBOOK_DEPLOY",
        describe=lambda a, p: {"target": {}, "plan": "deploy"},
        registry=reg,
    )
    async def t_playbook(rt: Runtime, approval_id: str | None = None) -> ToolResult:
        """a tier-4 placeholder that never reaches SOAR"""
        return ToolResult(data={"deployed": False})

    @soar_tool(name="soar_t_crash", tier=Tier.READ, registry=reg)
    async def t_crash(rt: Runtime) -> ToolResult:
        """crash"""
        from tests.conftest import SENTINEL

        raise RuntimeError(f"boom {SENTINEL}")

    return reg
