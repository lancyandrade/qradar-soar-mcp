"""``enforce()``: the pure permission gate (P1-05; 01 §4 steps 2-8).

A pure function of ``(tool, tier, capability, config, transport, policy)`` so
the whole permission matrix is table-testable with no network (07 §3).
Returns an explicit :class:`Decision` whose ``reason`` names the exact env var
to set when something is off.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.security.tiers import (
    APPROVAL_REQUIRED_FROM,
    CAPABILITY_TIERS,
    HTTP_DENIED_FROM,
    Tier,
)


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """The per-target classification ``action_policy.py`` hands to :func:`enforce`."""

    tier: Tier
    decision: str  # allow | deny | require_approval
    destructive: bool
    rule: str
    reason: str
    constraint_violation: str | None = None
    subject: str | None = None  # the classified thing's own name, for plans and audit

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": int(self.tier),
            "decision": self.decision,
            "destructive": self.destructive,
            "rule": self.rule,
            "reason": self.reason,
            "constraint_violation": self.constraint_violation,
            "subject": self.subject,
        }


class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Code(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY_CONFIG = "DENY_CONFIG"
    DENY_DISABLED = "DENY_DISABLED"
    DENY_TIER5 = "DENY_TIER5"
    DENY_POLICY = "DENY_POLICY"
    DENY_DESTRUCTIVE = "DENY_DESTRUCTIVE"
    DENY_TARGET = "DENY_TARGET"
    DENY_TRANSPORT = "DENY_TRANSPORT"
    DENY_KILL_SWITCH = "DENY_KILL_SWITCH"
    DENY_RATE_LIMIT = "DENY_RATE_LIMIT"
    DENY_MUTATION_CAP = "DENY_MUTATION_CAP"
    DENY_BREAKER = "DENY_BREAKER"
    DENY_APPROVAL = "DENY_APPROVAL"
    DENY_AUDIT = "DENY_AUDIT"
    DENY_UNSUPPORTED = "DENY_UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: Outcome
    code: Code
    reason: str
    tier: Tier
    capability: str | None = None
    policy_rule: str | None = None
    destructive: bool = False

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    @property
    def denied(self) -> bool:
        return self.outcome is Outcome.DENY

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": str(self.outcome),
            "code": str(self.code),
            "reason": self.reason,
            "tier": int(self.tier),
            "capability": self.capability,
            "policy_rule": self.policy_rule,
            "destructive": self.destructive,
        }


def deny(code: Code, reason: str, tier: Tier, **extra: object) -> Decision:
    return Decision(Outcome.DENY, code, reason, tier, **extra)  # type: ignore[arg-type]


def enforce(
    *,
    tool: str,
    tier: Tier,
    capability: str | None,
    config: Settings | None,
    transport: str,
    policy: PolicyResult | None = None,
    unsupported: str | None = None,
) -> Decision:
    """Steps 3-6 and 8 of 01 §4: flag → policy → tier → transport → approval.

    ``policy`` is the per-target classification for ``soar_invoke_action``
    (02 §1.1): it sets the *effective* tier and may itself deny or require
    approval. Rate/bulk gates (step 7) live in ``limits.py`` and run after this.

    ``unsupported`` is the fixed refusal of a tool whose SOAR request contract is
    not verified for the API this release targets (08 §21). Such a tool is gated
    like any other, then denied after the transport gate and before approval,
    so its refusal is an ordinary audited denial and nothing reaches SOAR.
    """
    if config is None:
        return deny(Code.DENY_CONFIG, "configuration failed to load; nothing is permitted", tier)

    effective = tier
    rule: str | None = None
    destructive = False

    # Step 3: the capability flag for this tool.
    if capability is not None:
        if capability not in CAPABILITY_TIERS:
            return deny(
                Code.DENY_CONFIG, f"{tool} declares unknown capability {capability!r}", tier
            )
        if not config.capability_enabled(capability):
            return deny(
                Code.DENY_DISABLED,
                f"{tool} is disabled; set {capability}=true to enable it",
                tier,
                capability=capability,
            )
    elif tier > Tier.READ:
        return deny(
            Code.DENY_CONFIG, f"{tool} is tier {int(tier)} but declares no capability", tier
        )

    # Step 4: per-target classification.
    if policy is not None:
        effective = policy.tier
        rule = policy.rule
        destructive = policy.destructive
        if policy.constraint_violation:
            return deny(
                Code.DENY_TARGET,
                f"{tool}: {policy.constraint_violation} (policy rule {rule!r})",
                effective,
                capability=capability,
                policy_rule=rule,
                destructive=destructive,
            )
        if policy.decision == "deny":
            return deny(
                Code.DENY_POLICY,
                f"{tool}: action denied by policy rule {rule!r}: {policy.reason}",
                effective,
                capability=capability,
                policy_rule=rule,
                destructive=destructive,
            )
        if destructive and not config.allow_destructive_actions:
            return deny(
                Code.DENY_DESTRUCTIVE,
                f"{tool}: rule {rule!r} classifies this action as destructive; "
                "set SOAR_ALLOW_DESTRUCTIVE_ACTIONS=true to permit it",
                effective,
                capability=capability,
                policy_rule=rule,
                destructive=True,
            )

    # Step 5: Tier 5 is not a permission level.
    if effective >= Tier.HIGH_RISK:
        return deny(
            Code.DENY_TIER5,
            f"{tool}: effective tier 5 has no enabling flag and never will (02 §1.2)",
            effective,
            capability=capability,
            policy_rule=rule,
            destructive=destructive,
        )

    # Step 6: transport gate.
    if transport != "stdio" and effective >= HTTP_DENIED_FROM:
        return deny(
            Code.DENY_TRANSPORT,
            f"{tool}: tier {int(effective)} is hard-disabled over the HTTP transport; use stdio",
            effective,
            capability=capability,
            policy_rule=rule,
            destructive=destructive,
        )

    # Step 6b: a tool whose SOAR request contract is unverified never runs (08 §21).
    if unsupported is not None:
        return deny(
            Code.DENY_UNSUPPORTED,
            unsupported,
            effective,
            capability=capability,
            policy_rule=rule,
            destructive=destructive,
        )

    # Step 8: does this call need a human?
    needs_approval = False
    if policy is not None and policy.decision == "require_approval":
        needs_approval = True
    if effective >= APPROVAL_REQUIRED_FROM:
        if effective >= Tier.AUTOMATION:
            needs_approval = needs_approval or config.require_playbook_confirmation
        else:
            needs_approval = needs_approval or config.require_action_confirmation
    if needs_approval and config.approval_mode != "disabled":
        return Decision(
            Outcome.REQUIRE_APPROVAL,
            Code.REQUIRE_APPROVAL,
            f"{tool}: tier {int(effective)} requires approval ({config.approval_mode})",
            effective,
            capability=capability,
            policy_rule=rule,
            destructive=destructive,
        )

    return Decision(
        Outcome.ALLOW,
        Code.ALLOW,
        "allowed",
        effective,
        capability=capability,
        policy_rule=rule,
        destructive=destructive,
    )
