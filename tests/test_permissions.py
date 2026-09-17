"""P1-05: tiers, the capability→tier map, and the pure enforce() gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from qradar_soar_mcp.config import CAPABILITY_FLAGS, Settings
from qradar_soar_mcp.security.permissions import Code, Decision, Outcome, PolicyResult, enforce
from qradar_soar_mcp.security.tiers import CAPABILITY_TIERS, Tier, tier_of_capability


@pytest.fixture
def policy_file(tmp_path: Path) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\n", encoding="utf-8")
    return str(p)


def _settings(policy_file: str, **flags: str) -> Settings:
    env = dict(flags)
    if env.get("SOAR_ALLOW_ACTIONS") == "true":
        env.setdefault("SOAR_ACTION_POLICY_FILE", policy_file)
    return Settings.load(env)


def _policy(
    tier: int, decision: str = "allow", destructive: bool = False, violation: str | None = None
) -> PolicyResult:
    return PolicyResult(Tier(tier), decision, destructive, "rule", "r", violation)


# ------------------------------------------------------------------ tiers


def test_tiers_and_capability_map():
    assert list(Tier) == [
        Tier.READ,
        Tier.DOCUMENTATION,
        Tier.MODIFICATION,
        Tier.CONTROL,
        Tier.AUTOMATION,
        Tier.HIGH_RISK,
    ]
    assert set(CAPABILITY_TIERS) == set(CAPABILITY_FLAGS)
    assert tier_of_capability("SOAR_ALLOW_COMMENTS") is Tier.DOCUMENTATION
    assert tier_of_capability("SOAR_ALLOW_ACTIONS") is Tier.CONTROL
    with pytest.raises(ValueError, match="not a capability"):
        tier_of_capability("SOAR_ALLOW_TIER5")
    assert not any(t is Tier.HIGH_RISK for t in CAPABILITY_TIERS.values())


# ----------------------------------------------------------------- enforce


def test_no_config_denies_everything_including_reads():
    d = enforce(
        tool="soar_get_incident", tier=Tier.READ, capability=None, config=None, transport="stdio"
    )
    assert d.denied and d.code is Code.DENY_CONFIG


def test_reads_need_no_flag_on_any_transport(policy_file):
    for transport in ("stdio", "streamable-http"):
        d = enforce(
            tool="soar_get_incident",
            tier=Tier.READ,
            capability=None,
            config=Settings.load({}),
            transport=transport,
        )
        assert d.allowed and d.tier is Tier.READ


@pytest.mark.parametrize("capability", CAPABILITY_FLAGS)
def test_default_config_denies_every_flagged_tool_naming_the_var(capability: str):
    tier = CAPABILITY_TIERS[capability]
    d = enforce(
        tool="t", tier=tier, capability=capability, config=Settings.load({}), transport="stdio"
    )
    assert d.denied and d.code is Code.DENY_DISABLED
    assert f"{capability}=true" in d.reason


def test_add_comment_denial_names_soar_allow_comments():
    d = enforce(
        tool="soar_add_comment",
        tier=Tier.DOCUMENTATION,
        capability="SOAR_ALLOW_COMMENTS",
        config=Settings.load({}),
        transport="stdio",
    )
    assert "SOAR_ALLOW_COMMENTS" in d.reason and d.code is Code.DENY_DISABLED


@pytest.mark.parametrize(
    "capability", [c for c in CAPABILITY_FLAGS if CAPABILITY_TIERS[c] <= Tier.MODIFICATION]
)
def test_flag_enables_tier_one_and_two_without_approval(capability: str, policy_file):
    d = enforce(
        tool="t",
        tier=CAPABILITY_TIERS[capability],
        capability=capability,
        config=_settings(policy_file, **{capability: "true"}),
        transport="stdio",
    )
    assert d.allowed and d.code is Code.ALLOW


def test_flagged_tool_without_capability_is_a_config_error():
    d = enforce(
        tool="t",
        tier=Tier.DOCUMENTATION,
        capability=None,
        config=Settings.load({}),
        transport="stdio",
    )
    assert d.code is Code.DENY_CONFIG
    d = enforce(
        tool="t",
        tier=Tier.DOCUMENTATION,
        capability="SOAR_ALLOW_NOPE",
        config=Settings.load({}),
        transport="stdio",
    )
    assert d.code is Code.DENY_CONFIG


# ------------------------------------------------------- policy classification


def test_invoke_action_uses_policy_tier(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_ACTIONS="true")
    tier1 = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(1),
    )
    assert tier1.allowed and tier1.tier is Tier.DOCUMENTATION and tier1.policy_rule == "rule"
    tier3 = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(3, "require_approval"),
    )
    assert tier3.outcome is Outcome.REQUIRE_APPROVAL and tier3.tier is Tier.CONTROL


def test_actions_flag_still_required_for_tier1_action(policy_file):
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=Settings.load({}),
        transport="stdio",
        policy=_policy(1),
    )
    assert d.code is Code.DENY_DISABLED and "SOAR_ALLOW_ACTIONS" in d.reason


def test_policy_deny_and_tier5(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_ACTIONS="true", SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true")
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(2, "deny"),
    )
    assert d.code is Code.DENY_POLICY and "rule" in d.reason
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(5, "allow"),
    )
    assert d.code is Code.DENY_TIER5


def test_destructive_requires_its_own_flag(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_ACTIONS="true")
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(3, "require_approval", destructive=True),
    )
    assert d.code is Code.DENY_DESTRUCTIVE and "SOAR_ALLOW_DESTRUCTIVE_ACTIONS" in d.reason
    cfg2 = _settings(policy_file, SOAR_ALLOW_ACTIONS="true", SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true")
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg2,
        transport="stdio",
        policy=_policy(3, "require_approval", destructive=True),
    )
    assert d.outcome is Outcome.REQUIRE_APPROVAL and d.destructive


def test_constraint_violation_denies_even_with_everything_on(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_ACTIONS="true", SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true")
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(
            3,
            "allow",
            violation="target '<private address>' is denied by deny_values entry '10.0.0.0/8'",
        ),
    )
    assert d.code is Code.DENY_TARGET and "10.0.0.0/8" in d.reason


# --------------------------------------------------------------- transport


@pytest.mark.parametrize("tier", [Tier.CONTROL, Tier.AUTOMATION])
def test_http_denies_tier_three_and_up_regardless_of_flags(tier: Tier, policy_file):
    cfg = _settings(
        policy_file,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_PLAYBOOK_DEPLOY="true",
        SOAR_APPROVAL_MODE="disabled",
        SOAR_LAB_MODE="true",
    )
    cap = "SOAR_ALLOW_ACTIONS" if tier is Tier.CONTROL else "SOAR_ALLOW_PLAYBOOK_DEPLOY"
    d = enforce(tool="t", tier=tier, capability=cap, config=cfg, transport="streamable-http")
    assert d.code is Code.DENY_TRANSPORT
    assert enforce(tool="t", tier=tier, capability=cap, config=cfg, transport="stdio").allowed


def test_http_allows_lower_tiers(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_INCIDENT_WRITES="true")
    d = enforce(
        tool="t",
        tier=Tier.MODIFICATION,
        capability="SOAR_ALLOW_INCIDENT_WRITES",
        config=cfg,
        transport="streamable-http",
    )
    assert d.allowed


# ---------------------------------------------------------------- approval


def test_tier3_requires_approval_by_default_and_not_in_disabled_lab_mode(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_ACTIONS="true")
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(3, "allow"),
    )
    assert d.outcome is Outcome.REQUIRE_APPROVAL and "out_of_band" in d.reason
    lab = _settings(
        policy_file, SOAR_ALLOW_ACTIONS="true", SOAR_APPROVAL_MODE="disabled", SOAR_LAB_MODE="true"
    )
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=lab,
        transport="stdio",
        policy=_policy(3, "allow"),
    )
    assert d.allowed


def test_require_action_confirmation_false_allows_tier3_when_policy_says_allow(policy_file):
    cfg = _settings(
        policy_file, SOAR_ALLOW_ACTIONS="true", SOAR_REQUIRE_ACTION_CONFIRMATION="false"
    )
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(3, "allow"),
    )
    assert d.allowed
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(3, "require_approval"),
    )
    assert d.outcome is Outcome.REQUIRE_APPROVAL  # the rule itself asked for it


def test_tier4_uses_playbook_confirmation(policy_file):
    cfg = _settings(policy_file, SOAR_ALLOW_PLAYBOOK_DEPLOY="true")
    d = enforce(
        tool="t",
        tier=Tier.AUTOMATION,
        capability="SOAR_ALLOW_PLAYBOOK_DEPLOY",
        config=cfg,
        transport="stdio",
    )
    assert d.outcome is Outcome.REQUIRE_APPROVAL
    cfg2 = _settings(
        policy_file, SOAR_ALLOW_PLAYBOOK_DEPLOY="true", SOAR_REQUIRE_PLAYBOOK_CONFIRMATION="false"
    )
    assert enforce(
        tool="t",
        tier=Tier.AUTOMATION,
        capability="SOAR_ALLOW_PLAYBOOK_DEPLOY",
        config=cfg2,
        transport="stdio",
    ).allowed


def test_legacy_writes_never_reaches_actions():
    cfg = Settings.load({"SOAR_ALLOW_WRITES": "true"})
    assert enforce(
        tool="soar_add_comment",
        tier=Tier.DOCUMENTATION,
        capability="SOAR_ALLOW_COMMENTS",
        config=cfg,
        transport="stdio",
    ).allowed
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(1),
    )
    assert d.code is Code.DENY_DISABLED


def test_decision_helpers():
    d = Decision(Outcome.ALLOW, Code.ALLOW, "ok", Tier.READ)
    assert d.allowed and not d.denied
    assert d.to_dict()["code"] == "ALLOW" and d.to_dict()["tier"] == 0
