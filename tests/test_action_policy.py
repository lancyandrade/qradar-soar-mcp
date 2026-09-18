"""P1-06: the action policy — ordered rules, deny_values with CIDR, fail closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from qradar_soar_mcp.security.action_policy import ActionPolicy, PolicyError
from qradar_soar_mcp.security.tiers import Tier

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "config" / "action_policy.example.yaml"
SCHEMA = ROOT / "docs" / "action_policy.schema.json"
# RFC1918 targets are what the CIDR deny-list acceptance test is about (P1-06 AC).
PRIVATE_A = "10.4.2.9"  # check_no_secrets:allow
PRIVATE_B = "192.168.1.1"  # check_no_secrets:allow
PRIVATE_C = "172.20.0.1"  # check_no_secrets:allow


@pytest.fixture
def example() -> ActionPolicy:
    return ActionPolicy.load(EXAMPLE)


def test_example_policy_loads_and_denies_by_default(example: ActionPolicy):
    d = example.describe()
    assert d["default"] == {"tier": 5, "decision": "deny"}
    r = example.classify(action_name="Anything Else")
    assert r.tier is Tier.HIGH_RISK and r.decision == "deny" and r.rule == "default"
    assert "Anything Else" in r.reason and "classify it explicitly" in r.reason


def test_first_match_wins_and_tiers_come_from_rules(example: ActionPolicy):
    assert example.classify(action_name="Send Analyst Digest").tier is Tier.DOCUMENTATION
    r = example.classify(action_name="Escalate to Tier 2")
    assert (
        r.tier is Tier.MODIFICATION and r.decision == "allow" and r.rule == "regex:^Escalate to .*"
    )
    r = example.classify(
        action_name="Firewall — Block IP",
        target_values=["203.0.113.44"],
        artifact_type="IP Address",
    )
    assert r.tier is Tier.CONTROL and r.decision == "require_approval" and r.destructive
    assert r.constraint_violation is None
    r = example.classify(action_name="Purge Mailbox")
    assert r.tier is Tier.HIGH_RISK and r.decision == "deny" and "never model-reachable" in r.reason


def test_name_match_is_case_insensitive_exact(example: ActionPolicy):
    assert example.classify(action_name="send analyst digest").tier is Tier.DOCUMENTATION
    assert example.classify(action_name="Send Analyst Digest Now").rule == "default"


def test_cidr_deny_values_block_private_targets(example: ActionPolicy):
    r = example.classify(
        action_name="Firewall — Block IP", target_values=[PRIVATE_A], artifact_type="IP Address"
    )
    assert r.constraint_violation is not None and "10.0.0.0/8" in r.constraint_violation
    r = example.classify(
        action_name="Firewall — Block IP", target_values=[PRIVATE_B], artifact_type="IP Address"
    )
    assert "192.168.0.0/16" in (r.constraint_violation or "")
    r = example.classify(
        action_name="Firewall — Block IP", target_values=["203.0.113.5", PRIVATE_C]
    )
    assert "172.16.0.0/12" in (r.constraint_violation or "")


def test_artifact_type_constraint(example: ActionPolicy):
    r = example.classify(
        action_name="Firewall — Block IP", target_values=["203.0.113.5"], artifact_type="DNS Name"
    )
    assert "artifact type 'DNS Name'" in (r.constraint_violation or "")
    r = example.classify(
        action_name="Firewall — Block IP", target_values=["203.0.113.5"], artifact_type=None
    )
    assert r.constraint_violation is None  # nothing to check against


def test_hostname_deny_values_are_exact_case_insensitive():
    p = ActionPolicy.from_mapping(
        {
            "version": 1,
            "actions": [
                {
                    "match": {"name": "Isolate"},
                    "tier": 3,
                    "decision": "require_approval",
                    "constraints": {"deny_values": ["DC01.example.internal", "10.0.0.0/8"]},
                }
            ],
        }
    )
    assert p.classify(
        action_name="Isolate", target_values=["dc01.example.internal"]
    ).constraint_violation
    assert (
        p.classify(
            action_name="Isolate", target_values=["dc02.example.internal"]
        ).constraint_violation
        is None
    )
    assert (
        p.classify(action_name="Isolate", target_values=["not-an-ip"]).constraint_violation is None
    )


def test_allow_values():
    p = ActionPolicy.from_mapping(
        {
            "version": 1,
            "actions": [
                {
                    "match": {"name": "Block"},
                    "tier": 3,
                    "decision": "allow",
                    "constraints": {"allow_values": ["203.0.113.0/24"]},
                }
            ],
        }
    )
    assert (
        p.classify(action_name="Block", target_values=["203.0.113.9"]).constraint_violation is None
    )
    assert "not in allow_values" in (
        p.classify(action_name="Block", target_values=["198.51.100.9"]).constraint_violation or ""
    )


def test_match_by_id():
    p = ActionPolicy.from_mapping(
        {"version": 1, "actions": [{"match": {"id": 47}, "tier": 2, "decision": "allow"}]}
    )
    assert p.classify(action_name="whatever", action_id=47).tier is Tier.MODIFICATION
    assert p.classify(action_name="whatever", action_id=48).rule == "default"


def test_regex_rules_are_anchored_via_fullmatch():
    p = ActionPolicy.from_mapping(
        {
            "version": 1,
            "actions": [{"match": {"name_regex": "Block.*"}, "tier": 3, "decision": "deny"}],
        }
    )
    assert p.classify(action_name="Block IP").rule == "regex:Block.*"
    assert p.classify(action_name="Do not Block IP").rule == "default"


@pytest.mark.parametrize("pattern", ["(a+)+", "(x*)*", "(.+)*$", "^(a|aa)+$", "(\\d+)+"])
def test_catastrophic_regex_rejected_at_load(pattern: str):
    with pytest.raises(PolicyError, match="nested quantifier"):
        ActionPolicy.from_mapping(
            {
                "version": 1,
                "actions": [{"match": {"name_regex": pattern}, "tier": 5, "decision": "deny"}],
            }
        )


def test_regex_too_long_or_invalid_rejected():
    with pytest.raises(PolicyError, match="longer than"):
        ActionPolicy.from_mapping(
            {
                "version": 1,
                "actions": [{"match": {"name_regex": "a" * 201}, "tier": 5, "decision": "deny"}],
            }
        )
    with pytest.raises(PolicyError, match="does not compile"):
        ActionPolicy.from_mapping(
            {
                "version": 1,
                "actions": [{"match": {"name_regex": "("}, "tier": 5, "decision": "deny"}],
            }
        )


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        "text",
        {"version": 2},
        {"version": 1, "extra": 1},
        {"version": 1, "actions": [{"match": {}, "tier": 1, "decision": "allow"}]},
        {
            "version": 1,
            "actions": [{"match": {"name": "a", "id": 1}, "tier": 1, "decision": "allow"}],
        },
        {"version": 1, "actions": [{"match": {"name": " "}, "tier": 1, "decision": "allow"}]},
        {"version": 1, "actions": [{"match": {"name": "a"}, "tier": 6, "decision": "allow"}]},
        {"version": 1, "actions": [{"match": {"name": "a"}, "tier": 1, "decision": "maybe"}]},
        {"version": 1, "actions": [{"match": {"name": "a"}, "tier": 1}]},
        {
            "version": 1,
            "actions": [
                {
                    "match": {"name": "a"},
                    "tier": 1,
                    "decision": "allow",
                    "constraints": {"cidr": []},
                }
            ],
        },
        {"version": 1, "default": {"tier": 5, "decision": "deny", "x": 1}},
        {"version": 1, "actions": {"match": {"name": "a"}}},
    ],
)
def test_malformed_policies_raise(raw):
    with pytest.raises(PolicyError):
        ActionPolicy.from_mapping(raw)


def test_missing_or_oversize_or_invalid_yaml_never_falls_back(tmp_path: Path):
    with pytest.raises(PolicyError, match="not set"):
        ActionPolicy.load(None)
    with pytest.raises(PolicyError, match="does not exist"):
        ActionPolicy.load(tmp_path / "nope.yaml")
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * 1_000_001)
    with pytest.raises(PolicyError, match="larger"):
        ActionPolicy.load(big)
    bad = tmp_path / "bad.yaml"
    bad.write_text("actions: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError) as info:
        ActionPolicy.load(bad)
    assert info.value.__cause__ is None
    tagged = tmp_path / "tagged.yaml"
    tagged.write_text("version: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        ActionPolicy.load(tagged)


def test_policy_error_message_names_location():
    with pytest.raises(PolicyError, match=r"actions\.0\.tier"):
        ActionPolicy.from_mapping(
            {"version": 1, "actions": [{"match": {"name": "a"}, "tier": 9, "decision": "allow"}]}
        )


def test_json_schema_is_emitted_and_committed_without_drift():
    schema = ActionPolicy.json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"version", "default", "actions"}
    committed = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert committed == schema, "docs/action_policy.schema.json drifted; regenerate it"


def test_example_validates_against_committed_schema():
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert set(raw) <= {"version", "default", "actions"}
    ActionPolicy.from_mapping(raw)  # would raise on drift between example and schema


def test_describe_contains_no_deny_values_content(example: ActionPolicy):
    text = json.dumps(example.describe())
    assert "10.0.0.0/8" not in text and "deny_values" in text
