"""P1-SEC-01: turning off a confirmation switch is lab-only (08 §31).

``SOAR_REQUIRE_ACTION_CONFIRMATION=false`` drops the approval step for a Tier-3
call whose policy rule says ``allow``; ``SOAR_REQUIRE_PLAYBOOK_CONFIRMATION=false``
does the same for Tier 4 (reserved: no Tier-4 tool exists). Before P1-SEC-01 either
was accepted without ``SOAR_LAB_MODE=true``. Now:

* either switch ``false`` outside lab mode refuses to start, naming the switch;
* with lab mode it loads, with a warning, and drops approval only where designed;
* unparseable values still resolve to ``true`` (fail closed) and never refuse;
* ``.env.example`` shows every capability, all off, including every Tier-4 flag;
* ``soar_invoke_action`` stays ``DENY_UNSUPPORTED`` and the tool surface is unchanged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from qradar_soar_mcp import cli
from qradar_soar_mcp.config import CAPABILITY_FLAGS, ConfigError, Settings
from qradar_soar_mcp.security.permissions import Code, Outcome, PolicyResult, enforce
from qradar_soar_mcp.security.tiers import CAPABILITY_TIERS, Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from qradar_soar_mcp.tools.actions import INVOCATION_UNVERIFIED
from tests.fake_soar import FakeSoar
from tests.tool_harness import audit_records, base_env, build_runtime, write_keys, write_policy

ROOT = Path(__file__).resolve().parents[1]
ACTION = "SOAR_REQUIRE_ACTION_CONFIRMATION"
PLAYBOOK = "SOAR_REQUIRE_PLAYBOOK_CONFIRMATION"
SWITCHES = (ACTION, PLAYBOOK)
FALSE_SPELLINGS = ("false", "FALSE", "0", "no", "off")
GARBAGE = ("", "nah", "FALSE ", " false", "0 ", "disabled", "null")


@pytest.fixture
def policy_file(tmp_path: Path) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\n", encoding="utf-8")
    return str(p)


def _policy(decision: str = "allow") -> PolicyResult:
    return PolicyResult(Tier.CONTROL, decision, False, "rule", "r")


def _tier3(cfg: Settings, decision: str = "allow"):
    return enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="stdio",
        policy=_policy(decision),
    )


def _tier4(cfg: Settings):
    return enforce(
        tool="t",
        tier=Tier.AUTOMATION,
        capability="SOAR_ALLOW_PLAYBOOK_DEPLOY",
        config=cfg,
        transport="stdio",
    )


# ------------------------------------------------------------- the defaults


def test_default_configuration_requires_both_confirmations():
    s = Settings.load({})
    assert s.require_action_confirmation is True
    assert s.require_playbook_confirmation is True
    assert s.lab_mode is False and s.warnings == ()


@pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "on"])
def test_explicit_true_needs_no_lab_mode(raw: str):
    s = Settings.load({ACTION: raw, PLAYBOOK: raw})
    assert s.require_action_confirmation and s.require_playbook_confirmation
    assert s.warnings == ()


# --------------------------------------------------- refused outside a lab


@pytest.mark.parametrize("switch", SWITCHES)
@pytest.mark.parametrize("raw", FALSE_SPELLINGS)
@pytest.mark.parametrize("lab", [None, "false", "0", "", "TRUE ", "maybe"])
def test_one_switch_off_outside_lab_mode_refuses_to_start(switch: str, raw: str, lab):
    """Absent, false and unparseable SOAR_LAB_MODE all mean "not a lab"."""
    env = {switch: raw}
    if lab is not None:
        env["SOAR_LAB_MODE"] = lab
    with pytest.raises(ConfigError) as info:
        Settings.load(env)
    message = str(info.value)
    assert f"{switch}=false is refused" in message
    assert "SOAR_LAB_MODE=true" in message
    other = PLAYBOOK if switch == ACTION else ACTION
    assert other not in message


def test_action_switch_off_is_refused_even_without_actions_enabled():
    with pytest.raises(ConfigError, match=ACTION):
        Settings.load({ACTION: "false"})


def test_action_switch_off_is_refused_with_actions_enabled(policy_file: str):
    env = {"SOAR_ALLOW_ACTIONS": "true", "SOAR_ACTION_POLICY_FILE": policy_file, ACTION: "false"}
    with pytest.raises(ConfigError, match=ACTION):
        Settings.load(env)


@pytest.mark.parametrize(
    "flag",
    [f for f in CAPABILITY_FLAGS if CAPABILITY_TIERS[f] is Tier.AUTOMATION],
)
def test_playbook_switch_off_is_refused_with_any_tier4_flag(flag: str):
    with pytest.raises(ConfigError, match=PLAYBOOK):
        Settings.load({flag: "true", PLAYBOOK: "false"})


def test_both_switches_off_outside_lab_mode_name_both():
    with pytest.raises(ConfigError) as info:
        Settings.load({ACTION: "false", PLAYBOOK: "false"})
    message = str(info.value)
    assert ACTION in message and PLAYBOOK in message


def test_refusal_never_echoes_a_secret():
    secret = "s3cr3t-value-never-shown"  # gitleaks:allow
    with pytest.raises(ConfigError) as info:
        Settings.load({ACTION: "false", "SOAR_API_KEY_SECRET": secret})
    assert secret not in str(info.value)


def test_runtime_and_cli_refuse_the_configuration(tmp_path: Path, capsys):
    rt = Runtime.build(base_env(tmp_path, **{ACTION: "false"}))
    assert not rt.usable and rt.config_error is not None and ACTION in rt.config_error
    env = {
        "SOAR_AUDIT_LOG_PATH": str(tmp_path / "state" / "audit.jsonl"),
        "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "state" / "approvals"),
        "SOAR_KILL_SWITCH_FILE": str(tmp_path / "state" / "HALT"),
        PLAYBOOK: "false",
    }
    code = cli.main([], env=env)
    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert "refusing to start" in captured.err and PLAYBOOK in captured.err


# ----------------------------------------------------------- lab mode only


def test_both_off_with_lab_mode_loads_and_warns():
    s = Settings.load({ACTION: "false", PLAYBOOK: "false", "SOAR_LAB_MODE": "true"})
    assert s.require_action_confirmation is False
    assert s.require_playbook_confirmation is False
    assert len(s.warnings) == 1
    assert ACTION in s.warnings[0] and PLAYBOOK in s.warnings[0]
    assert "Lab use only" in s.warnings[0]


def test_lab_mode_drops_approval_only_as_designed(policy_file: str):
    s = Settings.load(
        {
            "SOAR_ALLOW_ACTIONS": "true",
            "SOAR_ACTION_POLICY_FILE": policy_file,
            "SOAR_ALLOW_PLAYBOOK_DEPLOY": "true",
            ACTION: "false",
            PLAYBOOK: "false",
            "SOAR_LAB_MODE": "true",
        }
    )
    # An "allow" rule no longer asks; a "require_approval" rule still does.
    assert _tier3(s, "allow").allowed
    assert _tier3(s, "require_approval").outcome is Outcome.REQUIRE_APPROVAL
    assert _tier4(s).allowed
    # Every other gate still applies: a "deny" rule, a missing flag, the HTTP transport.
    assert _tier3(s, "deny").denied
    no_deploy = s.model_copy(update={"allow_playbook_deploy": False})
    assert _tier4(no_deploy).code is Code.DENY_DISABLED
    over_http = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=s,
        transport="streamable-http",
        policy=_policy("allow"),
    )
    assert over_http.code is Code.DENY_TRANSPORT


def test_lab_mode_alone_keeps_both_confirmations(policy_file: str):
    s = Settings.load(
        {
            "SOAR_LAB_MODE": "true",
            "SOAR_ALLOW_ACTIONS": "true",
            "SOAR_ACTION_POLICY_FILE": policy_file,
            "SOAR_ALLOW_PLAYBOOK_DEPLOY": "true",
        }
    )
    assert s.require_action_confirmation and s.require_playbook_confirmation
    assert _tier3(s).outcome is Outcome.REQUIRE_APPROVAL
    assert _tier4(s).outcome is Outcome.REQUIRE_APPROVAL


# --------------------------------------------------------- fail closed


@pytest.mark.parametrize("switch", SWITCHES)
@pytest.mark.parametrize("raw", GARBAGE)
def test_unparseable_switch_resolves_to_true_and_starts(switch: str, raw: str):
    s = Settings.load({switch: raw})
    assert getattr(s, switch.removeprefix("SOAR_").lower()) is True
    assert len(s.warnings) == 1 and switch in s.warnings[0]


@pytest.mark.parametrize("raw", GARBAGE)
def test_unparseable_switch_still_requires_approval(raw: str, policy_file: str):
    s = Settings.load(
        {
            "SOAR_ALLOW_ACTIONS": "true",
            "SOAR_ACTION_POLICY_FILE": policy_file,
            "SOAR_ALLOW_PLAYBOOK_DEPLOY": "true",
            ACTION: raw,
            PLAYBOOK: raw,
        }
    )
    assert _tier3(s).outcome is Outcome.REQUIRE_APPROVAL
    assert _tier4(s).outcome is Outcome.REQUIRE_APPROVAL


# ------------------------------------------------------------- .env.example


def _example() -> dict[str, str]:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    return dict(re.findall(r"^([A-Z_]+)=(.*)$", text, flags=re.MULTILINE))


def test_env_example_shows_every_capability_and_all_are_off():
    example = _example()
    for flag in (*CAPABILITY_FLAGS, "SOAR_ALLOW_SCRIPT_WRITES"):
        assert example.get(flag) == "false", flag
    assert {k for k in example if k.startswith("SOAR_ALLOW_")} == {
        *CAPABILITY_FLAGS,
        "SOAR_ALLOW_SCRIPT_WRITES",
    }


def test_env_example_has_every_tier4_flag_off():
    example = _example()
    tier4 = [f for f in CAPABILITY_FLAGS if CAPABILITY_TIERS[f] is Tier.AUTOMATION]
    assert tier4 == [
        "SOAR_ALLOW_PLAYBOOK_DRAFT",
        "SOAR_ALLOW_PLAYBOOK_EXPORT",
        "SOAR_ALLOW_PLAYBOOK_CREATE",
        "SOAR_ALLOW_PLAYBOOK_MODIFY",
        "SOAR_ALLOW_PLAYBOOK_DEPLOY",
        "SOAR_ALLOW_PLAYBOOK_ENABLE",
    ]
    assert {f: example.get(f) for f in tier4} == dict.fromkeys(tier4, "false")


def test_env_example_keeps_safety_switches_on_and_lab_mode_off():
    example = _example()
    assert example[ACTION] == "true" and example[PLAYBOOK] == "true"
    assert example["SOAR_AUDIT_REQUIRED"] == "true"
    assert example["SOAR_LAB_MODE"] == "false"
    assert example["SOAR_APPROVAL_MODE"] == "out_of_band"


# ---------------------------------------------- invocation and tool surface


async def test_invoke_action_stays_unsupported_with_every_switch_off(
    fake: FakeSoar, tmp_path: Path
):
    """The loosest lab configuration still cannot invoke an action (08 §21)."""
    rt = build_runtime(
        fake,
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(write_policy(tmp_path)),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(write_keys(tmp_path)[1]),
        SOAR_APPROVAL_MODE="disabled",
        SOAR_LAB_MODE="true",
        **{ACTION: "false", PLAYBOOK: "false"},
    )
    assert rt.usable, rt.config_error
    out = await run_pipeline(
        TOOL_REGISTRY["soar_invoke_action"], rt, {"incident_id": 42, "action_id": 47}
    )
    assert out["ok"] is False
    assert json.dumps(out["error"], sort_keys=True) == json.dumps(
        {"code": "DENY_UNSUPPORTED", "message": INVOCATION_UNVERIFIED}, sort_keys=True
    )
    assert fake.requests == []
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["DECISION_DENIED"]
    assert records[0]["decision"] == "DENY_UNSUPPORTED"
    await rt.aclose()


def test_no_new_mutation_or_tier4_tool():
    mutating = sorted((n, int(s.tier)) for n, s in TOOL_REGISTRY.items() if s.mutating)
    assert mutating == [
        ("soar_add_artifact", 1),
        ("soar_add_comment", 1),
        ("soar_assign_incident", 2),
        ("soar_close_incident", 2),
        ("soar_create_incident", 2),
        ("soar_invoke_action", 3),
        ("soar_update_incident", 2),
        ("soar_update_task_status", 2),
    ]
    assert len(TOOL_REGISTRY) == 36
    assert not [n for n, s in TOOL_REGISTRY.items() if s.tier >= Tier.AUTOMATION]
    assert {n for n, s in TOOL_REGISTRY.items() if s.unsupported} == {"soar_invoke_action"}
