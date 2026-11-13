"""P2-06: ``qradar-soar-policy scaffold`` (06 P2-06; 08 §34).

AC: the scaffold is valid against the policy schema and denies everything; a server
running with the unedited scaffold reaches SOAR for reads and denies every action; the
CLI never writes over an existing policy file.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from qradar_soar_mcp import cli_policy
from qradar_soar_mcp.catalog import Catalog, SectionState, SectionStatus
from qradar_soar_mcp.catalog.models import RuleSpec
from qradar_soar_mcp.security.action_policy import MAX_POLICY_BYTES, ActionPolicy
from qradar_soar_mcp.security.policy_scaffold import (
    KEYWORD_TIERS,
    SCAFFOLD_REASON,
    ScaffoldError,
    build_scaffold,
    suggest_tier,
)
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from tests.conftest import SENTINEL, connection_env
from tests.fake_soar import FakeSoar
from tests.tool_harness import base_env, write_keys

FIXTURE = Path(__file__).parent / "fixtures" / "catalog" / "lab-v51.json"


def lab_catalog() -> Catalog:
    return Catalog.from_json(FIXTURE.read_bytes())


def rule(rule_id: int, name: str, *, enabled: bool = True) -> RuleSpec:
    return RuleSpec(
        id=rule_id, name=name, uuid=f"uuid-{rule_id}", type=1, object_type="incident",
        enabled=enabled,
    )  # fmt: skip


def with_rules(rules: list[RuleSpec], base: Catalog | None = None) -> Catalog:
    base = base or lab_catalog()
    sections = dict(base.sections)
    sections["rules"] = SectionStatus(state=SectionState.LOADED, count=len(rules))
    return base.model_copy(update={"rules": {f"r{r.id}": r for r in rules}, "sections": sections})


def parsed(text: str) -> ActionPolicy:
    return ActionPolicy.from_mapping(yaml.safe_load(text), source="<test>")


def assert_denies_everything(policy: ActionPolicy) -> None:
    doc = policy.document
    assert (doc.default.tier, doc.default.decision) == (5, "deny")
    for entry in doc.actions:
        assert (entry.tier, entry.decision, entry.destructive) == (5, "deny", True)
        assert entry.reason == SCAFFOLD_REASON
        assert entry.constraints.allow_values == []


# ------------------------------------------------------------- the document


def test_scaffold_of_the_lab_catalog_is_valid_and_denies_everything():
    catalog = lab_catalog()
    result = build_scaffold(catalog)
    policy = parsed(result.text)
    assert_denies_everything(policy)
    assert result.entries == result.actions == len(catalog.rules) == len(policy.document.actions)
    assert result.functions == len(catalog.functions)
    assert {e.match.name for e in policy.document.actions} == {
        r.name for r in catalog.rules.values()
    }
    for name in catalog.functions:  # functions are not entries
        assert f"name: {name}" not in result.text


def test_scaffold_validates_against_the_published_json_schema():
    import jsonschema  # in the lock (via mcp); a missing module fails, never skips

    schema = json.loads(
        (Path(__file__).parents[1] / "docs" / "action_policy.schema.json").read_text("utf-8")
    )
    jsonschema.validate(yaml.safe_load(build_scaffold(lab_catalog()).text), schema)


def test_every_classification_from_an_unedited_scaffold_is_tier5_deny():
    names = ["Firewall — Block IP", "Send Analyst Digest", "Purge Mailbox", "Escalate"]
    policy = parsed(build_scaffold(with_rules([rule(i, n) for i, n in enumerate(names, 1)])).text)
    for i, name in enumerate([*names, "not in the catalog", "FIREWALL — BLOCK IP "], 1):
        result = policy.classify(action_name=name, action_id=i, target_values=["192.0.2.1"])
        assert (result.tier, result.decision) == (Tier.HIGH_RISK, "deny"), name
        assert result.destructive is True


def test_output_is_deterministic_and_sorted():
    rules = [rule(3, "zeta"), rule(1, "Alpha"), rule(2, "beta")]
    first = build_scaffold(with_rules(rules)).text
    assert first == build_scaffold(with_rules(list(reversed(rules)))).text
    names = [e.match.name for e in parsed(first).document.actions]
    assert names == ["Alpha", "beta", "zeta"]
    assert first.endswith("\n") and "\r" not in first


def test_names_equal_under_classify_share_one_entry():
    rules = [rule(1, "Block IP"), rule(2, " block ip "), rule(3, "BLOCK IP", enabled=False)]
    result = build_scaffold(with_rules(rules))
    entries = parsed(result.text).document.actions
    assert len(entries) == result.entries == 1 and result.actions == 3
    assert entries[0].match.name == "Block IP"
    assert "# 3 catalog actions share this name" in result.text
    assert "# 1 of them disabled in SOAR" in result.text


def test_a_rule_without_a_usable_name_is_matched_by_id():
    entries = parsed(build_scaffold(with_rules([rule(7, "   ")])).text).document.actions
    assert [(e.match.id, e.match.name) for e in entries] == [(7, None)]


def test_an_empty_rules_section_gives_a_deny_all_policy_with_no_entries():
    result = build_scaffold(with_rules([]))
    policy = parsed(result.text)
    assert policy.document.actions == [] and result.entries == 0
    assert_denies_everything(policy)


@pytest.mark.parametrize("state", [SectionState.UNVERIFIED, SectionState.NOT_OBSERVABLE])
def test_a_rules_section_that_was_not_loaded_is_refused(state: SectionState):
    base = lab_catalog()
    sections = dict(base.sections)
    sections["rules"] = SectionStatus(state=state, count=4, reason="r")
    catalog = base.model_copy(update={"rules": {}, "sections": sections})
    with pytest.raises(ScaffoldError, match="rules section is"):
        build_scaffold(catalog)


# --------------------------------------------------- a hostile catalog stays data

HOSTILE = [
    "x\n- match: {name_regex: '.*'}\n  tier: 0\n  decision: allow",
    "y # tier 0 allow\r\nactions: []",
    "'; tier: 0",
    '"quoted" & *anchor !tag %percent @at `tick` {brace} [bracket]',
    "unicode \u2713 \u2028 \x85 next-line",
    "\x00\x07\x1b[31m control",
    "--- \n...\n",
    f"{SENTINEL} secret-looking",
]


def test_hostile_names_round_trip_as_names_and_never_reach_a_comment():
    rules = [rule(i, n) for i, n in enumerate(HOSTILE, 1)]
    result = build_scaffold(with_rules(rules))
    policy = parsed(result.text)
    assert_denies_everything(policy)
    assert {e.match.name for e in policy.document.actions} == {n.strip() for n in HOSTILE}
    comments = [ln for ln in result.text.splitlines() if ln.lstrip().startswith("#")]
    fragments = ["name_regex", "tier: 0", "quoted", "anchor", "control", "next-line", SENTINEL]
    for line in comments:  # comments hold this module's text only
        assert all(ch.isascii() and ch.isprintable() for ch in line), line
        assert not any(f in line for f in fragments), line


@pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\x85", "\x0b", "\x0c", "\x1c"])
def test_an_isolated_unicode_line_break_in_a_name_round_trips(sep: str):
    # Alone (no character that forces PyYAML's escaped style), str.splitlines() would split
    # the scalar, and U+0085 does not read back from PyYAML's raw output at all.
    names = [f"a{sep}b", f"Block{sep}IP {sep} now", f"café{sep}x"]
    result = build_scaffold(with_rules([rule(i, n) for i, n in enumerate(names, 1)]))
    policy = parsed(result.text)
    assert_denies_everything(policy)
    assert [e.match.name for e in policy.document.actions] == sorted(names, key=str.lower)
    for name in names:
        assert policy.classify(action_name=name).rule == name


def test_names_without_a_unicode_line_break_stay_readable():
    text = build_scaffold(with_rules([rule(1, "café ✓")])).text
    assert "café ✓" in text


def test_header_writes_an_unexpected_soar_version_as_unknown():
    catalog = lab_catalog().model_copy(update={"soar_version": "51\n- match: {id: 1}"})
    text = build_scaffold(catalog).text
    assert "SOAR unknown" in text and "match: {id: 1}" not in text


def test_a_scaffold_over_the_policy_size_limit_is_refused():
    rules = [rule(i, f"{'n' * 900}{i}") for i in range(1, 1300)]
    with pytest.raises(ScaffoldError, match="larger than"):
        build_scaffold(with_rules(rules))
    assert MAX_POLICY_BYTES == 1_000_000


# -------------------------------------------------------------- suggestions


@pytest.mark.parametrize(
    ("name", "tier", "keyword"),
    [
        ("Firewall — Block IP", Tier.CONTROL, "block"),
        ("EDR Isolate Endpoint", Tier.CONTROL, "isolate"),
        ("Reset  Password for user", Tier.CONTROL, "reset password"),
        ("Enrich Artifact with Threat Intel", Tier.DOCUMENTATION, "enrich"),
        ("Escalate to Tier 2", Tier.MODIFICATION, "escalate"),
        ("Enable Playbook X", Tier.AUTOMATION, "playbook"),
        ("Enrich then Delete", Tier.HIGH_RISK, "delete"),
        ("Bulk block", Tier.HIGH_RISK, "bulk"),
        ("Blockchain lookup", Tier.DOCUMENTATION, "lookup"),  # word boundary: not "block"
        ("rule_300", Tier.HIGH_RISK, None),
        ("Do the thing", Tier.HIGH_RISK, None),
        ("", Tier.HIGH_RISK, None),
    ],
)
def test_suggestion_from_keywords(name: str, tier: Tier, keyword: str | None):
    s = suggest_tier(name)
    assert (s.tier, s.keyword) == (tier, keyword)


def test_suggestions_are_comments_only_and_every_keyword_is_plain_ascii():
    text = build_scaffold(with_rules([rule(1, "Send Analyst Digest"), rule(2, "Block IP")])).text
    assert '# suggested tier 3: the name contains "block"' in text
    assert '# suggested tier 1: the name contains "notify"' not in text
    assert "tier: 3" not in text and "tier: 1" not in text
    for tier, keywords in KEYWORD_TIERS:
        assert Tier.DOCUMENTATION <= tier <= Tier.HIGH_RISK
        for keyword in keywords:
            assert keyword.isascii() and keyword == keyword.lower() and "#" not in keyword
    assert all(t > u for (t, _), (u, _) in itertools.pairwise(KEYWORD_TIERS))


# ------------------------------------------------------------------- the CLI


def run_cli(*args: str, env: dict[str, str] | None = None) -> int:
    return cli_policy.main(["scaffold", *args], env=env or {})


def test_cli_writes_a_new_file_from_a_catalog_file(tmp_path: Path, capsys):
    out = tmp_path / "action_policy.yaml"
    assert run_cli("--catalog", str(FIXTURE), "-o", str(out)) == 0
    assert_denies_everything(ActionPolicy.load(out))
    assert out.read_bytes() == build_scaffold(lab_catalog()).text.encode("utf-8")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "wrote 2 deny entries for 2 actions" in captured.err


def test_cli_never_writes_over_an_existing_file(tmp_path: Path, capsys):
    out = tmp_path / "action_policy.yaml"
    out.write_text("version: 1\nactions: []\n# operator's own\n", encoding="utf-8")
    before = out.read_bytes()
    assert run_cli("--catalog", str(FIXTURE), "-o", str(out)) == 1
    assert out.read_bytes() == before
    assert "already exists" in capsys.readouterr().err


def test_cli_never_follows_a_symlink_at_the_output_path(tmp_path: Path):
    victim = tmp_path / "victim.yaml"
    victim.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "action_policy.yaml"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert run_cli("--catalog", str(FIXTURE), "-o", str(link)) == 1
    assert victim.read_text(encoding="utf-8") == "keep\n"
    dangling = tmp_path / "dangling.yaml"
    dangling.symlink_to(tmp_path / "nowhere.yaml")
    assert run_cli("--catalog", str(FIXTURE), "-o", str(dangling)) == 1
    assert not (tmp_path / "nowhere.yaml").exists()


def test_cli_exclusive_create_wins_a_race(tmp_path: Path, monkeypatch, capsys):
    out = tmp_path / "action_policy.yaml"
    real = cli_policy.build_scaffold

    def build_then_race(catalog: Catalog) -> Any:
        result = real(catalog)
        out.write_text("raced\n", encoding="utf-8")  # appears after the early check
        return result

    monkeypatch.setattr(cli_policy, "build_scaffold", build_then_race)
    assert run_cli("--catalog", str(FIXTURE), "-o", str(out)) == 1
    assert out.read_text(encoding="utf-8") == "raced\n"
    assert "already exists" in capsys.readouterr().err


def test_cli_writes_to_stdout_with_dash(capsysbinary):
    assert run_cli("--catalog", str(FIXTURE), "-o", "-") == 0
    out = capsysbinary.readouterr().out
    assert out == build_scaffold(lab_catalog()).text.encode("utf-8")


def test_cli_leaves_nothing_behind_when_the_scaffold_is_refused(tmp_path: Path, capsys):
    base = lab_catalog()
    sections = dict(base.sections)
    sections["rules"] = SectionStatus(state=SectionState.NOT_OBSERVABLE, reason="r")
    bad = tmp_path / "catalog.json"
    bad.write_text(
        base.model_copy(update={"rules": {}, "sections": sections}).to_json(), encoding="utf-8"
    )
    out = tmp_path / "action_policy.yaml"
    assert run_cli("--catalog", str(bad), "-o", str(out)) == 1
    assert not out.exists()
    assert "rules section is not_observable" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "message"),
    [(None, "does not exist"), ("{not json", "not a catalog"), ('{"rules": {}}', "not a catalog")],
)
def test_cli_rejects_a_bad_catalog_file(tmp_path: Path, capsys, content: str | None, message: str):
    path = tmp_path / "catalog.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    out = tmp_path / "action_policy.yaml"
    assert run_cli("--catalog", str(path), "-o", str(out)) == 1
    assert message in capsys.readouterr().err and not out.exists()


def test_cli_requires_an_output(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_policy.main(["scaffold", "--catalog", str(FIXTURE)], env={})
    assert exc.value.code == 2


def test_cli_live_mode_loads_the_catalog_with_reads_only(fake: FakeSoar, tmp_path: Path, capsys):
    out = tmp_path / "action_policy.yaml"
    assert run_cli("-o", str(out), env=connection_env()) == 0
    policy = ActionPolicy.load(out)
    assert_denies_everything(policy)
    assert len(policy.document.actions) == len(fake.discovery["actions"]["entities"])
    posts = {r.path for r in fake.requests if r.method != "GET"}
    assert all(p.endswith("/query_paged") for p in posts), posts  # reads only
    captured = capsys.readouterr()
    assert SENTINEL not in captured.err + captured.out + out.read_text(encoding="utf-8")


def test_cli_live_mode_refuses_a_bad_configuration(tmp_path: Path, capsys):
    out = tmp_path / "action_policy.yaml"
    assert run_cli("-o", str(out), env={"SOAR_BASE_URL": "http://soar.example.internal"}) == 2
    err = capsys.readouterr().err
    assert "refused configuration" in err and not out.exists()


def test_cli_live_mode_reports_an_unreachable_soar_without_writing(tmp_path: Path, capsys):
    import httpx

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    out = tmp_path / "action_policy.yaml"
    code = cli_policy.main(
        ["scaffold", "-o", str(out)],
        env=connection_env(),
        http_transport=httpx.MockTransport(refuse),
    )
    assert code == 1 and not out.exists()
    err = capsys.readouterr().err
    assert "cannot load the catalog from SOAR" in err and SENTINEL not in err


# ------------------------------------------- the server with an unedited scaffold


async def test_server_with_the_unedited_scaffold_reads_and_denies_every_action(
    fake: FakeSoar, tmp_path: Path
):
    names = [str(a["name"]) for a in fake.incident["actions"]]
    assert names, "the fake incident carries actions"
    policy_file = tmp_path / "action_policy.yaml"
    policy_file.write_text(
        build_scaffold(with_rules([rule(i, n) for i, n in enumerate(names, 1)])).text,
        encoding="utf-8",
    )
    _, public = write_keys(tmp_path)
    env = base_env(
        tmp_path,
        SOAR_ALLOW_ACTIONS="true",
        SOAR_ALLOW_DESTRUCTIVE_ACTIONS="true",
        SOAR_ACTION_POLICY_FILE=str(policy_file),
        SOAR_APPROVAL_PUBLIC_KEY_FILE=str(public),
    )
    rt = Runtime.build(env, transport="stdio")
    assert rt.usable, rt.config_error
    try:
        read = await run_pipeline(TOOL_REGISTRY["soar_get_incident"], rt, {"incident_id": 42})
        assert read["ok"] is True  # reads reach SOAR
        listed = await run_pipeline(
            TOOL_REGISTRY["soar_list_incident_actions"], rt, {"incident_id": 42}
        )
        assert listed["ok"] is True and listed["data"]["policy_loaded"] is True
        rows = listed["data"]["actions"]
        assert len(rows) == len(names)
        for row in rows:
            assert row["policy"]["tier"] == 5 and row["policy"]["decision"] == "deny"
            assert row["policy"]["rule"] == row["name"].strip()  # matched its own entry
            assert row["invocable"] is False
        seen = len(fake.requests)
        for action in fake.incident["actions"]:
            out = await run_pipeline(
                TOOL_REGISTRY["soar_invoke_action"],
                rt,
                {"incident_id": 42, "action_id": action["id"]},
            )
            assert out["ok"] is False
            assert out["error"]["code"] == "DENY_UNSUPPORTED"
        assert len(fake.requests) == seen  # no invocation reached SOAR
        assert all(r.method == "GET" for r in fake.requests)
    finally:
        await rt.aclose()


def test_the_entry_point_is_declared():
    import tomllib

    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text("utf-8"))
    scripts = pyproject["project"]["scripts"]
    assert scripts["qradar-soar-policy"] == "qradar_soar_mcp.cli_policy:main"


@pytest.mark.parametrize(
    ("text", "expected", "message"),
    [
        ("version: 2\n", 0, "not a valid policy"),
        ("version: 1\n: [\n", 0, "not a valid policy"),
        ("version: 1\ndefault: {tier: 4, decision: deny}\n", 0, "default to tier 5"),
        ("version: 1\ndefault: {tier: 5, decision: allow}\n", 0, "default to tier 5"),
        ("version: 1\n", 1, "one entry per action"),
        (
            "version: 1\nactions:\n"
            "- {match: {id: 2}, tier: 5, decision: deny, destructive: true}\n",
            1,
            "one entry per action",  # an entry, but not the expected one
        ),
        (
            "version: 1\nactions:\n- {match: {id: 1}, tier: 5, decision: allow}\n",
            1,
            "not tier 5 / deny",
        ),
        (
            "version: 1\nactions:\n- {match: {id: 1}, tier: 5, decision: deny}\n",
            1,
            "not tier 5 / deny",  # destructive missing
        ),
    ],
)
def test_the_self_check_refuses_anything_but_a_deny_everything_policy(
    text: str, expected: int, message: str
):
    from qradar_soar_mcp.security import policy_scaffold

    with pytest.raises(ScaffoldError, match=message):
        policy_scaffold._check(text, [{"id": 1}] * expected)


def test_cli_refuses_an_oversized_catalog_file(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli_policy, "MAX_CATALOG_BYTES", 10)
    out = tmp_path / "action_policy.yaml"
    assert run_cli("--catalog", str(FIXTURE), "-o", str(out)) == 1
    assert "larger than 10 bytes" in capsys.readouterr().err and not out.exists()


def test_cli_reports_an_unreadable_catalog_file(tmp_path: Path, monkeypatch, capsys):
    def unreadable(self: Path) -> bytes:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    assert run_cli("--catalog", str(FIXTURE), "-o", str(tmp_path / "p.yaml")) == 1
    assert "cannot read the catalog file (PermissionError)" in capsys.readouterr().err


def test_cli_reports_an_output_it_cannot_create(tmp_path: Path, capsys):
    out = tmp_path / "missing-dir" / "action_policy.yaml"
    assert run_cli("--catalog", str(FIXTURE), "-o", str(out)) == 1
    assert "cannot create the file (FileNotFoundError)" in capsys.readouterr().err
    assert not out.parent.exists()


def test_a_failed_write_removes_the_partial_file(tmp_path: Path, monkeypatch, capsys):
    out = tmp_path / "action_policy.yaml"
    real_open = Path.open

    class Full:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def __enter__(self) -> Full:
            return self

        def __exit__(self, *exc: object) -> None:
            self.handle.close()

        def write(self, text: str) -> int:
            self.handle.write(text[:10])  # part of the text reaches the disk
            raise OSError(28, "No space left on device")

    def full_disk(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        handle = real_open(self, mode, *args, **kwargs)
        return Full(handle) if mode == "x" else handle

    monkeypatch.setattr(Path, "open", full_disk)
    assert run_cli("--catalog", str(FIXTURE), "-o", str(out)) == 1
    assert "cannot write the file (OSError)" in capsys.readouterr().err
    assert not out.exists()


def test_cli_reports_a_closed_stdout(monkeypatch, capsys):
    class Closed:
        def write(self, data: bytes) -> int:
            raise BrokenPipeError(32, "Broken pipe")

    class Stdout:
        buffer = Closed()

        def flush(self) -> None: ...

    monkeypatch.setattr(sys, "stdout", Stdout())
    assert run_cli("--catalog", str(FIXTURE), "-o", "-") == 1
    assert "cannot write to stdout (BrokenPipeError)" in capsys.readouterr().err


def test_long_and_unicode_case_names_round_trip_and_match():
    long_name = " ".join(["word"] * 1500)  # past the dump width: folding must round-trip
    names = [long_name, "İstanbul", "i̇stanbul", "Straße", "STRASSE"]
    result = build_scaffold(with_rules([rule(i, n) for i, n in enumerate(names, 1)]))
    policy = parsed(result.text)
    assert_denies_everything(policy)
    for name in names:  # each action is matched by an entry, never by the default
        assert policy.classify(action_name=name).rule != "default", name
