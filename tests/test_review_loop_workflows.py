"""Review loop: static checks over the GitHub Actions workflows.

These pin the security properties the runbook promises, so that a later edit
to a workflow cannot quietly drop one.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from review_loop import policy

ROOT = Path(__file__).parent.parent
WF = ROOT / ".github" / "workflows"
ALL = sorted(WF.glob("*.yml"))
LOOP = ("review-loop.yml", "review-gate.yml", "codex-review-relay.yml")


def load(name: str) -> dict[str, Any]:
    return yaml.safe_load((WF / name).read_text(encoding="utf-8"))


def triggers(doc: dict[str, Any]) -> dict[str, Any]:
    return doc.get("on", doc.get(True))  # PyYAML reads the key `on` as True


def steps(doc: dict[str, Any]):
    for job_name, job in doc["jobs"].items():
        for step in job.get("steps", []):
            yield job_name, job, step


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_sha(path: Path):
    text = path.read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)(.*)", text)
    for ref, rest in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), ref
        assert re.search(r"#\s*v\d", rest), f"{ref}: add the version as a comment"


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_top_level_permissions_are_minimal(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    perms = doc.get("permissions")
    assert perms is not None, "declare top-level permissions"
    assert perms in ({}, {"contents": "read"}), perms
    assert "write-all" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", LOOP)
def test_no_expression_is_interpolated_into_a_shell_script(name: str):
    """Values reach scripts through env:, never through ${{ }} in run: (injection)."""
    for _job, _j, step in steps(load(name)):
        assert "${{" not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("name", LOOP)
def test_checkouts_never_keep_credentials(name: str):
    for _job, _j, step in steps(load(name)):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_relay_has_no_permissions_and_only_matches_the_codex_bot():
    doc = load("codex-review-relay.yml")
    assert doc["permissions"] == {}
    job = doc["jobs"]["relay"]
    assert f"github.event.review.user.id == {policy.CODEX.bot_user_id}" in job["if"]
    assert all("uses" not in s for s in job["steps"])


def test_gate_never_checks_out_pull_request_code():
    doc = load("review-gate.yml")
    assert "pull_request_target" in triggers(doc)
    for _job, _j, step in steps(doc):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    for _job, _j, step in steps(doc):
        assert "github.event.pull_request.head" not in yaml.safe_dump(step)


def test_only_the_gate_uses_pull_request_target():
    for path in ALL:
        if path.name != "review-gate.yml":
            assert "pull_request_target" not in triggers(yaml.safe_load(path.read_text("utf-8")))


def test_secrets_are_separated_by_job():
    doc = load("review-loop.yml")
    text_of = {name: yaml.safe_dump(job) for name, job in doc["jobs"].items()}
    anthropic = {n for n, t in text_of.items() if "ANTHROPIC_API_KEY" in t}
    app_key = {n for n, t in text_of.items() if "REVIEW_LOOP_APP_PRIVATE_KEY" in t}
    assert anthropic == {"fix"}
    assert app_key == {"push"}
    jobs = doc["jobs"]
    assert jobs["fix"]["environment"] == "review-loop-claude"
    assert jobs["push"]["environment"] == "review-loop"
    gate = load("review-gate.yml")["jobs"]["gate"]
    assert gate["environment"] == "review-loop"


def test_jobs_that_run_pull_request_code_hold_no_secrets_or_write_access():
    jobs = load("review-loop.yml")["jobs"]
    verify = jobs["verify"]
    assert verify["permissions"] == {"contents": "read"}
    assert "environment" not in verify
    assert "${{ secrets." not in yaml.safe_dump(verify)


def test_claude_job_is_read_only_and_tool_restricted():
    fix = load("review-loop.yml")["jobs"]["fix"]
    assert set(fix["permissions"].values()) == {"read"}
    (claude,) = [s for s in fix["steps"] if "claude-code-action" in str(s.get("uses"))]
    args = claude["with"]["claude_args"]
    assert '--allowedTools "Read,Edit,Write,Glob,Grep"' in args
    for tool in ("Bash", "WebFetch", "WebSearch"):
        assert tool in args.split("--disallowedTools", 1)[1]
    assert claude["with"]["allowed_bots"] == policy.CODEX.app_slug
    assert "disableAllHooks" in claude["with"]["settings"]
    assert claude["with"]["github_token"] == "${{ github.token }}"
    names = [s.get("name", "") for s in fix["steps"]]
    assert names.index("Set aside PR-controlled Claude configuration") < names.index("Claude Code")


def test_loop_is_off_unless_explicitly_enabled():
    triage = load("review-loop.yml")["jobs"]["triage"]
    assert triage["if"].startswith("vars.REVIEW_LOOP_ENABLED == 'true' && (")
    assert f"github.event.comment.user.id == {policy.CODEX.bot_user_id}" in triage["if"]


def test_runs_are_serialised_per_pull_request():
    for name in ("review-loop.yml", "review-gate.yml"):
        conc = load(name)["concurrency"]
        assert conc["cancel-in-progress"] is False
        assert "github.event.issue.number" in conc["group"]


def test_nothing_merges_force_pushes_or_touches_protection():
    texts = [p.read_text(encoding="utf-8") for p in ALL]
    texts += [p.read_text(encoding="utf-8") for p in (ROOT / "automation").rglob("*.py")]
    banned = (
        "gh pr merge",
        "/pulls/{n}/merge",
        "/merges",
        "enablePullRequestAutoMerge",
        "auto-merge",
        "--force",
        "push -f",
        "/protection",
        "rulesets",
        '"APPROVE"',  # no pull-request review approvals by automation
        "--approve",
    )
    for text in texts:
        for word in banned:
            for line in text.splitlines():
                if word in line:
                    pytest.fail(f"{word!r} in: {line.strip()}")


def test_push_is_plain_and_uses_the_attempt_trailers():
    push = load("review-loop.yml")["jobs"]["push"]
    (commit,) = [s for s in push["steps"] if s.get("id") == "commit"]
    script = commit["run"]
    assert (
        'push --no-verify "https://github.com/$GITHUB_REPOSITORY.git" "HEAD:refs/heads/$BRANCH"'
        in script
    )
    assert f"{policy.TRAILER_ATTEMPT}: $ATTEMPT/{policy.MAX_FIX_ATTEMPTS}" in script
    assert f"{policy.TRAILER_REVIEWED}: $HEAD_SHA" in script
    assert f"user.name={policy.COMMIT_AUTHOR_NAME}" in script
    assert f"user.email={policy.COMMIT_AUTHOR_EMAIL}" in script
    assert script.index(" prepush ") < script.index("push --no-verify")
    (app,) = [s for s in push["steps"] if s.get("id") == "app"]
    assert app["with"]["permission-contents"] == "write"
    assert "permission-workflows" not in app["with"]


def test_gate_token_can_only_write_checks():
    gate = load("review-gate.yml")["jobs"]["gate"]
    (app,) = [s for s in gate["steps"] if s.get("id") == "app"]
    perms = {k: v for k, v in app["with"].items() if k.startswith("permission-")}
    assert perms == {"permission-checks": "write"}
    assert set(gate["permissions"].values()) == {"read"}


def test_workflow_run_triggers_name_real_workflows():
    names = {yaml.safe_load(p.read_text("utf-8"))["name"] for p in ALL}
    for name in ("review-loop.yml", "review-gate.yml"):
        for upstream in triggers(load(name))["workflow_run"]["workflows"]:
            assert upstream in names


def test_required_ci_jobs_match_ci_yml():
    ci = load("ci.yml")
    expected = set()
    for job in ci["jobs"].values():
        name = job.get("name")
        matrix = (job.get("strategy") or {}).get("matrix")
        if matrix:
            expected |= {f"test ({os}, {py})" for os in matrix["os"] for py in matrix["python"]}
        else:
            expected.add(name)
    assert expected == set(policy.REQUIRED_CI_JOBS)


def test_verify_mirrors_the_ci_gates():
    ci = (WF / "ci.yml").read_text(encoding="utf-8")
    verify = yaml.safe_dump(load("review-loop.yml")["jobs"]["verify"])
    for needle in (
        "ruff check",
        "ruff format --check",
        "uv run mypy",
        "--cov-fail-under=80",
        "--fail-under=95",
        "check_no_secrets.py",
    ):
        assert needle in ci and needle in verify, needle


def test_patch_policy_runs_before_pull_request_code():
    verify = load("review-loop.yml")["jobs"]["verify"]
    ids = [s.get("id") or s.get("name") for s in verify["steps"]]
    assert ids.index("policy") < ids.index("Test suite (mirrors ci.yml)")


def test_gate_is_off_unless_explicitly_enabled():
    gate = load("review-gate.yml")["jobs"]["gate"]
    assert gate["if"].startswith("vars.REVIEW_LOOP_GATE_ENABLED == 'true' && (")


def test_noop_events_cannot_displace_a_pending_codex_run():
    group = load("review-loop.yml")["concurrency"]["group"]
    assert "format('noop-{0}', github.run_id)" in group
    assert "github.event.comment.user.id == 199175422" in group


def test_gate_prefilters_outside_users():
    cond = load("review-gate.yml")["jobs"]["gate"]["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in cond
    assert "github.event.comment.author_association == 'OWNER'" in cond
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in cond


def test_claude_file_tools_are_fenced_in():
    fix = load("review-loop.yml")["jobs"]["fix"]
    names = [s.get("name", "") for s in fix["steps"]]
    claude_at = names.index("Claude Code")
    assert names.index("Refuse symlinks in the checkout") < claude_at
    setaside = fix["steps"][names.index("Set aside PR-controlled Claude configuration")]["run"]
    for path in (".claude", ".claude.json", ".mcp.json", ".gitmodules", ".ripgreprc", ".husky"):
        assert path in setaside
    assert "CLAUDE.local.md" in setaside and "pristine.git" in setaside
    settings = fix["steps"][claude_at]["with"]["settings"]
    for rule in (
        "Read(//proc/**)",
        "Read(//home/runner/work/_temp/**)",
        "Edit(//home/runner/work/_temp/**)",
        "Edit(./.git/**)",
        "Edit(./.github/**)",
    ):
        assert rule in settings


def test_patch_is_built_with_pristine_git_metadata_and_scanned():
    fix = load("review-loop.yml")["jobs"]["fix"]
    (build,) = [s for s in fix["steps"] if s.get("id") == "patch"]
    assert '--git-dir="$RUNNER_TEMP/pristine.git"' in build["run"]
    assert "core.hooksPath=/dev/null" in build["run"]
    assert "sk-ant-" in build["run"]
    assert build["env"]["BASH_ENV"] == "" and build["env"]["LD_PRELOAD"] == ""


def test_patch_checks_include_existing_file_modes():
    jobs = load("review-loop.yml")["jobs"]
    for name in ("verify", "push"):
        assert "--repo ." in yaml.safe_dump(jobs[name])


def test_resolving_a_review_thread_re_evaluates_the_gate():
    """Codex PR #12: thread resolution must reach the gate, or it stays red after the fix."""
    relay = load("codex-review-relay.yml")
    assert triggers(relay)["pull_request_review_thread"]["types"] == ["resolved", "unresolved"]
    thread = relay["jobs"]["thread"]
    assert "github.event_name == 'pull_request_review_thread'" in thread["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in thread["if"]
    assert all("uses" not in s for s in thread["steps"])
    assert "codex-review-relay" in triggers(load("review-gate.yml"))["workflow_run"]["workflows"]


def test_thread_relays_never_start_a_fix():
    loop = load("review-loop.yml")
    relay_cond = (
        "github.event.workflow_run.name == 'codex-review-relay' && "
        "github.event.workflow_run.event == 'pull_request_review' && "
        "github.event.workflow_run.conclusion == 'success'"
    )
    assert relay_cond in loop["jobs"]["triage"]["if"]
    assert relay_cond in loop["concurrency"]["group"]
