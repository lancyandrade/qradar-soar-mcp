"""Review loop: which job runs, and in which concurrency group, for each event.

The real ``if:`` and ``concurrency:`` expressions are read from the workflow
files and evaluated (tests/gh_expr.py) against synthetic event contexts, so
the routing of the scheduled fan-out, the per-PR gate runs it dispatches, and
the no-op events is checked end to end without deploying anything.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from review_loop import cli, policy
from review_loop.github import GitHub, Response
from tests import review_loop_data as d
from tests.gh_expr import evaluate, render, truthy

WF = Path(__file__).parent.parent / ".github" / "workflows"
REPO = d.REPO
FORK = "someone/qradar-soar-mcp"
RUN_ID = 4242
CODEX_ID = policy.CODEX.bot_user_id


def load(name: str) -> dict[str, Any]:
    return yaml.safe_load((WF / name).read_text(encoding="utf-8"))


GATE = load("review-gate.yml")
LOOP = load("review-loop.yml")


def ctx(event_name: str, event: dict[str, Any], *, inputs=None, enabled=True) -> dict[str, Any]:
    return {
        "github": {
            "event_name": event_name,
            "event": event,
            "repository": REPO,
            "run_id": RUN_ID,
        },
        "vars": {
            "REVIEW_LOOP_GATE_ENABLED": "true" if enabled else "",
            "REVIEW_LOOP_ENABLED": "true" if enabled else "",
        },
        "inputs": inputs or {},
    }


def comment(user_id: int, association: str, *, on_pr: bool = True) -> dict[str, Any]:
    issue: dict[str, Any] = {"number": 12}
    if on_pr:
        issue["pull_request"] = {"url": "x"}
    return {
        "issue": issue,
        "comment": {"user": {"id": user_id}, "author_association": association},
    }


def workflow_run(name: str, conclusion: str, *, prs=(12,), head_repo=REPO, event="pull_request"):
    return {
        "workflow_run": {
            "name": name,
            "conclusion": conclusion,
            "event": event,
            "head_sha": d.HEAD,
            "head_repository": {"full_name": head_repo},
            "pull_requests": [{"number": n} for n in prs],
        }
    }


def pr_target(head_repo: str = REPO) -> dict[str, Any]:
    return {"pull_request": {"number": 12, "head": {"repo": {"full_name": head_repo}}}}


def gate_route(c: dict[str, Any]) -> tuple[set[str], str]:
    jobs = {name for name, job in GATE["jobs"].items() if truthy(evaluate(job["if"], c))}
    return jobs, render(GATE["concurrency"]["group"], c)


# ------------------------------------------------------------------ the gate workflow

GATE_CASES = [
    # (label, context, jobs that run, concurrency group)
    ("schedule fans out", ctx("schedule", {}), {"fanout"}, f"review-gate-other-{RUN_ID}"),
    (
        "dispatch from fanout evaluates one PR",
        ctx("workflow_dispatch", {"inputs": {"pr_number": "12"}}, inputs={"pr_number": 12}),
        {"gate"},
        "review-gate-pr-12",
    ),
    (
        "CI run naming the PR",
        ctx("workflow_run", workflow_run("ci", "success")),
        {"gate"},
        "review-gate-pr-12",
    ),
    (
        "Codex relay naming the PR",
        ctx(
            "workflow_run",
            workflow_run("codex-review-relay", "success", event="pull_request_review"),
        ),
        {"gate"},
        "review-gate-pr-12",
    ),
    (
        "workflow_run naming no PR fans out",
        ctx("workflow_run", workflow_run("ci", "success", prs=())),
        {"fanout"},
        f"review-gate-other-{RUN_ID}",
    ),
    (
        "workflow_run from a fork does nothing",
        ctx("workflow_run", workflow_run("ci", "success", head_repo=FORK)),
        set(),
        f"review-gate-other-{RUN_ID}",
    ),
    (
        "owner comment re-evaluates now",
        ctx("issue_comment", comment(33344501, "OWNER")),
        {"gate"},
        "review-gate-pr-12",
    ),
    (
        "Codex comment",
        ctx("issue_comment", comment(CODEX_ID, "NONE")),
        {"gate"},
        "review-gate-pr-12",
    ),
    (
        "drive-by comment does nothing and cannot displace a pending run",
        ctx("issue_comment", comment(1, "NONE")),
        set(),
        f"review-gate-other-{RUN_ID}",
    ),
    (
        "comment on a plain issue",
        ctx("issue_comment", comment(33344501, "OWNER", on_pr=False)),
        set(),
        f"review-gate-other-{RUN_ID}",
    ),
    (
        "same-repo PR update",
        ctx("pull_request_target", pr_target()),
        {"gate"},
        "review-gate-pr-12",
    ),
    (
        "fork PR update does nothing",
        ctx("pull_request_target", pr_target(FORK)),
        set(),
        f"review-gate-other-{RUN_ID}",
    ),
]


@pytest.mark.parametrize(
    ("label", "c", "jobs", "group"), GATE_CASES, ids=[c[0] for c in GATE_CASES]
)
def test_gate_routing(label: str, c: dict[str, Any], jobs: set[str], group: str):
    got_jobs, got_group = gate_route(c)
    assert got_jobs == jobs, label
    assert got_group == group, label


@pytest.mark.parametrize("case", GATE_CASES, ids=[c[0] for c in GATE_CASES])
def test_nothing_runs_while_the_gate_is_disabled(case):
    _label, c, _jobs, _group = case
    c = {**c, "vars": {}}
    assert gate_route(c)[0] == set()


def test_gate_and_fanout_never_both_run():
    for _label, c, _jobs, _group in GATE_CASES:
        assert len(gate_route(c)[0]) <= 1


def test_every_publishing_run_is_in_its_pr_group():
    """The gate job (the only publisher) always lands in review-gate-pr-<n>."""
    for _label, c, _jobs, _group in GATE_CASES:
        jobs, group = gate_route(c)
        if "gate" in jobs:
            assert group == "review-gate-pr-12"


# ------------------------------------------------------------------ fan-out end to end


def test_scheduled_fanout_dispatches_runs_that_land_in_per_pr_groups(monkeypatch, tmp_path: Path):
    """schedule -> fanout job -> cli fanout -> workflow_dispatch -> gate job in pr-<n>."""
    c = ctx("schedule", {})
    assert gate_route(c)[0] == {"fanout"}

    pulls = [
        {"number": n, "state": "open", "head": {"repo": {"full_name": REPO}}} for n in (3, 12)
    ] + [{"number": 9, "state": "open", "head": {"repo": {"full_name": FORK}}}]
    dispatched: list[dict[str, Any]] = []

    def transport(method, url, headers, body):
        if method == "GET" and "/pulls?state=open" in url:
            return Response(200, {}, json.dumps(pulls).encode())
        if method == "POST" and url.endswith("/actions/workflows/review-gate.yml/dispatches"):
            dispatched.append(json.loads(body))
            return Response(204, {}, b"")
        return Response(404, {}, b"{}")

    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    event = tmp_path / "event.json"
    event.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setattr(cli, "client", lambda env="GITHUB_TOKEN": GitHub("t", REPO, transport))
    step = GATE["jobs"]["fanout"]["steps"][-1]
    assert step["run"] == 'python3 -I automation/review_loop/cli.py fanout --ref "$DEFAULT_BRANCH"'
    assert cli.main(["fanout", "--ref", "main"]) == 0
    assert [p["inputs"]["pr_number"] for p in dispatched] == ["12", "3"]  # fork skipped

    for payload in dispatched:
        n = payload["inputs"]["pr_number"]
        # GitHub coerces the string input to the declared `type: number`.
        run = ctx("workflow_dispatch", {"inputs": payload["inputs"]}, inputs={"pr_number": int(n)})
        jobs, group = gate_route(run)
        assert jobs == {"gate"} and group == f"review-gate-pr-{n}"
        # The gate job's resolve step reads the PR number from the dispatch payload.
        assert cli.pr_numbers_from_event("workflow_dispatch", run["github"]["event"], REPO) == [
            int(n)
        ]


def test_the_schedule_runs_every_fifteen_minutes():
    on = GATE.get("on", GATE.get(True))
    (entry,) = on["schedule"]
    minutes = entry["cron"].split()[0].split(",")
    assert sorted(int(m) for m in minutes) == [7, 22, 37, 52]
    assert entry["cron"].split()[1:] == ["*", "*", "*", "*"]


def test_dispatch_input_is_the_number_the_gate_job_reads():
    on = GATE.get("on", GATE.get(True))
    assert on["workflow_dispatch"]["inputs"]["pr_number"] == {
        "description": "Pull request number to re-evaluate",
        "required": True,
        "type": "number",
    }


# ------------------------------------------------------------------ the loop workflow

LOOP_CASES = [
    ("Codex comment", ctx("issue_comment", comment(CODEX_ID, "NONE")), True, "review-loop-pr-12"),
    (
        "owner comment does not start a fix",
        ctx("issue_comment", comment(33344501, "OWNER")),
        False,
        f"review-loop-noop-{RUN_ID}",
    ),
    (
        "Codex review via the relay",
        ctx(
            "workflow_run",
            workflow_run("codex-review-relay", "success", event="pull_request_review"),
        ),
        True,
        "review-loop-pr-12",
    ),
    (
        "skipped relay (not Codex)",
        ctx(
            "workflow_run",
            workflow_run("codex-review-relay", "skipped", event="pull_request_review"),
        ),
        False,
        f"review-loop-noop-{RUN_ID}",
    ),
    (
        "relay started by something other than a review",
        ctx("workflow_run", workflow_run("codex-review-relay", "success", event="push")),
        False,
        f"review-loop-noop-{RUN_ID}",
    ),
    (
        "CI failure on a PR",
        ctx("workflow_run", workflow_run("ci", "failure")),
        True,
        "review-loop-pr-12",
    ),
    (
        "CI success",
        ctx("workflow_run", workflow_run("ci", "success")),
        False,
        f"review-loop-noop-{RUN_ID}",
    ),
    (
        "manual triage",
        ctx("workflow_dispatch", {}, inputs={"pr_number": 12}),
        True,
        "review-loop-pr-12",
    ),
]


@pytest.mark.parametrize(
    ("label", "c", "runs", "group"), LOOP_CASES, ids=[c[0] for c in LOOP_CASES]
)
def test_loop_routing(label: str, c: dict[str, Any], runs: bool, group: str):
    assert truthy(evaluate(LOOP["jobs"]["triage"]["if"], c)) is runs, label
    assert render(LOOP["concurrency"]["group"], c) == group, label


@pytest.mark.parametrize("case", LOOP_CASES, ids=[c[0] for c in LOOP_CASES])
def test_the_loop_stays_off_without_the_switch(case):
    _label, c, _runs, _group = case
    c = {**c, "vars": {"REVIEW_LOOP_ENABLED": "false"}}
    assert not truthy(evaluate(LOOP["jobs"]["triage"]["if"], c))


# ------------------------------------------------------------------ the evaluator itself


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("'a' || 'b'", "a"),
        ("null || 'b'", "b"),
        ("'' || 0 || 'c'", "c"),
        ("false && 'x'", False),
        ("'a' && 'b'", "b"),
        ("!null", True),
        ("!'x'", False),
        ("'TRUE' == 'true'", True),
        ("1 == '1'", True),
        ("null == 0", False),
        ("github.event.missing.deeper", None),
        ("github.event.list[0].n", 7),
        ("github.event.list[3].n", None),
        ("format('pr-{0}', 12)", "pr-12"),
        ("format('x-{0}-{1}', null, true)", "x--true"),
        ("(1 == 1) && (2 != 3)", True),
    ],
)
def test_expression_evaluator_follows_github_semantics(expression, expected):
    c = {"github": {"event": {"list": [{"n": 7}]}}}
    assert evaluate(expression, c) == expected


def test_expression_evaluator_rejects_what_it_does_not_understand():
    from tests.gh_expr import ExprError

    for bad in ("contains(a, b)", "a ==", "a > b", "'unterminated"):
        with pytest.raises(ExprError):
            evaluate(bad, {})
