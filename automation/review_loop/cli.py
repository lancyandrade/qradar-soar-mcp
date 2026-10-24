"""Command line used by the review-loop workflows.

Run from a checkout of the default branch:

    python -I automation/review_loop/cli.py <command> ...

Outputs go to ``$GITHUB_OUTPUT`` and ``$GITHUB_STEP_SUMMARY``; diagnostics go
to stderr. No command ever writes a token anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from review_loop import ledger, patch_policy, policy
from review_loop.evaluate import Action, Snapshot, eligibility, gate, plan_loop
from review_loop.github import GitHub, GitHubError
from review_loop.snapshot import HeadMovedError, take

_SHA = re.compile(r"[0-9a-f]{40}")
_SAFE_OUTPUT = re.compile(r"[A-Za-z0-9 ._:/()+,'#=\[\]-]*")
MAX_PRS_PER_EVENT = 5


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def set_output(name: str, value: str) -> None:
    if not _SAFE_OUTPUT.fullmatch(value) or "\n" in value:
        raise ValueError(f"unsafe output value for {name}")
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")
    log(f"output {name}={value}")


def summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(ledger.neutralise(text) + "\n")


def safe(text: str) -> str:
    """Reduce free text to characters safe for a step output."""
    return "".join(ch if _SAFE_OUTPUT.fullmatch(ch) else " " for ch in text)[:300]


def client(env_name: str = "GITHUB_TOKEN") -> GitHub:
    token = os.environ.get(env_name, "")
    if not token:
        raise SystemExit(f"{env_name} is not set")
    return GitHub(token, os.environ["GITHUB_REPOSITORY"])


def _sha(value: str) -> str:
    if not _SHA.fullmatch(value):
        raise SystemExit("not a full commit sha")
    return value


# ------------------------------------------------------------------ resolve


def pr_numbers_from_event(event_name: str, event: dict[str, Any], repo: str) -> list[int]:
    """PR numbers named by the triggering event. Payload bodies are never used."""
    nums: list[int] = []
    if event_name == "issue_comment":
        issue = event.get("issue") or {}
        if isinstance(issue.get("pull_request"), dict) and isinstance(issue.get("number"), int):
            nums.append(issue["number"])
    elif event_name in ("pull_request_target", "pull_request"):
        pr = event.get("pull_request") or {}
        if isinstance(pr.get("number"), int):
            nums.append(pr["number"])
    elif event_name == "workflow_run":
        run = event.get("workflow_run") or {}
        for pr in run.get("pull_requests") or []:
            base_repo = ((pr.get("base") or {}).get("repo") or {}).get("name")
            if isinstance(pr.get("number"), int) and base_repo == repo.split("/")[1]:
                nums.append(pr["number"])
    elif event_name == "workflow_dispatch":
        raw = str((event.get("inputs") or {}).get("pr_number", ""))
        if raw.isdigit() and 0 < int(raw) < 10**7:
            nums.append(int(raw))
    return sorted(set(nums))[:MAX_PRS_PER_EVENT]


def cmd_resolve(args: argparse.Namespace) -> int:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    name = os.environ["GITHUB_EVENT_NAME"]
    repo = os.environ["GITHUB_REPOSITORY"]
    nums = pr_numbers_from_event(name, event, repo)
    if not nums and name == "workflow_run":
        sha = (event.get("workflow_run") or {}).get("head_sha", "")
        if _SHA.fullmatch(str(sha)):
            gh = client()
            pulls = gh.get(f"/repos/{repo}/commits/{sha}/pulls")
            nums = sorted(
                p["number"]
                for p in pulls
                if p.get("state") == "open" and isinstance(p.get("number"), int)
            )[:MAX_PRS_PER_EVENT]
    set_output("prs", json.dumps(nums).replace(" ", ""))
    set_output("pr", str(nums[0]) if nums else "")
    return 0


# ------------------------------------------------------------------ gate


def publish_check(gh_app: GitHub, head: str, passed: bool, title: str, text: str) -> None:
    gh_app.request(
        "POST",
        f"/repos/{gh_app.repo}/check-runs",
        {
            "name": policy.GATE_CHECK_NAME,
            "head_sha": head,
            "status": "completed",
            "conclusion": "success" if passed else "failure",
            "output": {"title": title, "summary": ledger.neutralise(text)[:60000]},
        },
    )


def cmd_gate(args: argparse.Namespace) -> int:
    gh = client()
    app = client("REVIEW_LOOP_APP_TOKEN") if args.publish else None
    try:
        snap = take(gh, args.pr)
    except HeadMovedError:
        log("head moved during evaluation; the next event re-evaluates it")
        return 0
    except GitHubError as err:
        log(f"gate evaluation failed: {err}")
        if app is not None:
            pr = gh.get(f"/repos/{gh.repo}/pulls/{args.pr}")
            publish_check(
                app, pr["head"]["sha"], False, "Merge gate blocked", f"evaluation error: {err}"
            )
        return 1
    result = gate(snap)
    text = "\n".join(result.lines)
    summary(f"### {policy.GATE_CHECK_NAME} for #{args.pr} @ {result.head_sha[:12]}\n{text}")
    if app is not None:
        publish_check(app, result.head_sha, result.passed, result.title, text)
    set_output("passed", "true" if result.passed else "false")
    return 0


# ------------------------------------------------------------------ loop


def render_prompt(head: str, attempt: int, count: int) -> str:
    template = (Path(__file__).resolve().parent / "prompt.md").read_text(encoding="utf-8")
    return template.format(
        head_sha=head, attempt=attempt, max_attempts=policy.MAX_FIX_ATTEMPTS, count=count
    )


def cmd_triage(args: argparse.Namespace) -> int:
    gh = client()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    set_output("action", Action.NONE.value)
    try:
        snap = take(gh, args.pr)
    except HeadMovedError:
        log("head moved during triage; the next event handles the new head")
        return 0
    failed_sha = _sha(args.ci_failed_sha) if args.ci_failed_sha else None
    decision = plan_loop(snap, ci_failed_run_sha=failed_sha)
    log(f"decision: {decision.action} - {decision.reason}")
    summary(f"### review loop triage for #{args.pr}\n- {decision.action}: {decision.reason}")
    set_output("action", decision.action.value)
    set_output("reason", safe(decision.reason))
    set_output("head_sha", decision.head_sha)
    set_output("attempt", str(decision.attempt))
    set_output("report_key", decision.report_key)
    if decision.action is Action.FIX:
        # Only an eligible PR reaches FIX, so the branch matched APPROVED_BRANCH.
        set_output("head_ref", str(snap.pr["head"]["ref"]))
        (out / "findings.json").write_text(
            json.dumps({"head_sha": decision.head_sha, "findings": decision.findings}, indent=2),
            encoding="utf-8",
        )
        (out / "prompt.md").write_text(
            render_prompt(decision.head_sha, decision.attempt, len(decision.findings)),
            encoding="utf-8",
        )
    return 0


def cmd_claim(args: argparse.Namespace) -> int:
    gh = client()
    head = _sha(args.head)
    base = f"/repos/{gh.repo}"
    set_output("won", "false")
    pr = gh.get(f"{base}/pulls/{args.pr}")
    if pr["head"]["sha"] != head:
        log("head moved since triage; not claiming")
        return 0
    labels = {lb.get("name") for lb in pr.get("labels") or []}
    if policy.LABEL_HALTED in labels or policy.LABEL_OPT_OUT in labels:
        log("loop is halted or switched off for this PR")
        return 0
    comments = gh.paginate(f"{base}/issues/{args.pr}/comments")
    cl = ledger.claims(comments, gh.repo, args.pr)
    if head in ledger.claimed_heads(cl):
        log("head already claimed (duplicate event)")
        return 0
    if ledger.attempts_used(cl) >= policy.MAX_FIX_ATTEMPTS:
        log("fix attempts exhausted")
        return 0
    attempt = ledger.attempts_used(cl) + 1
    posted = gh.request(
        "POST",
        f"{base}/issues/{args.pr}/comments",
        {"body": ledger.claim_body(head, attempt, args.run_id)},
    )
    comments = gh.paginate(f"{base}/issues/{args.pr}/comments")
    verdict = ledger.verify_claim(
        ledger.claims(comments, gh.repo, args.pr), head, int(posted["id"])
    )
    log(f"claim: {verdict.reason}")
    set_output("won", "true" if verdict.won else "false")
    set_output("attempt", str(verdict.attempt))
    return 0


def _load_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def cmd_check_patch(args: argparse.Namespace) -> int:
    text = Path(args.patch).read_text(encoding="utf-8", errors="replace")
    report = patch_policy.check_patch(text)
    findings = _load_json(args.findings) or {}
    ids = [
        f["comment_id"]
        for f in findings.get("findings", [])
        if isinstance(f.get("comment_id"), int)
    ]
    verdicts = patch_policy.check_verdicts(_load_json(args.verdicts), ids, report)
    if args.expect_sha256:
        digest = hashlib.sha256(Path(args.patch).read_bytes()).hexdigest()
        if digest != args.expect_sha256:
            report.problems.append("patch does not match the digest recorded by the fix job")
            report.ok = False
    if args.repo and report.files:
        listed = subprocess.run(  # noqa: S603 - fixed argv, paths already validated
            ["git", "-C", args.repo, "ls-files", "-s", "--", *report.files],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        mode_problems = patch_policy.check_existing_modes(listed)
        if mode_problems:
            report.problems += mode_problems
            report.ok = False
    lines = [f"- files: {len(report.files)}, changed lines: {report.changed_lines}"]
    lines += [f"- patch: {p}" for p in report.problems]
    lines += [f"- verdicts: {p}" for p in verdicts.problems]
    lines += [f"- finding {r['comment_id']}: {r['verdict']}" for r in verdicts.rows]
    summary("### automated patch check\n" + "\n".join(lines))
    set_output("empty", "true" if report.empty else "false")
    set_output("needs_human", "true" if verdicts.needs_human else "false")
    ok = report.ok and verdicts.ok and not verdicts.needs_human
    set_output("ok", "true" if ok else "false")
    for line in lines:
        log(line)
    return 0 if ok else 1


def cmd_prepush(args: argparse.Namespace) -> int:
    """Last check before the push: same head, still eligible, still our attempt."""
    gh = client()
    head = _sha(args.head)
    base = f"/repos/{gh.repo}"
    pr = gh.get(f"{base}/pulls/{args.pr}")
    snap = Snapshot(
        gh.repo, pr, [], [], gh.paginate(f"{base}/issues/{args.pr}/comments"), [], [], [], {}
    )
    problems = eligibility(snap)
    if pr["head"]["sha"] != head:
        problems.append("the branch moved since the fix started")
    if pr["head"]["ref"] != args.branch:
        problems.append("branch name changed")
    if snap.labels & {policy.LABEL_HALTED, policy.LABEL_OPT_OUT}:
        problems.append("loop halted or switched off")
    cl = [c for c in ledger.claims(snap.issue_comments, gh.repo, args.pr) if c.head == head]
    if not cl or cl[0].attempt != args.attempt:
        problems.append("this run does not hold the claim for the head commit")
    for p in problems:
        log(f"prepush: {p}")
    return 1 if problems else 0


def cmd_rereview(args: argparse.Namespace) -> int:
    """Ask Codex to review the new head (with the request token if configured)."""
    env = (
        "REVIEW_LOOP_REQUEST_TOKEN"
        if os.environ.get("REVIEW_LOOP_REQUEST_TOKEN")
        else "REVIEW_LOOP_APP_TOKEN"
    )
    gh = client(env)
    head = _sha(args.head)
    data = json.dumps({"head": head}, sort_keys=True)
    gh.request(
        "POST",
        f"/repos/{gh.repo}/issues/{args.pr}/comments",
        {"body": f"@codex review\n\n<!-- {policy.REREVIEW_MARKER} {data} -->"},
    )
    return 0


OUTCOMES: dict[str, tuple[str, bool]] = {
    # outcome: (message, halt)
    "pushed": ("Pushed an automated fix and asked Codex to review the new head.", False),
    "no-change": ("No code change was needed or safe; nothing was pushed.", True),
    "needs-human": ("At least one finding needs a human decision; nothing was pushed.", True),
    "claude-failed": ("The Claude Code step failed; nothing was pushed.", True),
    "policy-failed": ("The automated patch broke the patch policy; nothing was pushed.", True),
    "tests-failed": ("The automated patch failed the test suite; nothing was pushed.", True),
    "push-refused": (
        "The branch moved or the claim was lost before pushing; nothing was pushed.",
        True,
    ),
    "rereview-failed": ("A fix was pushed but requesting the Codex re-review failed.", True),
    "halt": ("The review loop stopped.", True),
    "report": ("The review loop could not act on this review.", False),
}


def cmd_report(args: argparse.Namespace) -> int:
    gh = client()
    if args.outcome not in OUTCOMES:
        raise SystemExit("unknown outcome")
    message, halt = OUTCOMES[args.outcome]
    key = args.key or f"attempt:{_sha(args.head)}"
    base = f"/repos/{gh.repo}"
    comments = gh.paginate(f"{base}/issues/{args.pr}/comments")
    if key in ledger.report_keys(comments, gh.repo, args.pr):
        log("already reported")
        return 0
    parts = [f"**Review loop** - {message}"]
    if args.reason:
        parts.append(f"Reason: {args.reason}")
    # Only the finding id and the verdict enum are published. The model's
    # free-text reasons stay in the (short-lived) run artefact: the model ran
    # beside a secret, so its prose is never posted to a public page.
    rows = _load_json(args.verdicts) if args.verdicts else None
    if isinstance(rows, dict) and isinstance(rows.get("findings"), list):
        parts.append("| finding | verdict |\n| --- | --- |")
        for r in rows["findings"][: policy.MAX_FINDINGS]:
            if not isinstance(r, dict):
                continue
            cid, verdict = r.get("comment_id"), r.get("verdict")
            if isinstance(cid, int) and verdict in patch_policy.VERDICTS:
                parts.append(f"| {cid} | {verdict} |")
    if halt:
        parts.append(
            f"The `{policy.LABEL_HALTED}` label was added. The loop will not act on this "
            "PR again until a maintainer removes it."
        )
    parts.append(
        f"Run: {os.environ.get('GITHUB_SERVER_URL', '')}/{gh.repo}/actions/runs/"
        f"{os.environ.get('GITHUB_RUN_ID', '')}"
    )
    kind = "halted" if halt else "status"
    gh.request(
        "POST",
        f"{base}/issues/{args.pr}/comments",
        {"body": ledger.report_body(key, kind, "\n\n".join(parts))},
    )
    if halt:
        gh.request("POST", f"{base}/issues/{args.pr}/labels", {"labels": [policy.LABEL_HALTED]})
    return 0


# ------------------------------------------------------------------ main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="review_loop")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("resolve").set_defaults(func=cmd_resolve)

    p = sub.add_parser("gate")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--publish", action="store_true")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("triage")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--ci-failed-sha", default="")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("claim")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--run-id", required=True)
    p.set_defaults(func=cmd_claim)

    p = sub.add_parser("check-patch")
    p.add_argument("--patch", required=True)
    p.add_argument("--findings", required=True)
    p.add_argument("--verdicts", required=True)
    p.add_argument("--expect-sha256", default="")
    p.add_argument("--repo", default="", help="checkout the patch applies to (checks modes)")
    p.set_defaults(func=cmd_check_patch)

    p = sub.add_parser("prepush")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--attempt", type=int, required=True)
    p.set_defaults(func=cmd_prepush)

    p = sub.add_parser("rereview")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--head", required=True)
    p.set_defaults(func=cmd_rereview)

    p = sub.add_parser("report")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--outcome", required=True)
    p.add_argument("--head", default="")
    p.add_argument("--key", default="")
    p.add_argument("--reason", default="")
    p.add_argument("--verdicts", default="")
    p.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except GitHubError as err:
        log(f"error: {err}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
