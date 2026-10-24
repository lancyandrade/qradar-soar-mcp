"""Pure decisions over a pull-request snapshot: the merge gate and the loop step.

Nothing here performs I/O. ``snapshot.py`` fetches; this module decides; the
CLI acts. Every branch that is not positively proven good fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from review_loop import ledger, policy
from review_loop.codex import Assessment, Status, Thread, assess

_SHA = re.compile(r"[0-9a-f]{40}")


@dataclass
class Snapshot:
    """Everything fetched for one pull request at one moment."""

    repo: str
    pr: dict[str, Any]
    reviews: list[Any]
    review_comments: list[Any]
    issue_comments: list[Any]
    threads: list[Thread]
    files: list[Any]
    ci_runs: list[Any]
    ci_jobs: dict[int, list[Any]]
    head_commit: dict[str, Any] = field(default_factory=dict)

    @property
    def number(self) -> int:
        return int(self.pr["number"])

    @property
    def head_sha(self) -> str:
        return str(self.pr["head"]["sha"])

    @property
    def labels(self) -> set[str]:
        return {lb.get("name", "") for lb in self.pr.get("labels") or [] if isinstance(lb, dict)}


# ------------------------------------------------------------------ eligibility


def eligibility(snap: Snapshot) -> list[str]:
    """Reasons this PR may not be processed. Empty means eligible."""
    pr, repo = snap.pr, snap.repo
    problems: list[str] = []
    head, base = pr.get("head") or {}, pr.get("base") or {}
    if pr.get("state") != "open":
        problems.append("pull request is not open")
    if pr.get("draft"):
        problems.append("pull request is a draft")
    if base.get("ref") != policy.BASE_BRANCH:
        problems.append(f"base branch is not {policy.BASE_BRANCH}")
    if (base.get("repo") or {}).get("full_name") != repo:
        problems.append("base repository mismatch")
    if (head.get("repo") or {}).get("full_name") != repo:
        problems.append("head branch is not in this repository (fork)")
    ref = head.get("ref")
    if not isinstance(ref, str) or not policy.APPROVED_BRANCH.fullmatch(ref):
        problems.append("head branch is not an approved branch name")
    if not isinstance(head.get("sha"), str) or not _SHA.fullmatch(head["sha"]):
        problems.append("head sha is not a full sha")
    if pr.get("author_association") not in policy.TRUSTED_AUTHOR_ASSOCIATIONS:
        problems.append("pull request author is not a repository collaborator")
    return problems


# ------------------------------------------------------------------ CI


class CIStatus(StrEnum):
    SUCCESS = "success"
    PENDING = "pending"
    FAILED = "failed"
    MISSING = "missing"


@dataclass(frozen=True)
class CIResult:
    status: CIStatus
    reason: str
    run_id: int | None = None


def latest_ci_run(snap: Snapshot) -> dict[str, Any] | None:
    runs = [
        r
        for r in snap.ci_runs
        if isinstance(r, dict)
        and r.get("head_sha") == snap.head_sha
        and r.get("path") == policy.CI_WORKFLOW_PATH
        and r.get("event") == "pull_request"
        and (r.get("head_repository") or {}).get("full_name") == snap.repo
    ]
    if not runs:
        return None
    return max(
        runs, key=lambda r: (r.get("run_number", 0), r.get("run_attempt", 0), r.get("id", 0))
    )


def assess_ci(snap: Snapshot) -> CIResult:
    run = latest_ci_run(snap)
    if run is None:
        return CIResult(CIStatus.MISSING, "no CI run for the head commit")
    run_id = int(run["id"])
    if run.get("status") != "completed":
        return CIResult(CIStatus.PENDING, f"CI run {run_id} is {run.get('status')}", run_id)
    if run.get("conclusion") != "success":
        return CIResult(
            CIStatus.FAILED, f"CI run {run_id} concluded {run.get('conclusion')}", run_id
        )
    jobs = {j.get("name"): j for j in snap.ci_jobs.get(run_id, []) if isinstance(j, dict)}
    for name in sorted(policy.REQUIRED_CI_JOBS):
        job = jobs.get(name)
        if job is None:
            return CIResult(CIStatus.FAILED, f"required CI job missing: {name}", run_id)
        if job.get("head_sha") not in (None, snap.head_sha):
            return CIResult(CIStatus.FAILED, f"CI job {name} ran on another commit", run_id)
        if job.get("conclusion") != "success":
            return CIResult(CIStatus.FAILED, f"CI job {name}: {job.get('conclusion')}", run_id)
    return CIResult(CIStatus.SUCCESS, f"CI run {run_id}: all required jobs succeeded", run_id)


# ------------------------------------------------------------------ security


def sensitive_files(snap: Snapshot) -> list[str] | None:
    """Changed paths under a sensitive prefix. None when the file list is incomplete."""
    changed = snap.pr.get("changed_files")
    if not isinstance(changed, int) or changed != len(snap.files):
        return None
    hits: set[str] = set()
    for f in snap.files:
        for key in ("filename", "previous_filename"):
            path = f.get(key) if isinstance(f, dict) else None
            if isinstance(path, str) and (
                policy.path_matches(path, policy.SENSITIVE_PATH_PREFIXES)
                or policy.has_sensitive_name(path)
            ):
                hits.add(path)
    return sorted(hits)


def sensitive_approved(snap: Snapshot) -> bool:
    """A repository owner approved this exact head commit's sensitive changes."""
    for c in snap.issue_comments:
        if not isinstance(c, dict):
            continue
        user = c.get("user") or {}
        if user.get("type") != "User" or c.get("author_association") != "OWNER":
            continue
        if c.get("performed_via_github_app") is not None:
            continue
        body = c.get("body")
        if isinstance(body, str) and snap.head_sha in policy.SENSITIVE_APPROVAL.findall(body):
            return True
    return False


def security_problems(snap: Snapshot, codex: Assessment) -> list[str]:
    problems = []
    if policy.LABEL_HALTED in snap.labels:
        problems.append(f"label {policy.LABEL_HALTED} is set")
    sens = sensitive_files(snap)
    if sens is None:
        problems.append("could not list every changed file")
    elif sens and not sensitive_approved(snap):
        shown = ", ".join(sens[:5]) + (" ..." if len(sens) > 5 else "")
        problems.append(
            f"sensitive paths changed ({shown}); needs an owner comment "
            f"'review-loop: approve-sensitive {snap.head_sha}'"
        )
    if not codex.security_ok:
        problems.append("Codex security review of the head commit is not clean")
    return problems


# ------------------------------------------------------------------ gate


@dataclass
class GateResult:
    passed: bool
    head_sha: str
    lines: list[str]

    @property
    def title(self) -> str:
        return "Merge gate passed" if self.passed else "Merge gate blocked"


def codex_assessment(snap: Snapshot) -> Assessment:
    return assess(
        repo=snap.repo,
        number=snap.number,
        head_sha=snap.head_sha,
        reviews=snap.reviews,
        review_comments=snap.review_comments,
        issue_comments=snap.issue_comments,
        threads=snap.threads,
    )


def gate(snap: Snapshot) -> GateResult:
    lines: list[str] = []
    ok = True
    elig = eligibility(snap)
    if elig:
        ok = False
        lines += [f"- eligibility: {p}" for p in elig]
    ci = assess_ci(snap)
    lines.append(f"- CI: {ci.status} ({ci.reason})")
    ok = ok and ci.status is CIStatus.SUCCESS
    codex = codex_assessment(snap)
    lines.append(f"- Codex: {codex.status} ({'; '.join(codex.reasons) or 'no detail'})")
    ok = ok and codex.status is Status.CLEAN
    sec = security_problems(snap, codex)
    lines += [f"- security: {p}" for p in sec] or ["- security: requirements satisfied"]
    ok = ok and not sec
    return GateResult(ok, snap.head_sha, lines)


# ------------------------------------------------------------------ loop step


class Action(StrEnum):
    NONE = "none"  # nothing to do (log only)
    FIX = "fix"  # start a fix attempt
    REPORT = "report"  # post a one-off report, do not halt
    HALT = "halt"  # post a report and set the halted label


@dataclass
class LoopDecision:
    action: Action
    reason: str
    head_sha: str
    attempt: int = 0
    report_key: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)


def _once(snap: Snapshot, key: str, action: Action, reason: str, **kw: Any) -> LoopDecision:
    """Report each condition once per key: a repeated event must not repeat it."""
    if key in ledger.report_keys(snap.issue_comments, snap.repo, snap.number):
        return LoopDecision(Action.NONE, f"already reported: {reason}", snap.head_sha)
    return LoopDecision(action, reason, snap.head_sha, report_key=key, **kw)


def is_automation_commit(commit: dict[str, Any]) -> bool:
    msg = ((commit.get("commit") or {}).get("message")) or ""
    author = (commit.get("commit") or {}).get("author") or {}
    return (
        f"\n{policy.TRAILER_ATTEMPT}: " in msg
        and author.get("email") == policy.COMMIT_AUTHOR_EMAIL
        and author.get("name") == policy.COMMIT_AUTHOR_NAME
    )


def plan_loop(snap: Snapshot, *, ci_failed_run_sha: str | None = None) -> LoopDecision:
    """Decide the next loop step for the PR's current head commit."""
    head = snap.head_sha
    elig = eligibility(snap)
    if elig:
        return LoopDecision(Action.NONE, "not eligible: " + "; ".join(elig), head)
    if policy.LABEL_OPT_OUT in snap.labels:
        return LoopDecision(Action.NONE, f"label {policy.LABEL_OPT_OUT} is set", head)
    if policy.LABEL_HALTED in snap.labels:
        return LoopDecision(Action.NONE, f"label {policy.LABEL_HALTED} is set", head)

    if ci_failed_run_sha is not None:
        if ci_failed_run_sha == head and is_automation_commit(snap.head_commit):
            return _once(
                snap, f"ci-failed:{head}", Action.HALT, "CI failed on an automated fix commit"
            )
        return LoopDecision(Action.NONE, "CI failure is not on an automated head commit", head)

    codex = codex_assessment(snap)
    if codex.status is Status.INCOMPLETE:
        return _once(
            snap,
            f"incomplete:{head}",
            Action.REPORT,
            "Codex review data is incomplete: " + "; ".join(codex.reasons),
        )
    if codex.status is not Status.FINDINGS:
        return LoopDecision(Action.NONE, f"Codex status {codex.status}", head)
    if len(codex.findings) > policy.MAX_FINDINGS:
        return _once(
            snap,
            f"too-many:{head}",
            Action.HALT,
            f"{len(codex.findings)} findings exceed the automated limit of {policy.MAX_FINDINGS}",
        )

    if not any(f.commit_id == head for f in codex.findings):
        # Codex's review of the head added nothing; what is open are threads from
        # older commits that nobody resolved. A fix attempt would only re-check
        # them, so ask a person instead of spending an attempt.
        return _once(
            snap,
            f"old-threads:{head}",
            Action.REPORT,
            f"Codex found nothing new on the head, but {len(codex.findings)} thread(s) from "
            "older commits are unresolved; resolve them if they are fixed",
        )

    cl = ledger.claims(snap.issue_comments, snap.repo, snap.number)
    if head in ledger.claimed_heads(cl):
        return LoopDecision(
            Action.NONE, "this head commit was already claimed (duplicate event)", head
        )
    used = ledger.attempts_used(cl)
    if used >= policy.MAX_FIX_ATTEMPTS:
        return _once(
            snap,
            "exhausted",
            Action.HALT,
            f"all {policy.MAX_FIX_ATTEMPTS} automated fix attempts are used and Codex still "
            f"reports {len(codex.findings)} unresolved finding(s)",
        )
    return LoopDecision(
        Action.FIX,
        f"{len(codex.findings)} finding(s) on {head[:12]}",
        head,
        attempt=used + 1,
        findings=[f.as_dict() for f in codex.findings],
    )
