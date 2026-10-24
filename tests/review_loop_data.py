"""Builders for fake GitHub API objects used by the review-loop tests.

Shapes mirror what GitHub returned for this repository's PR #11 (Codex
review, inline comments, summary comment, workflow runs), reduced to the
fields the automation reads. Everything is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

from review_loop import policy
from review_loop.codex import RECEIPT_MARKER, Thread
from review_loop.evaluate import Snapshot

REPO = "lancyandrade/qradar-soar-mcp"
NUMBER = 42
HEAD = "a" * 40
OLD = "b" * 40
OTHER = "c" * 40
API = f"https://api.github.com/repos/{REPO}"

CODEX_USER = {"login": policy.CODEX.bot_login, "id": policy.CODEX.bot_user_id, "type": "Bot"}
CODEX_APP = {
    "id": policy.CODEX.app_id,
    "slug": policy.CODEX.app_slug,
    "owner": {"login": policy.CODEX.app_owner},
}
ACTIONS_USER = {
    "login": policy.GITHUB_ACTIONS.bot_login,
    "id": policy.GITHUB_ACTIONS.bot_user_id,
    "type": "Bot",
}
OWNER_USER = {"login": "lancyandrade", "id": 33344501, "type": "User"}

_ids = iter(range(1000, 10**6))


def next_id() -> int:
    return next(_ids)


def pr(
    *,
    head: str = HEAD,
    ref: str = "phase2/p2-05-example",
    labels: tuple[str, ...] = (),
    fork: bool = False,
    draft: bool = False,
    state: str = "open",
    author_association: str = "OWNER",
    changed_files: int = 1,
    base_ref: str = "main",
) -> dict[str, Any]:
    head_repo = "someone/qradar-soar-mcp" if fork else REPO
    return {
        "number": NUMBER,
        "state": state,
        "draft": draft,
        "author_association": author_association,
        "changed_files": changed_files,
        "labels": [{"name": n} for n in labels],
        "head": {"sha": head, "ref": ref, "repo": {"full_name": head_repo}},
        "base": {"ref": base_ref, "repo": {"full_name": REPO, "name": REPO.split("/")[1]}},
    }


def receipt_body(sha: str, *, findings: bool) -> str:
    lead = (
        "### 💡 Codex Review\n\nHere are some automated review suggestions for this pull request."
        if findings
        else "Codex Review: Didn't find any major issues. Bravo."
    )
    return f"{RECEIPT_MARKER}\n\n\n{lead}\n\n**Reviewed commit:** `{sha[:10]}`\n"


def review(sha: str = HEAD, *, user: dict[str, Any] | None = None, rid: int | None = None) -> dict:
    return {
        "id": rid or next_id(),
        "user": user or CODEX_USER,
        "body": receipt_body(sha, findings=True),
        "commit_id": sha,
        "state": "COMMENTED",
        "pull_request_url": f"{API}/pulls/{NUMBER}",
    }


def inline(
    rev: dict[str, Any],
    *,
    cid: int | None = None,
    user: dict[str, Any] | None = None,
    priority: str = "P2",
    title: str = "Redact before truncating",
    path: str = "src/qradar_soar_mcp/catalog/workflow_xml.py",
    reply_to: int | None = None,
) -> dict[str, Any]:
    return {
        "id": cid or next_id(),
        "pull_request_review_id": rev["id"],
        "user": user or CODEX_USER,
        "commit_id": rev["commit_id"],
        "original_commit_id": rev["commit_id"],
        "path": path,
        "line": 10,
        "in_reply_to_id": reply_to,
        "html_url": f"https://github.com/{REPO}/pull/{NUMBER}#discussion_r1",
        "pull_request_url": f"{API}/pulls/{NUMBER}",
        "body": (
            f"**<sub><sub>![{priority} Badge](https://img.shields.io/badge/{priority}-yellow"
            f"?style=flat)</sub></sub>  {title}**\n\nDetails of the finding."
        ),
    }


def issue_comment(
    body: str,
    *,
    user: dict[str, Any] | None = None,
    app: dict[str, Any] | None = None,
    cid: int | None = None,
    association: str = "NONE",
    number: int = NUMBER,
) -> dict[str, Any]:
    return {
        "id": cid or next_id(),
        "user": user or OWNER_USER,
        "performed_via_github_app": app,
        "author_association": association,
        "issue_url": f"{API}/issues/{number}",
        "body": body,
    }


def state_body(
    sha: str | None = HEAD,
    *,
    status: str | None = "completed",
    any_findings: bool | None = False,
    unresolved: bool | None = False,
    security: dict[str, Any] | None = None,
) -> str:
    state = {
        "code_review": {
            "commit_sha": sha,
            "has_any_findings": any_findings,
            "has_unresolved_findings": unresolved,
            "status": status,
        },
        "security_review": security
        or {
            "commit_sha": None,
            "has_any_findings": None,
            "has_unresolved_findings": None,
            "status": None,
        },
    }
    return (
        "<!-- codex-pull-request-review-summary -->\n"
        f"<!-- codex-review-state:v1 {json.dumps(state)} -->\n\n## Codex Review Summary\n"
    )


def codex_state(sha: str | None = HEAD, **kw: Any) -> dict[str, Any]:
    return issue_comment(state_body(sha, **kw), user=CODEX_USER, app=CODEX_APP)


def codex_clean_receipt(sha: str = HEAD) -> dict[str, Any]:
    return issue_comment(receipt_body(sha, findings=False), user=CODEX_USER, app=CODEX_APP)


def ci_run(
    sha: str = HEAD,
    *,
    rid: int = 900,
    status: str = "completed",
    conclusion: str | None = "success",
    path: str = policy.CI_WORKFLOW_PATH,
    run_number: int = 1,
    event: str = "pull_request",
) -> dict[str, Any]:
    return {
        "id": rid,
        "head_sha": sha,
        "path": path,
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "run_number": run_number,
        "run_attempt": 1,
        "head_repository": {"full_name": REPO},
    }


def ci_jobs(sha: str = HEAD, *, failing: str | None = None, drop: str | None = None) -> list:
    return [
        {"name": n, "head_sha": sha, "conclusion": "failure" if n == failing else "success"}
        for n in sorted(policy.REQUIRED_CI_JOBS)
        if n != drop
    ]


def snapshot(
    *,
    the_pr: dict[str, Any] | None = None,
    reviews: list[Any] | None = None,
    review_comments: list[Any] | None = None,
    issue_comments: list[Any] | None = None,
    threads: list[Thread] | None = None,
    files: list[Any] | None = None,
    runs: list[Any] | None = None,
    jobs: dict[int, list[Any]] | None = None,
    head_commit: dict[str, Any] | None = None,
) -> Snapshot:
    the_pr = the_pr or pr()
    if review_comments is not None and threads is None:
        threads = [
            Thread(c["id"], False) for c in review_comments if c.get("in_reply_to_id") is None
        ]
    return Snapshot(
        repo=REPO,
        pr=the_pr,
        reviews=reviews or [],
        review_comments=review_comments or [],
        issue_comments=issue_comments if issue_comments is not None else [],
        threads=threads or [],
        files=files if files is not None else [{"filename": "src/qradar_soar_mcp/tools/x.py"}],
        ci_runs=runs if runs is not None else [ci_run(the_pr["head"]["sha"])],
        ci_jobs=jobs if jobs is not None else {900: ci_jobs(the_pr["head"]["sha"])},
        head_commit=head_commit or {},
    )


def clean_snapshot(**kw: Any) -> Snapshot:
    """CI green, Codex completed a clean review of HEAD: the gate must pass."""
    comments = kw.pop("issue_comments", None) or [codex_state(), codex_clean_receipt()]
    return snapshot(issue_comments=comments, **kw)


def findings_snapshot(n: int = 2, *, extra_comments: list[Any] | None = None, **kw: Any):
    rev = review(HEAD)
    inl = [inline(rev, title=f"Finding {i}") for i in range(n)]
    comments = [codex_state(any_findings=True, unresolved=True), *(extra_comments or [])]
    return snapshot(reviews=[rev], review_comments=inl, issue_comments=comments, **kw), rev, inl
