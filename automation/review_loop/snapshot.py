"""Fetch a consistent snapshot of one pull request.

Every list comes from an endpoint scoped to this pull request, so an artefact
from another PR cannot be mixed in; the artefact URLs are checked again in
``codex.py``. If the head commit moves while the snapshot is taken, the
snapshot is refused rather than evaluated against a mix of two heads.
"""

from __future__ import annotations

from typing import Any

from review_loop import policy
from review_loop.codex import Thread
from review_loop.evaluate import Snapshot, latest_ci_run
from review_loop.github import GitHub, GitHubError

_THREADS = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes { isResolved comments(first: 1) { nodes { databaseId } } }
      }
    }
  }
}
"""


class HeadMovedError(GitHubError):
    """The pull request's head changed while the snapshot was being taken."""


def fetch_threads(gh: GitHub, number: int) -> list[Thread]:
    owner, name = gh.repo.split("/")
    out: list[Thread] = []
    after: str | None = None
    for _ in range(policy.MAX_PAGES):
        data = gh.graphql(
            _THREADS, {"owner": owner, "name": name, "number": number, "after": after}
        )
        conn = data["repository"]["pullRequest"]["reviewThreads"]
        for node in conn["nodes"]:
            first = node["comments"]["nodes"]
            if first and isinstance(first[0].get("databaseId"), int):
                out.append(Thread(first[0]["databaseId"], bool(node["isResolved"])))
        if not conn["pageInfo"]["hasNextPage"]:
            return out
        after = conn["pageInfo"]["endCursor"]
    raise GitHubError("too many review threads; refusing to continue")


def take(gh: GitHub, number: int) -> Snapshot:
    base = f"/repos/{gh.repo}"
    pr: dict[str, Any] = gh.get(f"{base}/pulls/{number}")
    head = pr["head"]["sha"]
    snap = Snapshot(
        repo=gh.repo,
        pr=pr,
        reviews=gh.paginate(f"{base}/pulls/{number}/reviews"),
        review_comments=gh.paginate(f"{base}/pulls/{number}/comments"),
        issue_comments=gh.paginate(f"{base}/issues/{number}/comments"),
        threads=fetch_threads(gh, number),
        files=gh.paginate(f"{base}/pulls/{number}/files"),
        ci_runs=gh.paginate(
            f"{base}/actions/workflows/ci.yml/runs?head_sha={head}&event=pull_request",
            key="workflow_runs",
        ),
        ci_jobs={},
        head_commit=gh.get(f"{base}/commits/{head}"),
    )
    run = latest_ci_run(snap)
    if run is not None:
        snap.ci_jobs[int(run["id"])] = gh.paginate(
            f"{base}/actions/runs/{int(run['id'])}/jobs?filter=latest", key="jobs"
        )
    again = gh.get(f"{base}/pulls/{number}")
    if again["head"]["sha"] != head:
        raise HeadMovedError("head commit changed while the snapshot was taken")
    return snap
