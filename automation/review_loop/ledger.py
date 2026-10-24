"""The attempt ledger: claim and report comments written by the automation.

A fix attempt starts by posting a claim comment (as ``github-actions[bot]``)
for the head commit it will fix. The ledger is the list of those comments:

* at most one attempt per head commit (the earliest claim wins, which settles
  races between two runs that both posted a claim);
* at most ``policy.MAX_FIX_ATTEMPTS`` distinct head commits per pull request.

Only comments whose author is proven to be ``github-actions[bot]`` by numeric
id count. A person can copy the marker into a comment; it is ignored. A
repository admin can delete claim comments to grant more attempts: that is a
deliberate, visible human override.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from review_loop import policy
from review_loop.codex import belongs_to_pr, is_app_issue_comment

_MARKER = re.compile(r"<!-- (review-loop:[a-z]+:v1) (\{[^<>]*\}) -->")
_SHA = re.compile(r"[0-9a-f]{40}")
_KEY = re.compile(r"[a-z-]{1,40}:[0-9a-f]{40}|[a-z-]{1,40}")


def _automation_markers(
    issue_comments: list[Any], repo: str, number: int, marker: str
) -> list[tuple[int, dict[str, Any]]]:
    out: list[tuple[int, dict[str, Any]]] = []
    for c in issue_comments:
        # GITHUB_TOKEN comments: the bot user id is unique to GitHub Actions;
        # the App block, when GitHub includes it, must match too.
        if not is_app_issue_comment(c, policy.GITHUB_ACTIONS, require_app=False):
            continue
        if not belongs_to_pr(c, repo, number, kind="issue_comment"):
            continue
        body = c.get("body")
        if not isinstance(body, str):
            continue
        for name, raw in _MARKER.findall(body):
            if name != marker:
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and isinstance(c.get("id"), int):
                out.append((c["id"], data))
    out.sort(key=lambda item: item[0])
    return out


@dataclass(frozen=True)
class Claim:
    comment_id: int
    head: str
    attempt: int


def claims(issue_comments: list[Any], repo: str, number: int) -> list[Claim]:
    out = []
    for cid, data in _automation_markers(issue_comments, repo, number, policy.CLAIM_MARKER):
        head, attempt = data.get("head"), data.get("attempt")
        if isinstance(head, str) and _SHA.fullmatch(head) and isinstance(attempt, int):
            out.append(Claim(cid, head, attempt))
    return out


def claimed_heads(cl: list[Claim]) -> list[str]:
    """Distinct claimed head commits, in order of their first claim."""
    seen: list[str] = []
    for c in cl:
        if c.head not in seen:
            seen.append(c.head)
    return seen


def attempts_used(cl: list[Claim]) -> int:
    return len(claimed_heads(cl))


def claim_body(head: str, attempt: int, run_id: str) -> str:
    if not _SHA.fullmatch(head):
        raise ValueError("head must be a full sha")
    data = json.dumps({"head": head, "attempt": attempt, "run": run_id}, sort_keys=True)
    return (
        f"<!-- {policy.CLAIM_MARKER} {data} -->\n"
        f"Review loop: automated fix attempt {attempt}/{policy.MAX_FIX_ATTEMPTS} "
        f"started for head `{head[:12]}` (run {run_id})."
    )


@dataclass(frozen=True)
class ClaimVerdict:
    won: bool
    attempt: int
    reason: str


def verify_claim(cl: list[Claim], head: str, our_comment_id: int) -> ClaimVerdict:
    """After posting a claim, decide whether this run owns the attempt."""
    for_head = [c for c in cl if c.head == head]
    if not for_head:
        return ClaimVerdict(False, 0, "our claim is not visible")
    if for_head[0].comment_id != our_comment_id:
        return ClaimVerdict(False, 0, "another run claimed this head commit first")
    heads = claimed_heads(cl)
    position = heads.index(head) + 1
    if position > policy.MAX_FIX_ATTEMPTS:
        return ClaimVerdict(False, position, "fix attempts exhausted")
    return ClaimVerdict(True, position, "claim won")


# ------------------------------------------------------------------ reports


def report_keys(issue_comments: list[Any], repo: str, number: int) -> set[str]:
    keys = set()
    for _cid, data in _automation_markers(issue_comments, repo, number, policy.REPORT_MARKER):
        key = data.get("key")
        if isinstance(key, str):
            keys.add(key)
    return keys


_ZWSP = chr(0x200B)  # zero-width space: breaks @mentions without changing what is shown


def neutralise(text: str) -> str:
    """Make untrusted text safe to embed in an automation comment.

    It must not be able to forge a hidden ledger marker (``<!--``), close one
    (``-->``), or mention anyone (``@codex`` would request work).
    """
    return text.replace("<!--", "&lt;!--").replace("-->", "--&gt;").replace("@", "@" + _ZWSP)


def report_body(key: str, kind: str, message: str) -> str:
    """``message`` may quote untrusted text; it is neutralised here."""
    if not _KEY.fullmatch(key) or not re.fullmatch(r"[a-z-]{1,40}", kind):
        raise ValueError("invalid report key or kind")
    data = json.dumps({"key": key, "kind": kind}, sort_keys=True)
    return f"<!-- {policy.REPORT_MARKER} {data} -->\n{neutralise(message)}"
