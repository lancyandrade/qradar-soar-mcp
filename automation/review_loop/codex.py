"""Identity checks and parsing for Codex reviews.

Codex (the ``chatgpt-codex-connector`` GitHub App) leaves three kinds of
artefact on a pull request, all observed on this repository:

* a pull-request **review** whose body starts with the receipt marker and names
  the reviewed commit, with one inline review comment per finding;
* an **issue comment** with the same receipt marker when it found nothing;
* one **summary issue comment** it keeps editing, carrying a machine-readable
  ``codex-review-state:v1`` JSON block (commit sha, status, finding flags).

Every function here treats bodies as untrusted text: nothing parsed from a
body is used unless the artefact's author was first proven to be Codex by
numeric id (and, where GitHub exposes it, by GitHub App id).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from review_loop import policy
from review_loop.policy import AppIdentity

RECEIPT_MARKER = "<!-- codex-review-receipt:v1 -->"
_REVIEWED_COMMIT = re.compile(r"\*\*Reviewed commit:\*\*\s*`([0-9a-f]{7,40})`")
_STATE = re.compile(r"<!-- codex-review-state:v1 (\{.*?\}) -->", re.DOTALL)
_BADGE = re.compile(r"!\[(P[0-3]) Badge\]")
_TITLE = re.compile(r"\*\*<sub><sub>!\[P[0-3] Badge\]\([^)]*\)</sub></sub>\s+(.+?)\*\*")
_SHA = re.compile(r"[0-9a-f]{40}")


# ------------------------------------------------------------------ identity


def is_bot_user(user: Any, ident: AppIdentity) -> bool:
    """True only when id, type and login all match. A login alone never passes."""
    return (
        isinstance(user, dict)
        and user.get("id") == ident.bot_user_id
        and user.get("type") == "Bot"
        and user.get("login") == ident.bot_login
    )


def is_app_issue_comment(comment: Any, ident: AppIdentity, *, require_app: bool = True) -> bool:
    """An issue comment written by ``ident``.

    GitHub records the acting App on issue comments; when ``require_app`` is
    set the App id, slug and owner must match as well as the bot user.
    """
    if not isinstance(comment, dict) or not is_bot_user(comment.get("user"), ident):
        return False
    app = comment.get("performed_via_github_app")
    if app is None:
        return not require_app
    return (
        isinstance(app, dict)
        and app.get("id") == ident.app_id
        and app.get("slug") == ident.app_slug
        and isinstance(app.get("owner"), dict)
        and app["owner"].get("login") == ident.app_owner
    )


def belongs_to_pr(item: Any, repo: str, number: int, *, kind: str) -> bool:
    """The artefact's own URL names this repository and pull request."""
    if not isinstance(item, dict):
        return False
    if kind == "issue_comment":
        url = item.get("issue_url", "")
        return isinstance(url, str) and url.endswith(f"/repos/{repo}/issues/{number}")
    url = item.get("pull_request_url", "")
    return isinstance(url, str) and url.endswith(f"/repos/{repo}/pulls/{number}")


# ------------------------------------------------------------------ parsing


def receipt_commit(body: Any) -> str | None:
    """The (possibly abbreviated) reviewed commit named by a receipt, or None."""
    if not isinstance(body, str) or RECEIPT_MARKER not in body:
        return None
    match = _REVIEWED_COMMIT.search(body)
    return match.group(1) if match else None


def has_receipt_marker(body: Any) -> bool:
    return isinstance(body, str) and RECEIPT_MARKER in body


@dataclass(frozen=True)
class ReviewState:
    commit_sha: str | None
    status: str | None
    has_any_findings: bool | None
    has_unresolved_findings: bool | None


@dataclass(frozen=True)
class CodexState:
    code_review: ReviewState
    security_review: ReviewState


class StateParseError(ValueError):
    pass


def _review_state(raw: Any) -> ReviewState:
    if not isinstance(raw, dict):
        raise StateParseError("review state is not an object")
    sha = raw.get("commit_sha")
    status = raw.get("status")
    anyf = raw.get("has_any_findings")
    unres = raw.get("has_unresolved_findings")
    if sha is not None and not (isinstance(sha, str) and _SHA.fullmatch(sha)):
        raise StateParseError("commit_sha is not a full sha")
    if status is not None and not isinstance(status, str):
        raise StateParseError("status is not a string")
    for flag in (anyf, unres):
        if flag is not None and not isinstance(flag, bool):
            raise StateParseError("finding flag is not a boolean")
    return ReviewState(sha, status, anyf, unres)


def parse_state(body: Any) -> CodexState | None:
    """Parse the ``codex-review-state:v1`` block. None if absent; raises if malformed."""
    if not isinstance(body, str):
        return None
    matches = _STATE.findall(body)
    if not matches:
        return None
    if len(matches) > 1:
        raise StateParseError("more than one state block")
    try:
        raw = json.loads(matches[0])
    except json.JSONDecodeError as err:
        raise StateParseError("state block is not JSON") from err
    if not isinstance(raw, dict) or "code_review" not in raw:
        raise StateParseError("state block has no code_review")
    security = raw.get("security_review") or {
        "commit_sha": None,
        "status": None,
        "has_any_findings": None,
        "has_unresolved_findings": None,
    }
    return CodexState(_review_state(raw["code_review"]), _review_state(security))


@dataclass(frozen=True)
class Finding:
    comment_id: int
    review_id: int
    commit_id: str
    path: str
    line: int | None
    priority: str
    title: str
    body: str
    url: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "comment_id": self.comment_id,
            "review_id": self.review_id,
            "commit_id": self.commit_id,
            "path": self.path,
            "line": self.line,
            "priority": self.priority,
            "title": self.title,
            "body": self.body,
            "url": self.url,
        }


def to_finding(comment: dict[str, Any]) -> Finding:
    raw_body = comment.get("body")
    body: str = raw_body if isinstance(raw_body, str) else ""
    badge = _BADGE.search(body)
    title = _TITLE.search(body)
    line = comment.get("line") if isinstance(comment.get("line"), int) else None
    if line is None and isinstance(comment.get("original_line"), int):
        line = comment["original_line"]
    return Finding(
        comment_id=int(comment["id"]),
        review_id=int(comment["pull_request_review_id"]),
        commit_id=str(comment.get("commit_id") or ""),
        path=str(comment.get("path") or ""),
        line=line,
        priority=badge.group(1) if badge else "unknown",
        title=(title.group(1).strip() if title else "")[:300],
        body=body[: policy.MAX_FINDING_BODY_CHARS],
        url=str(comment.get("html_url") or ""),
    )


# ------------------------------------------------------------------ assessment


class Status(StrEnum):
    CLEAN = "clean"  # completed review of the head commit, no unresolved finding
    FINDINGS = "findings"  # completed review of the head commit with unresolved findings
    PENDING = "pending"  # a review of the head commit is still running
    STALE = "stale"  # the latest review is of an older commit
    MISSING = "missing"  # no Codex review of the head commit
    INCOMPLETE = "incomplete"  # inconsistent or partial review data


@dataclass
class Assessment:
    status: Status
    head_sha: str
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    security_ok: bool = True


@dataclass(frozen=True)
class Thread:
    """A review thread, keyed by its first comment's database id (GraphQL)."""

    first_comment_id: int
    is_resolved: bool


def assess(
    *,
    repo: str,
    number: int,
    head_sha: str,
    reviews: list[Any],
    review_comments: list[Any],
    issue_comments: list[Any],
    threads: list[Thread],
) -> Assessment:
    """Decide what Codex has said about ``head_sha``. Every doubt fails closed."""
    if not _SHA.fullmatch(head_sha):
        return Assessment(Status.INCOMPLETE, head_sha, ["head sha is not a full sha"])
    reasons: list[str] = []

    codex_reviews = [
        r
        for r in reviews
        if is_bot_user(r.get("user") if isinstance(r, dict) else None, policy.CODEX)
        and belongs_to_pr(r, repo, number, kind="review")
    ]
    codex_issue = [
        c
        for c in issue_comments
        if is_app_issue_comment(c, policy.CODEX)
        and belongs_to_pr(c, repo, number, kind="issue_comment")
    ]
    codex_inline = [
        c
        for c in review_comments
        if is_bot_user(c.get("user") if isinstance(c, dict) else None, policy.CODEX)
        and belongs_to_pr(c, repo, number, kind="review_comment")
        and c.get("in_reply_to_id") is None
    ]

    # --- the state block (exactly one summary comment)
    states: list[CodexState] = []
    for c in codex_issue:
        try:
            parsed = parse_state(c.get("body"))
        except StateParseError as err:
            return Assessment(Status.INCOMPLETE, head_sha, [f"malformed Codex state: {err}"])
        if parsed is not None:
            states.append(parsed)
    if len(states) > 1:
        return Assessment(Status.INCOMPLETE, head_sha, ["more than one Codex state comment"])
    state = states[0] if states else None

    # --- receipts naming the head commit
    head_reviews: list[dict[str, Any]] = []
    for r in codex_reviews:
        if not has_receipt_marker(r.get("body")):
            continue
        named = receipt_commit(r.get("body"))
        commit_id = r.get("commit_id")
        touches_head = commit_id == head_sha or (named is not None and head_sha.startswith(named))
        consistent = (
            named is not None and isinstance(commit_id, str) and commit_id.startswith(named)
        )
        if touches_head and not consistent:
            return Assessment(
                Status.INCOMPLETE, head_sha, [f"Codex review {r.get('id')} receipt is inconsistent"]
            )
        if commit_id == head_sha:
            head_reviews.append(r)
    clean_receipts = [
        c
        for c in codex_issue
        if (named := receipt_commit(c.get("body"))) is not None and head_sha.startswith(named)
    ]
    malformed = [
        c
        for c in codex_issue
        if has_receipt_marker(c.get("body")) and receipt_commit(c.get("body")) is None
    ]
    if malformed:
        return Assessment(Status.INCOMPLETE, head_sha, ["a Codex receipt names no commit"])

    # --- security review (only binding when it ran on the head commit)
    security_ok = True
    if state is not None and state.security_review.commit_sha == head_sha:
        sec = state.security_review
        if sec.status != "completed" or sec.has_unresolved_findings is not False:
            security_ok = False
            reasons.append(
                f"Codex security review of head is {sec.status or 'unknown'} or has findings"
            )

    if state is None:
        if not head_reviews and not clean_receipts:
            return Assessment(Status.MISSING, head_sha, ["no Codex review of the head commit"])
        # Codex creates and then edits its summary comment; until it appears the
        # review is not settled. Still a failure for the gate.
        return Assessment(Status.PENDING, head_sha, ["Codex receipt without a state comment yet"])

    code = state.code_review
    if code.commit_sha != head_sha:
        if code.commit_sha is None:
            return Assessment(Status.MISSING, head_sha, ["Codex state names no reviewed commit"])
        return Assessment(
            Status.STALE, head_sha, [f"Codex last reviewed {code.commit_sha[:12]}, not the head"]
        )
    if code.status != "completed":
        return Assessment(Status.PENDING, head_sha, [f"Codex review status is {code.status!r}"])
    if not head_reviews and not clean_receipts:
        return Assessment(Status.INCOMPLETE, head_sha, ["Codex state is completed but no receipt"])

    # --- findings: every top-level Codex inline comment whose thread is open
    by_first = {t.first_comment_id: t for t in threads}
    head_review_ids = {r["id"] for r in head_reviews}
    findings: list[Finding] = []
    head_inline = 0
    for c in codex_inline:
        if c.get("pull_request_review_id") in head_review_ids:
            head_inline += 1
        thread = by_first.get(c.get("id"))
        if thread is None:
            return Assessment(
                Status.INCOMPLETE, head_sha, [f"no review thread for comment {c.get('id')}"]
            )
        if not thread.is_resolved:
            findings.append(to_finding(c))

    for r in head_reviews:
        if not any(c.get("pull_request_review_id") == r["id"] for c in codex_inline):
            return Assessment(
                Status.INCOMPLETE, head_sha, [f"Codex review {r['id']} has no retrievable findings"]
            )
    if code.has_any_findings is True and head_inline == 0:
        return Assessment(
            Status.INCOMPLETE, head_sha, ["Codex reports findings but none were retrieved"]
        )
    if code.has_any_findings is None or code.has_unresolved_findings is None:
        return Assessment(Status.INCOMPLETE, head_sha, ["Codex state finding flags are unknown"])
    if head_reviews and clean_receipts:
        reasons.append("Codex left both a findings review and a clean receipt for the head")
    if code.has_unresolved_findings and not findings:
        return Assessment(
            Status.INCOMPLETE, head_sha, ["Codex reports unresolved findings but none are open"]
        )

    if findings or code.has_unresolved_findings or code.has_any_findings:
        if not findings:
            # has_any_findings but every thread is already resolved by a person.
            reasons.append("findings on the head commit were all resolved")
            return Assessment(Status.CLEAN, head_sha, reasons, [], security_ok)
        reasons.append(f"{len(findings)} unresolved Codex finding(s)")
        return Assessment(Status.FINDINGS, head_sha, reasons, findings, security_ok)
    return Assessment(Status.CLEAN, head_sha, reasons, [], security_ok)
