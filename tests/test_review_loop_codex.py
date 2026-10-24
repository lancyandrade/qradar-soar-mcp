"""Review loop: Codex identity, receipts and the head-commit assessment."""

from __future__ import annotations

import pytest

from review_loop import codex, policy
from review_loop.codex import Status, Thread
from review_loop.evaluate import codex_assessment
from tests import review_loop_data as d

# ------------------------------------------------------------------ identity


@pytest.mark.parametrize(
    "user",
    [
        # Right login, wrong id: a look-alike account or a renamed bot.
        {"login": "chatgpt-codex-connector[bot]", "id": 1, "type": "Bot"},
        # Right id, but not a Bot account.
        {"login": "chatgpt-codex-connector[bot]", "id": 199175422, "type": "User"},
        # A person who picked a similar name.
        {"login": "chatgpt-codex-connector", "id": 199175422, "type": "Bot"},
        {"login": "chatgpt-codex-connector[bot]", "type": "Bot"},
        None,
        "chatgpt-codex-connector[bot]",
    ],
)
def test_bot_identity_needs_id_type_and_login(user):
    assert not codex.is_bot_user(user, policy.CODEX)


def test_codex_bot_identity_accepted():
    assert codex.is_bot_user(d.CODEX_USER, policy.CODEX)


@pytest.mark.parametrize(
    "app",
    [
        None,  # Codex issue comments always carry the App; its absence is suspicious
        {**d.CODEX_APP, "id": 1},
        {**d.CODEX_APP, "slug": "chatgpt-codex-connector-x"},
        {**d.CODEX_APP, "owner": {"login": "someone-else"}},
        {"id": policy.CODEX.app_id},
    ],
)
def test_issue_comment_needs_the_codex_app(app):
    comment = d.issue_comment(d.state_body(), user=d.CODEX_USER, app=app)
    assert not codex.is_app_issue_comment(comment, policy.CODEX)


def test_spoofed_state_comment_from_a_person_is_ignored():
    """A human pasting Codex's clean state + receipt cannot make the review clean."""
    spoof = [
        d.issue_comment(d.state_body()),
        d.issue_comment(d.receipt_body(d.HEAD, findings=False)),
    ]
    snap = d.snapshot(issue_comments=spoof)
    assert codex_assessment(snap).status is Status.MISSING


def test_spoofed_review_from_a_lookalike_bot_is_ignored():
    fake_bot = {"login": "chatgpt-codex-connector[bot]", "id": 7, "type": "Bot"}
    rev = d.review(user=fake_bot)
    snap = d.snapshot(
        reviews=[rev],
        review_comments=[d.inline(rev, user=fake_bot)],
        issue_comments=[d.codex_state(), d.codex_clean_receipt()],
    )
    result = codex_assessment(snap)
    assert result.status is Status.CLEAN and result.findings == []


def test_artefacts_from_another_pr_are_ignored():
    """The receipt must belong to this PR: its own URL is checked, not just the listing."""
    other = d.issue_comment(
        d.receipt_body(d.HEAD, findings=False), user=d.CODEX_USER, app=d.CODEX_APP, number=7
    )
    state_other = d.issue_comment(d.state_body(), user=d.CODEX_USER, app=d.CODEX_APP, number=7)
    snap = d.snapshot(issue_comments=[state_other, other])
    assert codex_assessment(snap).status is Status.MISSING

    rev = d.review()
    rev["pull_request_url"] = f"{d.API}/pulls/7"
    snap = d.snapshot(reviews=[rev], issue_comments=[d.codex_state()])
    assert codex_assessment(snap).status is Status.INCOMPLETE  # state but no receipt for this PR


# ------------------------------------------------------------------ parsing


def test_parse_state_round_trip():
    state = codex.parse_state(d.state_body(d.HEAD, any_findings=True, unresolved=True))
    assert state is not None
    assert state.code_review.commit_sha == d.HEAD
    assert state.code_review.status == "completed"
    assert state.code_review.has_unresolved_findings is True


@pytest.mark.parametrize(
    "body",
    [
        "<!-- codex-review-state:v1 {not json} -->",
        '<!-- codex-review-state:v1 {"code_review": {"commit_sha": "abc"}} -->',
        '<!-- codex-review-state:v1 {"code_review": {"has_any_findings": "no"}} -->',
        '<!-- codex-review-state:v1 {"security_review": {}} -->',
        d.state_body() + d.state_body(),
    ],
)
def test_malformed_state_is_rejected(body):
    with pytest.raises(codex.StateParseError):
        codex.parse_state(body)


def test_malformed_state_comment_makes_the_review_incomplete():
    bad = d.issue_comment(
        "<!-- codex-review-state:v1 {oops} -->", user=d.CODEX_USER, app=d.CODEX_APP
    )
    assert codex_assessment(d.snapshot(issue_comments=[bad])).status is Status.INCOMPLETE


def test_receipt_commit_parsing():
    assert codex.receipt_commit(d.receipt_body(d.HEAD, findings=False)) == d.HEAD[:10]
    assert codex.receipt_commit("**Reviewed commit:** `aaaaaaaaaa`") is None  # no marker
    assert codex.receipt_commit(f"{codex.RECEIPT_MARKER}\n**Reviewed commit:** `abc`") is None


def test_finding_fields():
    rev = d.review()
    f = codex.to_finding(d.inline(rev, priority="P1", title="Validate graph references"))
    assert (f.priority, f.title, f.review_id) == ("P1", "Validate graph references", rev["id"])
    huge = d.inline(rev)
    huge["body"] = "x" * (policy.MAX_FINDING_BODY_CHARS + 50)
    assert len(codex.to_finding(huge).body) == policy.MAX_FINDING_BODY_CHARS


# ------------------------------------------------------------------ stale / missing / pending


def test_clean_review_of_head():
    assert codex_assessment(d.clean_snapshot()).status is Status.CLEAN


def test_no_codex_activity_is_missing():
    assert codex_assessment(d.snapshot(issue_comments=[])).status is Status.MISSING


def test_review_of_an_older_commit_is_stale():
    """A clean review of the previous head says nothing about the new head."""
    snap = d.snapshot(issue_comments=[d.codex_state(d.OLD), d.codex_clean_receipt(d.OLD)])
    result = codex_assessment(snap)
    assert result.status is Status.STALE
    assert d.OLD[:12] in result.reasons[0]


def test_clean_receipt_for_an_older_commit_with_state_for_head_is_incomplete():
    snap = d.snapshot(issue_comments=[d.codex_state(d.HEAD), d.codex_clean_receipt(d.OLD)])
    assert codex_assessment(snap).status is Status.INCOMPLETE


@pytest.mark.parametrize("status", ["in_progress", "queued", None, "COMPLETED", "done"])
def test_unfinished_or_unknown_status_is_pending(status):
    snap = d.snapshot(issue_comments=[d.codex_state(status=status), d.codex_clean_receipt()])
    assert codex_assessment(snap).status is Status.PENDING


def test_state_without_reviewed_commit_is_missing():
    snap = d.snapshot(issue_comments=[d.codex_state(None, status=None)])
    assert codex_assessment(snap).status is Status.MISSING


def test_receipt_without_state_is_pending_not_clean():
    """Codex posts the receipt and then edits its summary; until then nothing is settled."""
    snap = d.snapshot(issue_comments=[d.codex_clean_receipt()])
    assert codex_assessment(snap).status is Status.PENDING


def test_two_state_comments_are_incomplete():
    snap = d.snapshot(issue_comments=[d.codex_state(), d.codex_state(), d.codex_clean_receipt()])
    assert codex_assessment(snap).status is Status.INCOMPLETE


def test_short_receipt_prefix_does_not_match():
    comment = d.codex_clean_receipt()
    comment["body"] = comment["body"].replace(d.HEAD[:10], d.HEAD[:5])
    snap = d.snapshot(issue_comments=[d.codex_state(), comment])
    assert codex_assessment(snap).status is Status.INCOMPLETE


def test_unknown_finding_flags_are_incomplete():
    snap = d.snapshot(issue_comments=[d.codex_state(any_findings=None), d.codex_clean_receipt()])
    assert codex_assessment(snap).status is Status.INCOMPLETE


# ------------------------------------------------------------------ findings / missing findings


def test_findings_on_head_are_collected_from_inline_comments():
    snap, _rev, inl = d.findings_snapshot(3)
    result = codex_assessment(snap)
    assert result.status is Status.FINDINGS
    assert [f.comment_id for f in result.findings] == [c["id"] for c in inl]


def test_replies_are_not_findings():
    snap, rev, inl = d.findings_snapshot(1)
    snap.review_comments.append(d.inline(rev, reply_to=inl[0]["id"]))
    assert len(codex_assessment(snap).findings) == 1


def test_findings_review_without_inline_comments_is_incomplete():
    """Codex says it has suggestions but none can be retrieved: never act on the summary."""
    rev = d.review()
    snap = d.snapshot(
        reviews=[rev], review_comments=[], issue_comments=[d.codex_state(any_findings=True)]
    )
    result = codex_assessment(snap)
    assert result.status is Status.INCOMPLETE
    assert "no retrievable findings" in result.reasons[0]


def test_state_reports_findings_but_none_retrieved_is_incomplete():
    snap = d.snapshot(
        issue_comments=[
            d.codex_state(any_findings=True, unresolved=True),
            d.codex_clean_receipt(),
        ]
    )
    assert codex_assessment(snap).status is Status.INCOMPLETE


def test_inline_comment_without_a_thread_is_incomplete():
    snap, _rev, _inl = d.findings_snapshot(2)
    snap.threads = snap.threads[:1]
    assert codex_assessment(snap).status is Status.INCOMPLETE


def test_resolved_threads_are_not_findings():
    snap, _rev, inl = d.findings_snapshot(2)
    snap.threads = [Thread(inl[0]["id"], True), Thread(inl[1]["id"], False)]
    result = codex_assessment(snap)
    assert [f.comment_id for f in result.findings] == [inl[1]["id"]]


def test_all_threads_resolved_is_clean():
    snap, _rev, inl = d.findings_snapshot(2)
    snap.issue_comments = [d.codex_state(any_findings=True, unresolved=False)]
    snap.threads = [Thread(c["id"], True) for c in inl]
    assert codex_assessment(snap).status is Status.CLEAN


def test_unresolved_threads_from_older_commits_still_block():
    """A clean review of the head does not erase an open finding on an older commit."""
    old = d.review(d.OLD)
    old_inline = d.inline(old)
    snap = d.snapshot(
        reviews=[old],
        review_comments=[old_inline],
        issue_comments=[d.codex_state(), d.codex_clean_receipt()],
    )
    result = codex_assessment(snap)
    assert result.status is Status.FINDINGS
    assert result.findings[0].comment_id == old_inline["id"]


def test_state_says_unresolved_but_every_thread_resolved_is_incomplete():
    snap, _rev, inl = d.findings_snapshot(1)
    snap.threads = [Thread(inl[0]["id"], True)]
    assert codex_assessment(snap).status is Status.INCOMPLETE


def test_inconsistent_head_receipt_is_incomplete():
    rev = d.review(d.HEAD)
    rev["body"] = d.receipt_body(d.OTHER, findings=True)  # names another commit
    snap = d.snapshot(reviews=[rev], issue_comments=[d.codex_state()])
    assert codex_assessment(snap).status is Status.INCOMPLETE


def test_inconsistent_receipt_on_an_old_commit_does_not_block_forever():
    old = d.review(d.OLD)
    old["body"] = d.receipt_body(d.OTHER, findings=True)
    snap = d.clean_snapshot(reviews=[old])
    assert codex_assessment(snap).status is Status.CLEAN


def test_security_review_of_head_with_findings_is_flagged():
    sec = {
        "commit_sha": d.HEAD,
        "status": "completed",
        "has_any_findings": True,
        "has_unresolved_findings": True,
    }
    snap = d.snapshot(issue_comments=[d.codex_state(security=sec), d.codex_clean_receipt()])
    result = codex_assessment(snap)
    assert result.status is Status.CLEAN and result.security_ok is False


def test_non_sha_head_is_incomplete():
    snap = d.clean_snapshot(the_pr=d.pr(head="not-a-sha"))
    assert codex_assessment(snap).status is Status.INCOMPLETE
