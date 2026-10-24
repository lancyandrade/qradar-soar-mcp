"""Review loop: when to fix, duplicates, races, retry exhaustion, CI failure."""

from __future__ import annotations

from review_loop import ledger, policy
from review_loop.evaluate import Action, plan_loop
from tests import review_loop_data as d


def claim_comment(head: str, attempt: int, *, user=None, cid=None) -> dict:
    return d.issue_comment(
        ledger.claim_body(head, attempt, "1"), user=user or d.ACTIONS_USER, cid=cid
    )


def test_findings_on_head_start_attempt_one():
    snap, _, inl = d.findings_snapshot(2)
    decision = plan_loop(snap)
    assert decision.action is Action.FIX
    assert decision.attempt == 1
    assert [f["comment_id"] for f in decision.findings] == [c["id"] for c in inl]


def test_clean_review_does_nothing():
    assert plan_loop(d.clean_snapshot()).action is Action.NONE


def test_stale_review_does_nothing():
    """A Codex event about an older head (e.g. replayed after our push) is not acted on."""
    rev = d.review(d.OLD)
    snap = d.snapshot(
        reviews=[rev],
        review_comments=[d.inline(rev)],
        issue_comments=[d.codex_state(d.OLD, any_findings=True, unresolved=True)],
    )
    decision = plan_loop(snap)
    assert decision.action is Action.NONE and "stale" in decision.reason


def test_pending_review_does_nothing():
    snap, _, _ = d.findings_snapshot(1)
    snap.issue_comments = [d.codex_state(status="in_progress")]
    assert plan_loop(snap).action is Action.NONE


def test_missing_findings_are_reported_once_never_fixed():
    rev = d.review()
    snap = d.snapshot(reviews=[rev], issue_comments=[d.codex_state(any_findings=True)])
    first = plan_loop(snap)
    assert first.action is Action.REPORT and first.report_key == f"incomplete:{d.HEAD}"
    snap.issue_comments.append(
        d.issue_comment(ledger.report_body(first.report_key, "status", "x"), user=d.ACTIONS_USER)
    )
    assert plan_loop(snap).action is Action.NONE


# ------------------------------------------------------------------ duplicates


def test_duplicate_event_for_a_claimed_head_does_nothing():
    snap, _, _ = d.findings_snapshot(1, extra_comments=[claim_comment(d.HEAD, 1)])
    decision = plan_loop(snap)
    assert decision.action is Action.NONE and "duplicate" in decision.reason


def test_claims_written_by_a_person_do_not_count():
    """A human copying the claim marker neither blocks nor consumes attempts."""
    spoofed = [claim_comment(d.HEAD, 1, user=d.OWNER_USER)]
    snap, _, _ = d.findings_snapshot(1, extra_comments=spoofed)
    assert plan_loop(snap).action is Action.FIX


def test_claims_with_the_wrong_app_do_not_count():
    forged = claim_comment(d.HEAD, 1)
    forged["performed_via_github_app"] = {"id": 1, "slug": "x", "owner": {"login": "y"}}
    snap, _, _ = d.findings_snapshot(1, extra_comments=[forged])
    assert plan_loop(snap).action is Action.FIX


def test_marker_inside_codex_text_does_not_count():
    rev = d.review()
    inl = d.inline(rev)
    inl["body"] += "\n" + ledger.claim_body(d.HEAD, 1, "1")
    snap = d.snapshot(
        reviews=[rev],
        review_comments=[inl],
        issue_comments=[d.codex_state(any_findings=True, unresolved=True)],
    )
    assert plan_loop(snap).action is Action.FIX


# ------------------------------------------------------------------ races


def test_earliest_claim_wins_a_race():
    cl = [
        ledger.Claim(10, d.HEAD, 1),
        ledger.Claim(11, d.HEAD, 1),
    ]
    assert ledger.verify_claim(cl, d.HEAD, 10).won
    loser = ledger.verify_claim(cl, d.HEAD, 11)
    assert not loser.won and "first" in loser.reason


def test_claim_not_visible_loses():
    assert not ledger.verify_claim([], d.HEAD, 10).won


def test_racing_claims_on_different_heads_cannot_exceed_the_cap():
    heads = ["1" * 40, "2" * 40, "3" * 40, "4" * 40]
    cl = [ledger.Claim(i, h, i) for i, h in enumerate(heads, start=1)]
    assert [ledger.verify_claim(cl, h, i).won for i, h in enumerate(heads, start=1)] == [
        True,
        True,
        True,
        False,
    ]


# ------------------------------------------------------------------ retry exhaustion


def test_attempts_are_counted_per_distinct_head():
    claims = [claim_comment("1" * 40, 1), claim_comment("1" * 40, 1), claim_comment("2" * 40, 2)]
    snap, _, _ = d.findings_snapshot(1, extra_comments=claims)
    decision = plan_loop(snap)
    assert decision.action is Action.FIX and decision.attempt == 3


def test_retry_exhaustion_halts_and_reports_once():
    claims = [claim_comment(h * 40, i) for i, h in enumerate("123", start=1)]
    snap, _, _ = d.findings_snapshot(1, extra_comments=claims)
    decision = plan_loop(snap)
    assert decision.action is Action.HALT and decision.report_key == "exhausted"
    assert str(policy.MAX_FIX_ATTEMPTS) in decision.reason
    snap.issue_comments.append(
        d.issue_comment(ledger.report_body("exhausted", "halted", "x"), user=d.ACTIONS_USER)
    )
    assert plan_loop(snap).action is Action.NONE


def test_halted_label_stops_the_loop():
    snap, _, _ = d.findings_snapshot(1, the_pr=d.pr(labels=(policy.LABEL_HALTED,)))
    assert plan_loop(snap).action is Action.NONE


def test_opt_out_label_stops_the_loop():
    snap, _, _ = d.findings_snapshot(1, the_pr=d.pr(labels=(policy.LABEL_OPT_OUT,)))
    assert plan_loop(snap).action is Action.NONE


def test_too_many_findings_halt():
    snap, _, _ = d.findings_snapshot(policy.MAX_FINDINGS + 1)
    decision = plan_loop(snap)
    assert decision.action is Action.HALT and decision.report_key.startswith("too-many:")


# ------------------------------------------------------------------ eligibility


def test_fork_is_never_processed():
    snap, _, _ = d.findings_snapshot(1, the_pr=d.pr(fork=True))
    decision = plan_loop(snap)
    assert decision.action is Action.NONE and "fork" in decision.reason


def test_unapproved_branch_is_never_processed():
    snap, _, _ = d.findings_snapshot(1, the_pr=d.pr(ref="main"))
    assert plan_loop(snap).action is Action.NONE


def test_untrusted_author_is_never_processed():
    snap, _, _ = d.findings_snapshot(1, the_pr=d.pr(author_association="CONTRIBUTOR"))
    assert plan_loop(snap).action is Action.NONE


# ------------------------------------------------------------------ CI failure


def automation_commit() -> dict:
    return {
        "commit": {
            "message": f"fix: x\n\n{policy.TRAILER_ATTEMPT}: 1/3\n",
            "author": {"name": policy.COMMIT_AUTHOR_NAME, "email": policy.COMMIT_AUTHOR_EMAIL},
        }
    }


def test_ci_failure_on_an_automated_commit_halts_once():
    snap = d.clean_snapshot(head_commit=automation_commit())
    decision = plan_loop(snap, ci_failed_run_sha=d.HEAD)
    assert decision.action is Action.HALT and decision.report_key == f"ci-failed:{d.HEAD}"
    snap.issue_comments.append(
        d.issue_comment(ledger.report_body(decision.report_key, "halted", "x"), user=d.ACTIONS_USER)
    )
    assert plan_loop(snap, ci_failed_run_sha=d.HEAD).action is Action.NONE


def test_ci_failure_on_a_human_commit_is_left_to_the_author():
    human = {"commit": {"message": "feat: x", "author": {"name": "a", "email": "a@b"}}}
    snap = d.clean_snapshot(head_commit=human)
    assert plan_loop(snap, ci_failed_run_sha=d.HEAD).action is Action.NONE


def test_ci_failure_on_an_old_commit_is_ignored():
    snap = d.clean_snapshot(head_commit=automation_commit())
    assert plan_loop(snap, ci_failed_run_sha=d.OLD).action is Action.NONE


def test_report_body_rejects_bad_keys():
    import pytest

    with pytest.raises(ValueError):
        ledger.report_body("bad key!", "halted", "x")
    with pytest.raises(ValueError):
        ledger.claim_body("short", 1, "1")


def test_only_old_unresolved_threads_ask_a_person_instead_of_spending_an_attempt():
    old = d.review(d.OLD)
    snap = d.snapshot(
        reviews=[old],
        review_comments=[d.inline(old)],
        issue_comments=[d.codex_state(), d.codex_clean_receipt()],
    )
    decision = plan_loop(snap)
    assert decision.action is Action.REPORT and decision.report_key == f"old-threads:{d.HEAD}"


# ------------------------------------------------------------------ finding age (Codex on 901fb39)


def carried_forward_snapshot():
    """An open Codex thread from an older commit that GitHub now shows on the head."""
    old = d.review(d.OLD)
    comment = d.inline(old)
    comment["commit_id"] = d.HEAD  # GitHub moved the comment forward
    comment["original_commit_id"] = d.OLD
    return d.snapshot(
        reviews=[old],
        review_comments=[comment],
        issue_comments=[d.codex_state(), d.codex_clean_receipt()],
    )


def test_carried_forward_old_thread_is_not_a_new_finding():
    decision = plan_loop(carried_forward_snapshot())
    assert decision.action is Action.REPORT
    assert decision.report_key == f"old-threads:{d.HEAD}"


def test_carried_forward_old_thread_spends_no_attempt():
    snap = carried_forward_snapshot()
    assert plan_loop(snap).attempt == 0
    assert ledger.attempts_used(ledger.claims(snap.issue_comments, d.REPO, d.NUMBER)) == 0


def test_a_finding_written_by_the_head_review_is_new():
    snap, _rev, _inl = d.findings_snapshot(1)
    decision = plan_loop(snap)
    assert decision.action is Action.FIX
    assert decision.findings[0]["on_head"] is True


def test_owning_review_decides_over_the_comment_commit_fields():
    """Even if both commit fields named the head, the owning review's commit wins."""
    old = d.review(d.OLD)
    comment = d.inline(old)
    comment["commit_id"] = comment["original_commit_id"] = d.HEAD
    snap = d.snapshot(
        reviews=[old],
        review_comments=[comment],
        issue_comments=[d.codex_state(), d.codex_clean_receipt()],
    )
    assert plan_loop(snap).action is Action.REPORT


def test_original_commit_is_used_when_the_owning_review_is_unknown():
    from review_loop.codex import _written_on

    comment = {"pull_request_review_id": 999, "commit_id": d.HEAD, "original_commit_id": d.OLD}
    assert _written_on(comment, {}) == d.OLD
    assert _written_on(comment, {999: d.HEAD}) == d.HEAD
