"""Review loop: the merge gate fails closed unless everything is proven good."""

from __future__ import annotations

import pytest

from review_loop import policy
from review_loop.evaluate import CIStatus, assess_ci, gate
from tests import review_loop_data as d


def test_gate_passes_only_when_everything_holds():
    result = gate(d.clean_snapshot())
    assert result.passed, result.lines
    assert result.head_sha == d.HEAD


# ------------------------------------------------------------------ CI


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "skipped", None])
def test_failed_ci_blocks(conclusion):
    snap = d.clean_snapshot(runs=[d.ci_run(conclusion=conclusion)])
    assert assess_ci(snap).status is CIStatus.FAILED
    assert not gate(snap).passed


def test_failing_required_job_blocks_even_if_run_says_success():
    failing = sorted(policy.REQUIRED_CI_JOBS)[0]
    snap = d.clean_snapshot(jobs={900: d.ci_jobs(failing=failing)})
    assert assess_ci(snap).status is CIStatus.FAILED
    assert not gate(snap).passed


def test_missing_required_job_blocks():
    snap = d.clean_snapshot(jobs={900: d.ci_jobs(drop="dependency audit (pip-audit)")})
    result = assess_ci(snap)
    assert result.status is CIStatus.FAILED and "pip-audit" in result.reason


def test_running_ci_blocks():
    snap = d.clean_snapshot(runs=[d.ci_run(status="in_progress", conclusion=None)])
    assert assess_ci(snap).status is CIStatus.PENDING
    assert not gate(snap).passed


def test_no_ci_run_blocks():
    snap = d.clean_snapshot(runs=[])
    assert assess_ci(snap).status is CIStatus.MISSING
    assert not gate(snap).passed


@pytest.mark.parametrize(
    "run",
    [
        d.ci_run(d.OLD),  # green CI on the previous head
        d.ci_run(path=".github/workflows/other.yml"),  # another workflow pretending
        d.ci_run(event="workflow_dispatch"),
    ],
)
def test_ci_from_the_wrong_commit_or_workflow_does_not_count(run):
    snap = d.clean_snapshot(runs=[run])
    assert assess_ci(snap).status is CIStatus.MISSING


def test_ci_from_a_fork_head_repository_does_not_count():
    run = d.ci_run()
    run["head_repository"] = {"full_name": "someone/qradar-soar-mcp"}
    assert assess_ci(d.clean_snapshot(runs=[run])).status is CIStatus.MISSING


def test_latest_ci_run_wins():
    """A failed re-run after a green one blocks; a green re-run after a failure passes."""
    green, red = (
        d.ci_run(rid=900, run_number=1),
        d.ci_run(rid=901, run_number=2, conclusion="failure"),
    )
    snap = d.clean_snapshot(runs=[green, red], jobs={900: d.ci_jobs(), 901: d.ci_jobs()})
    assert assess_ci(snap).status is CIStatus.FAILED
    red2 = d.ci_run(rid=901, run_number=1, conclusion="failure")
    green2 = d.ci_run(rid=902, run_number=2)
    snap = d.clean_snapshot(runs=[red2, green2], jobs={902: d.ci_jobs()})
    assert assess_ci(snap).status is CIStatus.SUCCESS


def test_job_from_another_commit_blocks():
    jobs = d.ci_jobs()
    jobs[0]["head_sha"] = d.OLD
    assert assess_ci(d.clean_snapshot(jobs={900: jobs})).status is CIStatus.FAILED


# ------------------------------------------------------------------ Codex


def test_codex_findings_block():
    snap, _, _ = d.findings_snapshot(1)
    assert not gate(snap).passed


def test_stale_codex_review_blocks():
    snap = d.clean_snapshot(issue_comments=[d.codex_state(d.OLD), d.codex_clean_receipt(d.OLD)])
    result = gate(snap)
    assert not result.passed
    assert any("stale" in line for line in result.lines)


def test_missing_codex_review_blocks():
    assert not gate(d.snapshot(issue_comments=[])).passed


# ------------------------------------------------------------------ security / eligibility


def test_halted_label_blocks():
    assert not gate(d.clean_snapshot(the_pr=d.pr(labels=(policy.LABEL_HALTED,)))).passed


@pytest.mark.parametrize(
    "kw",
    [
        {"fork": True},
        {"draft": True},
        {"state": "closed"},
        {"ref": "main"},
        {"ref": "claude/issue-1"},
        {"ref": "Fix/Upper"},
        {"base_ref": "release"},
        {"author_association": "CONTRIBUTOR"},
        {"author_association": "NONE"},
    ],
)
def test_ineligible_pull_requests_are_blocked(kw):
    assert not gate(d.clean_snapshot(the_pr=d.pr(**kw))).passed


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        "automation/review_loop/policy.py",
        "src/qradar_soar_mcp/security/policy.py",
        "docs/design/02-SECURITY-MODEL.md",
        "scripts/check_no_secrets.py",
        ".gitleaks.toml",
        "SECURITY.md",
    ],
)
def test_sensitive_paths_need_an_owner_approval_for_the_exact_head(path):
    files = [{"filename": path}]
    assert not gate(d.clean_snapshot(files=files)).passed

    approve = d.issue_comment(f"review-loop: approve-sensitive {d.HEAD}", association="OWNER")
    comments = [d.codex_state(), d.codex_clean_receipt(), approve]
    assert gate(d.clean_snapshot(files=files, issue_comments=comments)).passed


def test_renamed_away_from_a_sensitive_path_still_counts():
    files = [{"filename": "docs/moved.md", "previous_filename": "SECURITY.md"}]
    assert not gate(d.clean_snapshot(files=files)).passed


@pytest.mark.parametrize(
    "comment",
    [
        # approval for another commit
        d.issue_comment(f"review-loop: approve-sensitive {d.OLD}", association="OWNER"),
        # not the owner
        d.issue_comment(f"review-loop: approve-sensitive {d.HEAD}", association="COLLABORATOR"),
        # a bot (e.g. the automation itself or Codex) cannot approve
        d.issue_comment(
            f"review-loop: approve-sensitive {d.HEAD}",
            user=d.ACTIONS_USER,
            association="OWNER",
        ),
        d.issue_comment(
            f"review-loop: approve-sensitive {d.HEAD}",
            app={"id": 1, "slug": "x", "owner": {"login": "y"}},
            association="OWNER",
        ),
        # not on its own line
        d.issue_comment(f"please review-loop: approve-sensitive {d.HEAD}", association="OWNER"),
    ],
)
def test_invalid_sensitive_approvals_are_ignored(comment):
    files = [{"filename": ".github/workflows/ci.yml"}]
    comments = [d.codex_state(), d.codex_clean_receipt(), comment]
    assert not gate(d.clean_snapshot(files=files, issue_comments=comments)).passed


def test_incomplete_file_list_fails_closed():
    snap = d.clean_snapshot(the_pr=d.pr(changed_files=3000))
    result = gate(snap)
    assert not result.passed
    assert any("every changed file" in line for line in result.lines)


def test_codex_security_review_findings_block():
    sec = {
        "commit_sha": d.HEAD,
        "status": "completed",
        "has_any_findings": True,
        "has_unresolved_findings": True,
    }
    snap = d.clean_snapshot(issue_comments=[d.codex_state(security=sec), d.codex_clean_receipt()])
    assert not gate(snap).passed


def test_gate_text_cannot_carry_markers_or_mentions():
    """Check summaries are built from fixed text plus neutralised values."""
    from review_loop.ledger import neutralise

    assert neutralise("<!-- review-loop:claim:v1 {} --> @codex review") == (
        "&lt;!-- review-loop:claim:v1 {} --&gt; @" + chr(0x200B) + "codex review"
    )


@pytest.mark.parametrize(
    "path",
    [
        "pyproject.toml",
        "uv.lock",
        "tests/conftest.py",
        "tests/test_permission_matrix.py",
        "tests/fixtures/soar/x.json",
        "CLAUDE.md",
        ".claude/settings.json",
        "scripts/probe/probe.py",
        ".GITHUB/workflows/x.yml",
    ],
)
def test_more_sensitive_paths_need_approval(path):
    assert not gate(d.clean_snapshot(files=[{"filename": path}])).passed


@pytest.mark.parametrize(
    "path", ["docs/AGENTS.md", "tests/x/conftest.py", "tests/.gitattributes", "docs/Claude.md"]
)
def test_nested_tool_steering_files_need_approval(path):
    assert not gate(d.clean_snapshot(files=[{"filename": path}])).passed
