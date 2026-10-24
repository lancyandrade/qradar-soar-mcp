"""Review loop: the policy every automated patch must pass before test and push."""

from __future__ import annotations

import pytest

from review_loop import policy
from review_loop.patch_policy import check_patch, check_verdicts, path_allowed


def diff(path: str, *, added: int = 1, mode: str | None = None, old: str | None = None) -> str:
    old = old or path
    head = f"diff --git a/{old} b/{path}\n"
    if mode:
        head += f"new file mode {mode}\n"
    body = "".join(f"+line {i}\n" for i in range(added))
    return f"{head}index 1..2 100644\n--- a/{old}\n+++ b/{path}\n@@ -1 +1,{added} @@\n{body}"


GOOD = diff("src/qradar_soar_mcp/tools/x.py") + diff("tests/test_x.py")


def test_good_patch_passes():
    report = check_patch(GOOD)
    assert report.ok, report.problems
    assert report.files == ["src/qradar_soar_mcp/tools/x.py", "tests/test_x.py"]


def test_empty_patch_is_ok_and_empty():
    report = check_patch("")
    assert report.ok and report.empty


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        "automation/review_loop/policy.py",
        "src/qradar_soar_mcp/security/policy.py",
        "docs/design/02-SECURITY-MODEL.md",
        "scripts/check_no_secrets.py",
        ".gitleaks.toml",
        ".pre-commit-config.yaml",
        "SECURITY.md",
        ".env",
        ".env.example",
        ".claude/settings.json",
        ".mcp.json",
        "CLAUDE.md",
        "pyproject.toml",
        "uv.lock",
        "tests/test_permission_matrix.py",
        "tests/fixtures/soar/x.json",
        ".review-loop/findings.json",
        "scripts/probe/probe.py",
        "Makefile",
        "src/../.github/x",
    ],
)
def test_protected_or_unlisted_paths_are_refused(path):
    assert path_allowed(path) is not None
    report = check_patch(diff(path) + diff("tests/test_x.py"))
    assert not report.ok


def test_rename_into_a_protected_path_is_refused():
    text = (
        "diff --git a/tests/test_x.py b/tests/test_y.py\n"
        "similarity index 100%\nrename from tests/test_x.py\nrename to .github/workflows/x.yml\n"
    )
    assert not check_patch(text).ok


@pytest.mark.parametrize("mode", ["100755", "120000", "160000"])
def test_executable_symlink_and_submodule_modes_are_refused(mode):
    text = diff("src/qradar_soar_mcp/tools/x.py", mode=mode) + diff("tests/test_x.py")
    report = check_patch(text)
    assert not report.ok and any(mode in p for p in report.problems)


def test_binary_changes_are_refused():
    text = (
        "diff --git a/docs/x.png b/docs/x.png\nnew file mode 100644\nGIT binary patch\nliteral 1\n"
        + diff("tests/test_x.py")
    )
    assert not check_patch(text).ok


def test_quoted_paths_are_refused():
    text = 'diff --git "a/src/x y.py" "b/src/x y.py"\n' + diff("tests/test_x.py")
    assert not check_patch(text).ok


def test_a_fix_without_a_regression_test_is_refused():
    report = check_patch(diff("src/qradar_soar_mcp/tools/x.py"))
    assert not report.ok and any("regression test" in p for p in report.problems)
    # A helper module under tests/ is not a test file.
    report = check_patch(diff("src/qradar_soar_mcp/tools/x.py") + diff("tests/helpers.py"))
    assert not report.ok


def test_size_limits():
    big = diff("src/qradar_soar_mcp/tools/x.py", added=policy.MAX_PATCH_CHANGED_LINES + 1)
    assert not check_patch(big + diff("tests/test_x.py")).ok
    many = "".join(diff(f"tests/test_{i}.py") for i in range(policy.MAX_PATCH_FILES + 1))
    assert not check_patch(many).ok


# ------------------------------------------------------------------ verdicts


def test_verdicts_must_cover_every_finding_exactly_once():
    patch = check_patch(GOOD)
    ok = check_verdicts(
        {"summary": "s", "findings": [{"comment_id": 1, "verdict": "fixed", "reason": "r"}]},
        [1],
        patch,
    )
    assert ok.ok and ok.fixed == [1]

    missing = check_verdicts({"summary": "", "findings": []}, [1], patch)
    assert not missing.ok

    dup = check_verdicts(
        {
            "findings": [
                {"comment_id": 1, "verdict": "fixed", "reason": ""},
                {"comment_id": 1, "verdict": "not_a_bug", "reason": ""},
            ]
        },
        [1],
        patch,
    )
    assert not dup.ok

    unknown = check_verdicts(
        {"findings": [{"comment_id": 99, "verdict": "fixed", "reason": ""}]}, [1], patch
    )
    assert not unknown.ok

    bad_verdict = check_verdicts(
        {"findings": [{"comment_id": 1, "verdict": "merged", "reason": ""}]}, [1], patch
    )
    assert not bad_verdict.ok


@pytest.mark.parametrize("raw", [None, "", [], {"findings": "x"}])
def test_malformed_verdicts_fail(raw):
    assert not check_verdicts(raw, [1], check_patch(GOOD)).ok


def test_fixed_needs_a_patch_and_a_patch_needs_a_fix():
    empty = check_patch("")
    fixed_no_patch = check_verdicts(
        {"findings": [{"comment_id": 1, "verdict": "fixed", "reason": ""}]}, [1], empty
    )
    assert not fixed_no_patch.ok
    patch_no_fix = check_verdicts(
        {"findings": [{"comment_id": 1, "verdict": "not_a_bug", "reason": ""}]},
        [1],
        check_patch(GOOD),
    )
    assert not patch_no_fix.ok


def test_needs_human_is_reported():
    report = check_verdicts(
        {"findings": [{"comment_id": 1, "verdict": "needs_human", "reason": "design"}]},
        [1],
        check_patch(""),
    )
    assert report.ok and report.needs_human == [1]


@pytest.mark.parametrize(
    "path",
    [
        ".GITHUB/workflows/x.yml",
        "src/qradar_soar_mcp/Security/x.py",
        "Tests/Fixtures/x.json",
        "docs/Design/02-x.md",
        "src/qradar_soar_mcp/security./x.py",
        "docs/x /y.md",
        "src/qradar_soar_mcp/config.py",
        "src/qradar_soar_mcp/tls.py",
        "src/qradar_soar_mcp/redaction.py",
        "src/qradar_soar_mcp/tools/registry.py",
        "tests/conftest.py",
        "tests/test_ci_hygiene.py",
        "tests/test_review_loop_patch.py",
        ".gitattributes",
    ],
)
def test_case_and_alias_tricks_do_not_reach_protected_paths(path):
    assert path_allowed(path) is not None


def test_deleting_files_is_refused():
    text = (
        "diff --git a/tests/test_old.py b/tests/test_old.py\ndeleted file mode 100644\n"
        "--- a/tests/test_old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    ) + GOOD
    report = check_patch(text)
    assert not report.ok and any("delete" in p for p in report.problems)


def test_gutting_a_test_does_not_count_as_a_regression_test():
    text = diff("src/qradar_soar_mcp/tools/x.py") + (
        "diff --git a/tests/test_x.py b/tests/test_x.py\n--- a/tests/test_x.py\n"
        "+++ b/tests/test_x.py\n@@ -1,2 +1 @@\n-def test_a():\n-    assert x\n"
    )
    report = check_patch(text)
    assert not report.ok and not report.touches_tests


@pytest.mark.parametrize(
    "value",
    [
        "sk-ant-api03-" + "A" * 30,
        "ghs_" + "a" * 36,
        "github_pat_" + "a" * 30,
        "-----BEGIN RSA " + "PRIVATE KEY-----",  # assembled so scanners stay quiet
        "x-access-token:abc",
    ],
)
def test_credential_shaped_output_is_refused(value):
    text = (
        GOOD + f"diff --git a/docs/x.md b/docs/x.md\n--- a/docs/x.md\n+++ b/docs/x.md\n+{value}\n"
    )
    assert not check_patch(text).ok
    verdicts = {"findings": [{"comment_id": 1, "verdict": "fixed", "reason": value}]}
    assert not check_verdicts(verdicts, [1], check_patch(GOOD)).ok


def test_existing_symlinks_and_executables_are_refused():
    from review_loop.patch_policy import check_existing_modes

    listed = (
        "100644 1111 0\ttests/test_x.py\n"
        "120000 2222 0\tdocs/link.md\n"
        "100755 3333 0\tsrc/qradar_soar_mcp/tools/x.py\n"
    )
    problems = check_existing_modes(listed)
    assert len(problems) == 2
    assert check_existing_modes("100644 1 0\ttests/test_x.py\n") == []
