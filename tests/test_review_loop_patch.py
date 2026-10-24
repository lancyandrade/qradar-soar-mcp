"""Review loop: the patch boundary between the model and the push.

Adversarial cases for the strict patch parser, the path and content rules,
git's own view of the patch, the existing tree (modes, case collisions,
attributes) and the staged result. Real ``git`` runs against throwaway
repositories; nothing touches this checkout.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from review_loop import cli, gitcheck, policy
from review_loop.patch_policy import (
    PatchFormatError,
    check_patch,
    check_verdicts,
    parse_patch,
    path_allowed,
)

SRC = "src/qradar_soar_mcp/tools/x.py"
TEST = "tests/test_x.py"
GIT_ID = ("-c", "user.name=t", "-c", "user.email=t@example.invalid")


# ------------------------------------------------------------------ helpers


def new_file(path: str, lines: list[str], mode: str = "100644") -> str:
    """A well-formed git diff that adds ``path``."""
    body = "".join(f"+{line}\n" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\nnew file mode {mode}\nindex 0000000..1111111\n"
        f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n{body}"
    )


def edit_file(path: str, old: list[str], new: list[str]) -> str:
    body = "".join(f"-{line}\n" for line in old) + "".join(f"+{line}\n" for line in new)
    return (
        f"diff --git a/{path} b/{path}\nindex 1111111..2222222 100644\n"
        f"--- a/{path}\n+++ b/{path}\n@@ -1,{len(old)} +1,{len(new)} @@\n{body}"
    )


GOOD = edit_file(SRC, ["x = 1"], ["x = 2"]) + edit_file(
    TEST, ["def test_x():"], ["def test_x():", "    assert True"]
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src/qradar_soar_mcp/tools").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "docs").mkdir()
    (root / SRC).write_text("x = 1\n", encoding="utf-8")
    (root / TEST).write_text("def test_x():\n    pass\n", encoding="utf-8")
    (root / "docs/Guide.md").write_text("guide\n", encoding="utf-8")
    (root / ".gitattributes").write_text("*.py text eol=lf\n", encoding="utf-8")
    gitcheck.git(tmp_path, "init", "-q", str(root))
    gitcheck.git(root, "add", "-A")
    gitcheck.git(root, *GIT_ID, "commit", "-q", "-m", "init")
    return root


def real_patch(repo: Path, edits: dict[str, str]) -> bytes:
    """``git diff`` for ``edits``, then the work tree is put back."""
    for path, content in edits.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    gitcheck.git(repo, "add", "-A")
    out = gitcheck.git(repo, "diff", "--cached", "--binary", "--no-ext-diff").stdout
    gitcheck.git(repo, "reset", "-q", "--hard")
    gitcheck.git(repo, "clean", "-qfd")
    return out.encode("utf-8")


def good_real_patch(repo: Path) -> bytes:
    return real_patch(
        repo,
        {SRC: "x = 2\n", TEST: "def test_x():\n    pass\n\n\ndef test_y():\n    assert True\n"},
    )


def short_id(value: object) -> str:
    """Readable, short test ids (pytest puts the id in an environment variable)."""
    if isinstance(value, str) and len(value) <= 60 and chr(10) not in value:
        return value
    return "case"


def write(tmp_path: Path, name: str, data: bytes | str) -> Path:
    path = tmp_path / name
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return path


# ------------------------------------------------------------------ parser: accepted input


def test_good_patch_passes():
    report = check_patch(GOOD)
    assert report.ok, report.problems
    assert report.files == [SRC, TEST]
    assert report.changed_lines == 5


def test_real_git_output_passes(repo: Path):
    report = check_patch(good_real_patch(repo))
    assert report.ok, report.problems


def test_empty_patch_is_ok_and_empty():
    report = check_patch(b"")
    assert report.ok and report.empty


def test_header_lookalikes_inside_a_hunk_are_content():
    """Hunks are consumed by their counts: a content line reading like a header
    for a protected file is just content of the test file."""
    smuggled = ["diff --git a/.github/x.yml b/.github/x.yml", "--- a/.github/x.yml", "+++ b/x"]
    text = edit_file(SRC, ["x = 1"], ["x = 2"]) + new_file("tests/test_new.py", smuggled)
    report = check_patch(text)
    assert report.ok, report.problems
    assert report.files == [SRC, "tests/test_new.py"]


def test_no_newline_marker_is_accepted():
    text = (
        f"diff --git a/{TEST} b/{TEST}\nindex 1111111..2222222 100644\n--- a/{TEST}\n"
        f"+++ b/{TEST}\n@@ -1 +1,2 @@\n-a\n\\ No newline at end of file\n+a\n+b\n"
    )
    assert parse_patch(text)[0].added == 2


# ------------------------------------------------------------------ parser: malformed input


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("traditional diff, no git header", f"--- a/{SRC}\n+++ b/{SRC}\n@@ -1 +1 @@\n-x\n+y\n"),
        (
            "traditional diff appended after a valid one",
            GOOD
            + "--- a/.github/workflows/x.yml\n+++ b/.github/workflows/x.yml\n@@ -1 +1 @@\n-a\n+b\n",
        ),
        ("leading junk", "hello\n" + GOOD),
        ("hunk shorter than its count", GOOD.replace("@@ -1,1 +1,1 @@", "@@ -1,1 +1,3 @@", 1)),
        ("hunk longer than its count", GOOD.replace("+x = 2\n", "+x = 2\n+x = 3\n", 1)),
        ("empty line inside a hunk", GOOD.replace("-x = 1\n", "\n", 1)),
        ("no trailing newline", GOOD[:-1]),
        ("--- path differs from header", GOOD.replace(f"--- a/{SRC}", "--- a/README.md", 1)),
        ("+++ path differs from header", GOOD.replace(f"+++ b/{SRC}", "+++ b/README.md", 1)),
        ("header names differ without rename", GOOD.replace(f"b/{SRC}\n", "b/docs/x.md\n", 1)),
        ("/dev/null source on a modify", GOOD.replace(f"--- a/{SRC}", "--- /dev/null", 1)),
        ("/dev/null target on a modify", GOOD.replace(f"+++ b/{SRC}", "+++ /dev/null", 1)),
        ("hunk without file lines", f"diff --git a/{SRC} b/{SRC}\n@@ -1 +1 @@\n-a\n+b\n"),
        ("file lines without a hunk", f"diff --git a/{SRC} b/{SRC}\n--- a/{SRC}\n+++ b/{SRC}\n"),
        ("unknown header line", GOOD.replace("index 1111111..2222222 100644", "x-evil yes", 1)),
        ("malformed hunk header", GOOD.replace("@@ -1,1 +1,1 @@", "@@ -1,1 @@", 1)),
        ("quoted path with spaces", 'diff --git "a/src/a b.py" "b/src/a b.py"\n'),
        (
            "git-quoted unicode path",
            'diff --git "a/docs/caf\\303\\251.md" "b/docs/caf\\303\\251.md"\n',
        ),
        ("raw unicode path", f"diff --git a/docs/caf{chr(0xE9)}.md b/docs/caf{chr(0xE9)}.md\n"),
        (
            "rename target differs from header",
            f"diff --git a/{TEST} b/tests/test_y.py\nsimilarity index 100%\n"
            f"rename from {TEST}\nrename to .github/x.yml\n",
        ),
    ],
    ids=short_id,
)
def test_malformed_patches_are_refused(label: str, text: str):
    report = check_patch(text)
    assert not report.ok, label
    assert any("malformed" in p for p in report.problems), (label, report.problems)


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("carriage return", GOOD.replace("+x = 2\n", "+x = 2\r\n").encode()),
        ("invalid utf-8", GOOD.encode() + b"\xff\xfe"),
        ("NUL byte", GOOD.replace("+x = 2", "+x" + chr(0) + "= 2").encode()),
        ("escape character", GOOD.replace("+x = 2", "+x = 2" + chr(0x1B) + "[2K").encode()),
        (
            "bidi override (Trojan Source)",
            GOOD.replace("+x = 2", "+x = 2 #" + chr(0x202E)).encode(),
        ),
        ("zero-width space", GOOD.replace("+x = 2", "+x" + chr(0x200B) + "= 2").encode()),
        ("line separator", GOOD.replace("+x = 2", "+x" + chr(0x2028) + "= 2").encode()),
        ("BOM", GOOD.replace("+x = 2", "+" + chr(0xFEFF) + "x = 2").encode()),
        ("oversized", GOOD.encode() + b"x" * (policy.MAX_PATCH_BYTES + 1)),
    ],
    ids=short_id,
)
def test_unsafe_bytes_are_refused(label: str, data: bytes):
    assert not check_patch(data).ok, label


def test_parse_patch_raises_for_bad_format():
    with pytest.raises(PatchFormatError):
        parse_patch("diff --git a/x b/x\n@@ -1 +1 @@\n")


# ------------------------------------------------------------------ path rules


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        "automation/review_loop/policy.py",
        "src/qradar_soar_mcp/security/policy.py",
        "docs/design/02-SECURITY-MODEL.md",
        "scripts/check_no_secrets.py",
        "scripts/probe/probe.py",
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
        ".gitattributes",
        ".gitmodules",
        "tests/test_permission_matrix.py",
        "tests/fixtures/soar/x.json",
        "tests/conftest.py",
        "tests/test_ci_hygiene.py",
        "tests/test_review_loop_patch.py",
        ".review-loop/findings.json",
        "src/qradar_soar_mcp/config.py",
        "src/qradar_soar_mcp/tls.py",
        "src/qradar_soar_mcp/redaction.py",
        "src/qradar_soar_mcp/tools/registry.py",
        "Makefile",
        # case and alias tricks
        ".GITHUB/workflows/x.yml",
        "src/qradar_soar_mcp/Security/x.py",
        "Tests/Fixtures/x.json",
        "docs/Design/02-x.md",
        "src/qradar_soar_mcp/security./x.py",
        "src/qradar_soar_mcp/Config.PY",
        "docs/x./y.md",
        "src/../.github/x",
        "tests/./test_x.py",
        "tests//test_x.py",
        "docs/.git/config",
        "docs/.GIT/hooks/x",
        "docs/GITHUB~1/x.md",  # 8.3 short name
        "docs/x.md:stream",  # NTFS alternate data stream
        f"docs/caf{chr(0xE9)}.md",
        "/etc/passwd",
    ],
)
def test_protected_unlisted_and_aliased_paths_are_refused(path: str):
    assert path_allowed(path) is not None


def test_protected_path_in_a_patch_is_refused():
    report = check_patch(new_file(".github/workflows/x.yml", ["on: push"]) + GOOD)
    assert not report.ok and any("protected" in p for p in report.problems)


@pytest.mark.parametrize(
    ("label", "text"),
    [
        (
            "delete",
            f"diff --git a/{TEST} b/{TEST}\ndeleted file mode 100644\nindex 1111111..0000000\n"
            f"--- a/{TEST}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n" + GOOD,
        ),
        (
            "rename",
            f"diff --git a/{TEST} b/tests/test_y.py\nsimilarity index 100%\n"
            f"rename from {TEST}\nrename to tests/test_y.py\n" + GOOD,
        ),
        (
            "copy",
            f"diff --git a/{TEST} b/tests/test_y.py\nsimilarity index 100%\n"
            f"copy from {TEST}\ncopy to tests/test_y.py\n" + GOOD,
        ),
        ("mode change", f"diff --git a/{SRC} b/{SRC}\nold mode 100644\nnew mode 100755\n" + GOOD),
        ("new executable", new_file("tests/test_y.py", ["x"], mode="100755") + GOOD),
        ("new symlink", new_file("tests/test_y.py", ["target"], mode="120000") + GOOD),
        (
            "submodule index",
            GOOD.replace("index 1111111..2222222 100644", "index 1111111..2222222 160000", 1),
        ),
        (
            "binary",
            "diff --git a/docs/x.png b/docs/x.png\nnew file mode 100644\n"
            "index 0000000..1111111\nGIT binary patch\nliteral 1\nIcmZpY&;S4c\n\n" + GOOD,
        ),
        ("same file twice", GOOD + edit_file(SRC, ["x = 2"], ["x = 3"])),
    ],
    ids=short_id,
)
def test_structural_changes_are_refused(label: str, text: str):
    assert not check_patch(text).ok, label


def test_a_fix_must_add_to_a_test_file():
    assert not check_patch(edit_file(SRC, ["x = 1"], ["x = 2"])).ok
    helper = edit_file(SRC, ["x = 1"], ["x = 2"]) + new_file("tests/helpers.py", ["y = 1"])
    assert not check_patch(helper).ok
    gutted = edit_file(SRC, ["x = 1"], ["x = 2"]) + edit_file(TEST, ["def test_a():", "    x"], [])
    report = check_patch(gutted)
    assert not report.ok and not report.touches_tests


def test_size_limits():
    big = edit_file(SRC, ["x"], ["y"] * (policy.MAX_PATCH_CHANGED_LINES + 1))
    assert not check_patch(big + GOOD).ok
    many = "".join(new_file(f"tests/test_{i}.py", ["x"]) for i in range(policy.MAX_PATCH_FILES + 1))
    assert not check_patch(many).ok


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
def test_credential_shaped_output_is_refused(value: str):
    assert not check_patch(GOOD + new_file("docs/x.md", [value])).ok
    verdicts = {"findings": [{"comment_id": 1, "verdict": "fixed", "reason": value}]}
    assert not check_verdicts(verdicts, [1], check_patch(GOOD)).ok


# ------------------------------------------------------------------ git's view, before applying


def test_git_agrees_on_a_good_patch(repo: Path, tmp_path: Path):
    data = good_real_patch(repo)
    report = check_patch(data)
    patch = write(tmp_path, "p.diff", data)
    assert gitcheck.pre_apply_problems(repo, patch, report.diffs) == []


def test_git_parser_disagreement_is_refused(repo: Path, tmp_path: Path, monkeypatch):
    data = good_real_patch(repo)
    report = check_patch(data)
    patch = write(tmp_path, "p.diff", data)
    monkeypatch.setattr(gitcheck, "numstat_paths", lambda r, p: ({SRC, ".github/x.yml"}, False))
    problems = gitcheck.pre_apply_problems(repo, patch, report.diffs)
    assert any("disagree" in p for p in problems)


def test_git_sees_binary_is_refused(repo: Path, tmp_path: Path, monkeypatch):
    data = good_real_patch(repo)
    report = check_patch(data)
    monkeypatch.setattr(gitcheck, "numstat_paths", lambda r, p: ({SRC, TEST}, True))
    problems = gitcheck.pre_apply_problems(repo, write(tmp_path, "p.diff", data), report.diffs)
    assert any("binary" in p for p in problems)


def test_patch_that_does_not_apply_is_refused(repo: Path, tmp_path: Path):
    text = edit_file(SRC, ["something else"], ["x = 2"]) + new_file("tests/test_y.py", ["x"])
    report = check_patch(text)
    assert report.ok, report.problems
    problems = gitcheck.pre_apply_problems(repo, write(tmp_path, "p.diff", text), report.diffs)
    assert any("does not apply" in p for p in problems)


@pytest.mark.parametrize("mode", ["120000", "100755", "160000"])
def test_existing_unusual_mode_is_refused(repo: Path, tmp_path: Path, mode: str):
    """A diff never repeats the mode of an existing file; the index is checked."""
    data = good_real_patch(repo)
    ref = "HEAD" if mode == "160000" else f":{SRC}"
    obj = gitcheck.git(repo, "rev-parse", ref).stdout.strip()
    gitcheck.git(repo, "update-index", "--cacheinfo", f"{mode},{obj},{SRC}")
    report = check_patch(data)
    problems = gitcheck.pre_apply_problems(repo, write(tmp_path, "p.diff", data), report.diffs)
    assert any(f"mode {mode}" in p for p in problems), problems


@pytest.mark.parametrize("new_path", ["docs/guide.md", "docs/sub/b.md"])
def test_case_only_collision_with_a_tracked_path_is_refused(repo: Path, new_path: str):
    (repo / "docs/Sub").mkdir()
    (repo / "docs/Sub/a.md").write_text("a\n", encoding="utf-8")
    gitcheck.git(repo, "add", "-A")
    gitcheck.git(repo, *GIT_ID, "commit", "-q", "-m", "sub")
    report = check_patch(new_file(new_path, ["x"]) + new_file("tests/test_y.py", ["x"]))
    assert report.ok, report.problems
    assert gitcheck.case_collisions(repo, report.diffs)


def test_no_case_collision_for_ordinary_new_files(repo: Path):
    report = check_patch(new_file("docs/new.md", ["x"]) + new_file("tests/test_y.py", ["x"]))
    assert gitcheck.case_collisions(repo, report.diffs) == []


@pytest.mark.parametrize(
    ("attributes", "expect"),
    [
        ("*.py filter=evil\n", "filter"),
        ("*.py working-tree-encoding=UTF-16\n", "working-tree-encoding"),
        ("*.py ident\n", "ident"),
        ("*.py diff=custom\n", "diff driver"),
        ("*.py merge=custom\n", "merge driver"),
        ("*.py binary\n", "binary"),
    ],
)
def test_content_transforming_attributes_are_refused(repo: Path, attributes: str, expect: str):
    (repo / ".gitattributes").write_text(attributes, encoding="utf-8")
    gitcheck.git(repo, "add", ".gitattributes")
    gitcheck.git(repo, *GIT_ID, "commit", "-q", "-m", "attrs")
    problems = gitcheck.attribute_problems(repo, [SRC, TEST])
    assert any(expect in p for p in problems), problems


def test_ordinary_text_attributes_are_allowed(repo: Path):
    assert gitcheck.attribute_problems(repo, [SRC, TEST]) == []


def test_git_runs_with_a_scrubbed_environment(repo: Path, tmp_path: Path, monkeypatch):
    """GIT_DIR / GIT_INDEX_FILE / a hostile global config cannot redirect the checks."""
    data = good_real_patch(repo)
    evil = tmp_path / "evil.gitconfig"
    evil.write_text("[alias]\n\tapply = !false\n[core]\n\tattributesFile = /x\n", encoding="utf-8")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "nowhere"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "index"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(evil))
    report = check_patch(data)
    assert gitcheck.pre_apply_problems(repo, write(tmp_path, "p.diff", data), report.diffs) == []


def test_git_environment_is_scrubbed():
    env = gitcheck._env()
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert not any(k in env for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"))


# ------------------------------------------------------------------ after applying


def applied(repo: Path, tmp_path: Path):
    data = good_real_patch(repo)
    report = check_patch(data)
    gitcheck.apply(repo, write(tmp_path, "p.diff", data))
    return report


def test_staged_result_matches_the_checked_patch(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    assert gitcheck.staged_problems(repo, report.diffs) == []


def test_untracked_file_after_apply_is_refused(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    (repo / "docs/extra.md").write_text("x\n", encoding="utf-8")
    assert any("untracked" in p for p in gitcheck.staged_problems(repo, report.diffs))


def test_unstaged_edit_after_apply_is_refused(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    (repo / "docs/Guide.md").write_text("changed\n", encoding="utf-8")
    assert any("unstaged" in p for p in gitcheck.staged_problems(repo, report.diffs))


def test_extra_staged_file_is_refused(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    (repo / "docs/Guide.md").write_text("changed\n", encoding="utf-8")
    gitcheck.git(repo, "add", "docs/Guide.md")
    problems = gitcheck.staged_problems(repo, report.diffs)
    assert any("not in the checked patch" in p for p in problems)


def test_staged_deletion_is_refused(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    gitcheck.git(repo, "rm", "-q", "docs/Guide.md")
    assert any("staged as D" in p for p in gitcheck.staged_problems(repo, report.diffs))


def test_staged_executable_bit_is_refused(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    gitcheck.git(repo, "update-index", "--chmod=+x", SRC)
    assert any("100755" in p for p in gitcheck.staged_problems(repo, report.diffs))


def test_patch_entry_that_was_not_staged_is_refused(repo: Path, tmp_path: Path):
    report = applied(repo, tmp_path)
    gitcheck.git(repo, "reset", "-q", "--", TEST)
    gitcheck.git(repo, "checkout", "-q", "--", TEST)
    assert any("not staged" in p for p in gitcheck.staged_problems(repo, report.diffs))


# ------------------------------------------------------------------ CLI end to end


def run_apply(tmp_path: Path, repo: Path, data: bytes, monkeypatch) -> int:
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    patch = write(tmp_path, "p.diff", data)
    findings = write(tmp_path, "f.json", json.dumps({"findings": [{"comment_id": 1}]}))
    verdicts = write(
        tmp_path,
        "v.json",
        json.dumps({"findings": [{"comment_id": 1, "verdict": "fixed", "reason": "r"}]}),
    )
    args = ["apply", "--patch", str(patch), "--findings", str(findings)]
    return cli.main([*args, "--verdicts", str(verdicts), "--repo", str(repo)])


def test_cli_apply_stages_a_good_patch(repo: Path, tmp_path: Path, monkeypatch):
    assert run_apply(tmp_path, repo, good_real_patch(repo), monkeypatch) == 0
    staged = gitcheck.git(repo, "diff", "--cached", "--name-only").stdout.split()
    assert sorted(staged) == [SRC, TEST]


def test_cli_apply_refuses_and_stages_nothing(repo: Path, tmp_path: Path, monkeypatch):
    bad = good_real_patch(repo) + new_file("pyproject.toml", ["[x]"]).encode()
    assert run_apply(tmp_path, repo, bad, monkeypatch) == 1
    assert gitcheck.git(repo, "diff", "--cached", "--name-only").stdout == ""


def test_cli_apply_refuses_an_empty_patch(repo: Path, tmp_path: Path, monkeypatch):
    assert run_apply(tmp_path, repo, b"", monkeypatch) == 1


# ------------------------------------------------------------------ verdicts


def test_verdicts_must_cover_every_finding_exactly_once():
    patch = check_patch(GOOD)
    ok = check_verdicts(
        {"summary": "s", "findings": [{"comment_id": 1, "verdict": "fixed", "reason": "r"}]},
        [1],
        patch,
    )
    assert ok.ok and ok.fixed == [1]
    assert not check_verdicts({"summary": "", "findings": []}, [1], patch).ok
    dup = {
        "findings": [
            {"comment_id": 1, "verdict": "fixed", "reason": ""},
            {"comment_id": 1, "verdict": "not_a_bug", "reason": ""},
        ]
    }
    assert not check_verdicts(dup, [1], patch).ok
    unknown = {"findings": [{"comment_id": 99, "verdict": "fixed", "reason": ""}]}
    assert not check_verdicts(unknown, [1], patch).ok
    bad = {"findings": [{"comment_id": 1, "verdict": "merged", "reason": ""}]}
    assert not check_verdicts(bad, [1], patch).ok


@pytest.mark.parametrize("raw", [None, "", [], {"findings": "x"}])
def test_malformed_verdicts_fail(raw):
    assert not check_verdicts(raw, [1], check_patch(GOOD)).ok


def test_fixed_needs_a_patch_and_a_patch_needs_a_fix():
    fixed = {"findings": [{"comment_id": 1, "verdict": "fixed", "reason": ""}]}
    assert not check_verdicts(fixed, [1], check_patch(b"")).ok
    not_bug = {"findings": [{"comment_id": 1, "verdict": "not_a_bug", "reason": ""}]}
    assert not check_verdicts(not_bug, [1], check_patch(GOOD)).ok


def test_needs_human_is_reported():
    raw = {"findings": [{"comment_id": 1, "verdict": "needs_human", "reason": "design"}]}
    report = check_verdicts(raw, [1], check_patch(b""))
    assert report.ok and report.needs_human == [1]


@pytest.mark.parametrize(
    "path",
    [
        "docs/AGENTS.md",  # Codex reads the nearest AGENTS.md: it would steer the gate's input
        "tests/Agents.MD",
        "docs/agents.override.md",
        "docs/claude.md",
        "tests/sub/CLAUDE.local.md",
        "tests/x/conftest.py",  # pytest loads it; its hooks see the whole session
        "tests/sub/pytest.ini",
        "tests/.gitattributes",
        "docs/.gitignore",
        "src/qradar_soar_mcp/.claude/settings.json",
        "src/qradar_soar_mcp/evil.pth",
        "src/qradar_soar_mcp/sitecustomize.py",
        "examples/setup.py",
        "config/pyproject.toml",
    ],
)
def test_tool_steering_names_are_refused_at_any_depth(path: str):
    """Second review of PR #12: protected names were only matched at the root."""
    assert path_allowed(path) is not None
    assert not check_patch(new_file(path, ["x"]) + GOOD).ok
