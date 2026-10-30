"""SEC-14: scripts/check_artifact_hygiene.py, offline.

The repository itself must pass; synthetic git repositories under ``tmp_path`` show
each failure class; and the checker never deletes, changes or reads the contents of
a local artefact.
"""

from __future__ import annotations

import ast
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_artifact_hygiene.py"
CANARY = "HYGIENE-CANARY-CONTENT-must-never-be-printed"

spec = importlib.util.spec_from_file_location("check_artifact_hygiene", SCRIPT)
assert spec and spec.loader
hygiene = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = hygiene  # dataclasses resolve the module by name
spec.loader.exec_module(hygiene)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(tmp_path: Path, gitignore: str) -> Path:
    root = tmp_path / "repo"
    (root / "src" / "qradar_soar_mcp").mkdir(parents=True)
    _git(root, "init", "-q")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    _git(root, "add", ".gitignore")  # only a tracked .gitignore counts
    return root


def test_this_repository_is_clean():
    assert hygiene.run_checks(ROOT) == []


def test_every_sample_path_is_ignored_by_the_tracked_gitignore_alone():
    result = hygiene.ignored_by_tracked_gitignore(hygiene.MUST_BE_IGNORED, ROOT)
    assert [p for p, ok in result.items() if not ok] == []
    keep = hygiene.ignored_by_tracked_gitignore(hygiene.MUST_NOT_BE_IGNORED, ROOT)
    assert not any(keep.values())


def test_a_per_machine_exclude_does_not_count(tmp_path: Path):
    """The H-5 lesson: .git/info/exclude protects one machine, not the next clone."""
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").replace(".playwright-mcp/\n", "")
    root = _repo(tmp_path, gitignore)
    (root / ".git" / "info" / "exclude").write_text(".playwright-mcp/\n", encoding="utf-8")
    kinds = {(f.kind, f.path) for f in hygiene.check_ignore_rules(root)}
    assert ("not-ignored", ".playwright-mcp/console.log") in kinds
    assert ("not-ignored", ".playwright-mcp/page.png") in kinds


def test_an_over_broad_rule_is_reported(tmp_path: Path):
    root = _repo(tmp_path, (ROOT / ".gitignore").read_text(encoding="utf-8") + "*.lock\n")
    assert ("over-ignored", "uv.lock") in {
        (f.kind, f.path) for f in hygiene.check_ignore_rules(root)
    }


def test_a_tracked_sensitive_file_fails(tmp_path: Path):
    root = _repo(tmp_path, "")
    for name in ("key.pem", ".env", "audit.jsonl", ".env.example"):
        (root / name).write_text("x", encoding="utf-8")
    _git(root, "add", "-f", "key.pem", ".env", "audit.jsonl", ".env.example")
    found = {f.path for f in hygiene.check_tracked_files(root)}
    assert found == {"key.pem", ".env", "audit.jsonl"}


def test_sensitive_directories_are_matched_at_every_depth(tmp_path: Path):
    """PR #22 review: `.local/`, `.playwright-mcp/` and the other directory rules apply
    at any depth in .gitignore, so a nested tracked file must fail too, whatever its
    extension; a file merely *named* like a sensitive directory must not."""
    root = _repo(tmp_path, "")
    nested = [
        "src/qradar_soar_mcp/.local/notes.txt",
        "docs/.playwright-mcp/page.png",
        "tests/approvals/APR-1.json",
        "deep/a/b/lab-evidence/run.txt",
        ".claude/settings.json",
    ]
    harmless = ["src/qradar_soar_mcp/security/approvals.py", "tests/__snapshots__/x.ambr"]
    for name in nested + harmless:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("x", encoding="utf-8")
    _git(root, "add", "-f", *nested, *harmless)
    found = {f.path for f in hygiene.check_tracked_files(root)}
    assert found == set(nested)


def test_an_untracked_file_in_the_package_fails(tmp_path: Path):
    root = _repo(tmp_path, "*.log\n")
    (root / "src" / "qradar_soar_mcp" / "notes.txt").write_text("x", encoding="utf-8")
    (root / "src" / "qradar_soar_mcp" / "ignored.log").write_text("x", encoding="utf-8")
    found = hygiene.check_package_tree(root)
    assert [(f.kind, f.path) for f in found] == [
        ("untracked-in-package", "src/qradar_soar_mcp/notes.txt")
    ]


def test_a_package_file_hidden_only_by_a_per_machine_exclude_still_fails(tmp_path: Path):
    """Review M1: Hatch honours .gitignore only, so .git/info/exclude must not hide a
    file the sdist would pack (the H-5 failure mode)."""
    root = _repo(tmp_path, "*.log\n")
    (root / ".git" / "info" / "exclude").write_text("stray.txt\n", encoding="utf-8")
    (root / "src" / "qradar_soar_mcp" / "stray.txt").write_text("x", encoding="utf-8")
    found = [(f.kind, f.path) for f in hygiene.check_package_tree(root)]
    assert found == [("untracked-in-package", "src/qradar_soar_mcp/stray.txt")]


def test_an_untracked_nested_gitignore_does_not_count(tmp_path: Path):
    """Review m1: a .gitignore git does not track exists on this machine only."""
    root = _repo(tmp_path, "")
    (root / ".playwright-mcp").mkdir()
    (root / ".playwright-mcp" / ".gitignore").write_text("*\n", encoding="utf-8")
    result = hygiene.ignored_by_tracked_gitignore([".playwright-mcp/page.png"], root)
    assert result == {".playwright-mcp/page.png": False}
    _git(root, "add", "-f", ".playwright-mcp/.gitignore")  # once tracked, it counts
    result = hygiene.ignored_by_tracked_gitignore([".playwright-mcp/page.png"], root)
    assert result == {".playwright-mcp/page.png": True}


def test_an_untracked_root_gitignore_does_not_count(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / ".gitignore").write_text(".env\n", encoding="utf-8")  # never added
    assert hygiene.ignored_by_tracked_gitignore([".env"], root) == {".env": False}


def test_the_report_names_files_and_never_touches_them(tmp_path: Path):
    root = _repo(tmp_path, (ROOT / ".gitignore").read_text(encoding="utf-8"))
    files = [
        root / ".playwright-mcp" / "page.yml",
        root / "audit.jsonl",
        root / ".local" / "ca.pem",
        root / "lab-evidence" / "t4" / "audit.jsonl",
    ]
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CANARY, encoding="utf-8")
    lines = hygiene.local_report(root)
    text = "\n".join(lines)
    for path in files:
        assert path.relative_to(root).as_posix() in text
        assert path.read_text(encoding="utf-8") == CANARY  # still there, unchanged
    assert CANARY not in text
    assert any(line.startswith("worktree ") for line in lines)


def test_the_checker_has_no_way_to_delete_or_write():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    forbidden = {
        "unlink", "rmdir", "rmtree", "remove", "removedirs", "rename", "replace",
        "move", "write_text", "write_bytes", "truncate", "chmod",
    }  # fmt: skip
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert calls & forbidden == set()
    names = {
        a.name
        for n in ast.walk(tree)
        if isinstance(n, ast.Import | ast.ImportFrom)
        for a in n.names
    }
    assert "shutil" not in names and "os" not in names
    assert '"open"' not in SCRIPT.read_text(encoding="utf-8")


def test_cli_exits_zero_on_this_repository():
    assert hygiene.main(["--quiet"]) == 0
