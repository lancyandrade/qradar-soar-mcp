"""Review loop: git must never run a command chosen by the model.

Codex on PR #12 (commit 6d99f55): the fix job built the patch with
``git add`` while ~/.gitconfig and the work tree's .gitattributes were
writable by the model, so a ``filter.<x>.clean`` command would run inside the
job that can obtain Anthropic credentials. These tests plant every
configuration-based execution path git has (filter and diff drivers,
textconv, fsmonitor, hooks, pager, ``GIT_CONFIG_*`` injection) in every place
git reads configuration from, then build and check a patch, and assert that
the planted command never ran. Each command only touches a marker file in a
temporary directory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from review_loop import cli, gitcheck
from review_loop.patch_policy import check_patch

ID = ("-c", "user.name=t", "-c", "user.email=t@example.invalid")


def marker_command(marker: Path) -> str:
    # Runs under git's shell (sh, also on Git for Windows). Touches the marker,
    # then passes stdin through so a "working" filter would look harmless.
    return f"echo pwned >> '{marker.as_posix()}'; cat"


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A PR checkout, its pristine .git copy, and a 'model-edited' work tree."""
    work = tmp_path / "work"
    (work / "src/qradar_soar_mcp/tools").mkdir(parents=True)
    (work / "tests").mkdir()
    (work / "src/qradar_soar_mcp/tools/x.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    (work / "tests/test_x.py").write_text(
        "def test_x():\n    pass\n", encoding="utf-8", newline="\n"
    )
    gitcheck.git(tmp_path, "init", "-q", str(work))
    gitcheck.git(work, "add", "-A")
    gitcheck.git(work, *ID, "commit", "-q", "-m", "init")
    base = gitcheck.git(work, "rev-parse", "HEAD").stdout.strip()
    pristine = tmp_path / "pristine.git"
    shutil.copytree(work / ".git", pristine)
    # The model's edits: a fix, a regression test, and a hostile .gitattributes.
    (work / "src/qradar_soar_mcp/tools/x.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
    (work / "tests/test_x.py").write_text(
        "def test_x():\n    pass\n\n\ndef test_y():\n    assert True\n",
        encoding="utf-8",
        newline="\n",
    )
    (work / ".gitattributes").write_text(
        "* filter=evil diff=evil\n*.py filter=lfs\n", encoding="utf-8", newline="\n"
    )
    marker = tmp_path / "MARKER"
    home = tmp_path / "home"
    (home / ".config" / "git").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    return work, pristine, base, marker, home


def hostile_config(marker: Path) -> str:
    cmd = marker_command(marker)
    return (
        f'[filter "evil"]\n\tclean = {cmd}\n\tsmudge = {cmd}\n\tprocess = {cmd}\n'
        f'[filter "lfs"]\n\tclean = {cmd}\n\trequired = true\n'
        f'[diff "evil"]\n\tcommand = {cmd}\n\ttextconv = {cmd}\n'
        f"[diff]\n\texternal = {cmd}\n"
        f"[core]\n\tfsmonitor = {cmd}\n\tpager = {cmd}\n"
        f"\thooksPath = {marker.parent.as_posix()}/hooks\n"
        f"[alias]\n\tadd = !{cmd}\n\tdiff = !{cmd}\n"
    )


def plant_hooks(marker: Path) -> None:
    hooks = marker.parent / "hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("pre-commit", "post-index-change", "fsmonitor-watchman", "pre-applypatch"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\n{marker_command(marker)}\n", encoding="utf-8", newline="\n")
        hook.chmod(0o755)


# ------------------------------------------------------------------ reproduction


def test_reproduction_the_old_command_ran_the_planted_filter(setup):
    """Regression anchor: the fix job's former `git add` executes the filter."""
    work, pristine, _base, marker, home = setup
    (home / ".gitconfig").write_text(hostile_config(marker), encoding="utf-8", newline="\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
    subprocess.run(
        ["git", f"--git-dir={pristine}", f"--work-tree={work}", "-c", "core.hooksPath=/dev/null",
         "-c", "core.fsmonitor=false", "add", "-A", "--", "."],
        env=env, capture_output=True, check=False,
    )  # fmt: skip
    assert marker.exists(), "the reproduction no longer reproduces; update the test"


# ------------------------------------------------------------------ patch construction


@pytest.mark.parametrize(
    "where", ["global", "xdg", "pristine-repo", "env-parameters", "env-count", "work-tree-gitfile"]
)
def test_build_patch_runs_no_planted_command(setup, monkeypatch, where: str):
    work, pristine, base, marker, home = setup
    config = hostile_config(marker)
    plant_hooks(marker)
    if where == "global":
        (home / ".gitconfig").write_text(config, encoding="utf-8", newline="\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
    elif where == "xdg":
        (home / ".config" / "git" / "config").write_text(config, encoding="utf-8", newline="\n")
        (home / ".config" / "git" / "attributes").write_text(
            "* filter=evil\n", encoding="utf-8", newline="\n"
        )
    elif where == "pristine-repo":
        # Even if the pristine copy's own config were tampered with, the
        # builder uses a fresh git directory and only borrows objects.
        with (pristine / "config").open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(config)
        (pristine / "info").mkdir(exist_ok=True)
        (pristine / "info" / "attributes").write_text(
            "* filter=evil\n", encoding="utf-8", newline="\n"
        )
    elif where == "env-parameters":
        cmd = marker_command(marker).replace("'", "")
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'filter.evil.clean'='{cmd}'")
    elif where == "env-count":
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.evil.clean")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", marker_command(marker))
    elif where == "work-tree-gitfile":
        # A model-written .git file in a subdirectory pointing at a hostile repo.
        hostile = marker.parent / "hostile.git"
        subprocess.run(
            ["git", "init", "-q", "--bare", str(hostile)], check=True, capture_output=True
        )
        (hostile / "config").write_text(config, encoding="utf-8", newline="\n")
        (work / "src" / ".git").write_text(
            f"gitdir: {hostile.as_posix()}\n", encoding="utf-8", newline="\n"
        )
    patch = gitcheck.build_patch(work, pristine / "objects", base)
    assert not marker.exists(), f"a planted command ran ({where})"
    text = patch.decode()
    assert "src/qradar_soar_mcp/tools/x.py" in text and "tests/test_x.py" in text
    # The hostile .gitattributes is in the patch as content, and the policy refuses it.
    assert ".gitattributes" in text
    assert not check_patch(patch).ok


def test_build_patch_output_is_plain_git_format(setup):
    work, pristine, base, _marker, _home = setup
    (work / ".gitattributes").unlink()
    patch = gitcheck.build_patch(work, pristine / "objects", base)
    report = check_patch(patch)
    assert report.ok, report.problems
    assert report.files == ["src/qradar_soar_mcp/tools/x.py", "tests/test_x.py"]


def test_build_patch_needs_a_full_base_sha(setup):
    work, pristine, _base, _marker, _home = setup
    with pytest.raises(gitcheck.GitCheckError):
        gitcheck.build_patch(work, pristine / "objects", "HEAD")


# ------------------------------------------------------------------ the verify / push path


def test_apply_and_checks_run_no_planted_command(setup, monkeypatch, tmp_path: Path):
    """The trusted checks in verify/push run git on a tree with hostile config too."""
    work, pristine, base, marker, home = setup
    (work / ".gitattributes").unlink()
    data = gitcheck.build_patch(work, pristine / "objects", base)
    report = check_patch(data)
    patch = tmp_path / "p.diff"
    patch.write_bytes(data)
    # A fresh checkout to apply to, with every hostile source planted.
    target = tmp_path / "target"
    gitcheck.git(tmp_path, "clone", "-q", str(work), str(target))
    (target / ".gitattributes").write_text(
        "* filter=evil diff=evil\n", encoding="utf-8", newline="\n"
    )
    gitcheck.git(target, "add", ".gitattributes")
    gitcheck.git(target, *ID, "commit", "-q", "-m", "attrs")
    (home / ".gitconfig").write_text(hostile_config(marker), encoding="utf-8", newline="\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'filter.evil.clean'='touch nope'")
    plant_hooks(marker)
    with (target / ".git" / "config").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"[core]\n\thooksPath = {(marker.parent / 'hooks').as_posix()}\n")
    problems = gitcheck.pre_apply_problems(target, patch, report.diffs)
    gitcheck.apply(target, patch)
    gitcheck.staged_problems(target, report.diffs)
    assert not marker.exists()
    # The existing filter attribute is reported, so the policy refuses this tree.
    assert any("filter" in p for p in problems)


# ------------------------------------------------------------------ configuration manifest


def test_manifest_detects_a_planted_global_config(setup, monkeypatch):
    _work, pristine, _base, marker, home = setup
    before = gitcheck.config_manifest(cli.git_config_paths(str(pristine)))
    (home / ".gitconfig").write_text(hostile_config(marker), encoding="utf-8", newline="\n")
    assert gitcheck.config_manifest(cli.git_config_paths(str(pristine))) != before


@pytest.mark.parametrize("target", ["config", "hooks/pre-commit", "info/attributes"])
def test_manifest_detects_a_tampered_pristine_copy(setup, target: str):
    _work, pristine, _base, _marker, _home = setup
    before = gitcheck.config_manifest(cli.git_config_paths(str(pristine)))
    path = pristine / target
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write("\n[core]\n\tfsmonitor = x\n")
    assert gitcheck.config_manifest(cli.git_config_paths(str(pristine))) != before


def test_manifest_detects_xdg_config_and_attributes(setup):
    _work, pristine, _base, _marker, home = setup
    before = gitcheck.config_manifest(cli.git_config_paths(str(pristine)))
    (home / ".config" / "git" / "attributes").write_text(
        "* filter=x\n", encoding="utf-8", newline="\n"
    )
    assert gitcheck.config_manifest(cli.git_config_paths(str(pristine))) != before


def test_check_git_manifest_command(setup, monkeypatch, tmp_path: Path):
    _work, pristine, _base, marker, home = setup
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    assert cli.main(["git-manifest", "--pristine", str(pristine)]) == 0
    digest = (tmp_path / "out.txt").read_text(encoding="utf-8").strip().split("=", 1)[1]
    assert cli.main(["check-git-manifest", "--pristine", str(pristine), "--expect", digest]) == 0
    (home / ".gitconfig").write_text(hostile_config(marker), encoding="utf-8", newline="\n")
    assert cli.main(["check-git-manifest", "--pristine", str(pristine), "--expect", digest]) == 1
    with pytest.raises(SystemExit):
        cli.main(["check-git-manifest", "--pristine", str(pristine), "--expect", ""])


def test_build_patch_command_refuses_credentials_in_model_output(setup, monkeypatch, tmp_path):
    work, pristine, base, _marker, _home = setup
    (work / ".gitattributes").unlink()
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    out = tmp_path / "out"
    args = ["build-patch", "--worktree", str(work), "--objects", str(pristine / "objects")]
    monkeypatch.setenv("VERDICTS", '{"findings": [], "summary": "ok"}')
    assert cli.main([*args, "--base", base, "--out", str(out)]) == 0
    assert (out / "patch.diff").read_bytes() and (out / "verdicts.json").exists()
    leak = "ghs_" + "a" * 36
    monkeypatch.setenv("VERDICTS", '{"summary": "' + leak + '"}')
    out2 = tmp_path / "out2"
    assert cli.main([*args, "--base", base, "--out", str(out2)]) == 1
    assert not (out2 / "patch.diff").exists()
