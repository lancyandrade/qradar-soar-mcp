"""Checks that ask git itself about an automated patch.

``patch_policy`` parses the patch with its own strict parser. Here git's parser
must agree with it (same file list, nothing binary, applies cleanly), the
existing tree is checked for things a diff does not show (current file modes,
case-only collisions, git attributes that change how content is written), and
after ``git apply --index`` the staged change set must be exactly what was
checked: only additions and modifications of regular 100644 files, nothing
unstaged, nothing untracked.

git runs with system and global configuration ignored and with hooks,
fsmonitor and symlinks off, so neither the runner's nor the PR's git settings
can change what is checked.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from review_loop import policy
from review_loop.patch_policy import ALLOWED_MODE, FileDiff, check_existing_modes

HARDENED = (
    "-c", "core.hooksPath=" + os.devnull,
    "-c", "core.fsmonitor=false",
    "-c", "core.symlinks=false",
    "-c", "core.protectNTFS=true",
    "-c", "core.protectHFS=true",
    "-c", "core.quotePath=true",
    "-c", "apply.whitespace=nowarn",
)  # fmt: skip

# Attributes that make git transform or reinterpret content on its way in or out.
_TRANSFORMING = ("filter", "working-tree-encoding", "ident")
_DRIVER_ATTRS = ("diff", "merge")


class GitCheckError(RuntimeError):
    pass


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_ATTR_NOSYSTEM="1",
    )
    return env


def git(repo: str | Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(  # noqa: S603 - fixed program, argv list, no shell
        ["git", "-C", str(repo), *HARDENED, *args],  # noqa: S607
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_env(),
    )
    if check and proc.returncode != 0:
        raise GitCheckError(f"git {args[0]} failed ({proc.returncode})")
    return proc


def numstat_paths(repo: str | Path, patch: str | Path) -> tuple[set[str], bool]:
    """Paths git would touch, and whether git sees any binary change."""
    out = git(repo, "apply", "--numstat", "-z", str(patch)).stdout
    fields = out.split("\0")
    paths: set[str] = set()
    binary = False
    i = 0
    while i < len(fields) and fields[i]:
        added, deleted, path = fields[i].split("\t", 2)
        if added == "-" or deleted == "-":
            binary = True
        if path:
            paths.add(path)
            i += 1
        else:  # rename/copy: "a\td\t\0old\0new\0"
            paths.update(fields[i + 1 : i + 3])
            i += 3
    return paths, binary


def case_collisions(repo: str | Path, diffs: list[FileDiff]) -> list[str]:
    """New paths whose file or directory name differs only in case from a tracked one."""
    tracked = [p for p in git(repo, "ls-files", "-z").stdout.split("\0") if p]
    known: dict[str, str] = {}
    for path in tracked:
        parts = path.split("/")
        for k in range(1, len(parts) + 1):
            prefix = "/".join(parts[:k])
            known.setdefault(prefix.casefold(), prefix)
    problems = []
    for fd in diffs:
        parts = fd.new_path.split("/")
        for k in range(1, len(parts) + 1):
            prefix = "/".join(parts[:k])
            existing = known.get(prefix.casefold())
            if existing is not None and existing != prefix:
                problems.append(f"{fd.new_path}: differs only in case from {existing}")
                break
    return problems


def attribute_problems(repo: str | Path, paths: list[str]) -> list[str]:
    if not paths:
        return []
    names = [*_TRANSFORMING, *_DRIVER_ATTRS, "binary"]
    out = git(repo, "check-attr", "-z", *names, "--", *paths).stdout
    fields = out.split("\0")
    problems = []
    for j in range(0, len(fields) - 2, 3):
        path, attr, value = fields[j : j + 3]
        if attr in _TRANSFORMING and value not in ("unspecified", "unset"):
            problems.append(f"{path}: attribute {attr}={value} is not allowed")
        elif attr in _DRIVER_ATTRS and value not in ("unspecified", "set", "unset"):
            problems.append(f"{path}: custom {attr} driver {value!r} is not allowed")
        elif attr == "binary" and value == "set":
            problems.append(f"{path}: marked binary")
    return problems


def pre_apply_problems(repo: str | Path, patch: str | Path, diffs: list[FileDiff]) -> list[str]:
    """Everything git can tell about the patch before it is applied."""
    ours = {p for fd in diffs for p in fd.paths}
    problems: list[str] = []
    try:
        theirs, binary = numstat_paths(repo, patch)
    except GitCheckError:
        return ["git cannot parse the patch"]
    if theirs != ours:
        problems.append("git and the policy parser disagree about which files the patch touches")
    if binary:
        problems.append("git sees a binary change")
    if git(repo, "apply", "--check", str(patch), check=False).returncode != 0:
        problems.append("the patch does not apply cleanly")
    paths = sorted(ours)
    if paths:
        problems += check_existing_modes(git(repo, "ls-files", "-s", "--", *paths).stdout)
    problems += case_collisions(repo, diffs)
    problems += attribute_problems(repo, paths)
    return problems


def apply(repo: str | Path, patch: str | Path) -> None:
    git(repo, "apply", "--index", str(patch))


def staged_problems(repo: str | Path, diffs: list[FileDiff]) -> list[str]:
    """After ``git apply --index``: the index holds exactly the checked change."""
    expected = {fd.new_path for fd in diffs}
    out = git(repo, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff").stdout
    fields = out.split("\0")
    problems: list[str] = []
    seen: set[str] = set()
    i = 0
    while i + 1 < len(fields) and fields[i].startswith(":"):
        meta, path = fields[i], fields[i + 1]
        old_mode, new_mode, _old, _new, status = meta[1:].split(" ")
        seen.add(path)
        if status not in ("A", "M"):
            problems.append(f"{path}: staged as {status}, only additions and edits are allowed")
        if new_mode != ALLOWED_MODE or (status == "M" and old_mode != ALLOWED_MODE):
            problems.append(f"{path}: staged mode {old_mode} -> {new_mode}")
        if path not in expected:
            problems.append(f"{path}: staged but not in the checked patch")
        i += 2
    for path in sorted(expected - seen):
        problems.append(f"{path}: in the patch but not staged")
    status_out = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    for entry in (e for e in status_out.split("\0") if e):
        code, path = entry[:2], entry[3:]
        if code == "??":
            problems.append(f"{path}: untracked file in the work tree")
        elif code[1] != " ":
            problems.append(f"{path}: unstaged change in the work tree")
    if len(seen) > policy.MAX_PATCH_FILES:
        problems.append("too many staged files")
    return problems
