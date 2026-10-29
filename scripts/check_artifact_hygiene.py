"""SEC-14: check that local development artefacts cannot reach git or a package.

Read-only and non-destructive. It never deletes, moves, opens or prints the contents
of any file: it reads ``.gitignore`` rules through ``git check-ignore``, lists file
*names*, sizes and ages, and exits non-zero on a hard failure.

Run from the repository root:

    python scripts/check_artifact_hygiene.py           # checks + local report
    python scripts/check_artifact_hygiene.py --quiet   # checks only

Hard failures (exit 1):

1. a sensitive path that no tracked ``.gitignore`` ignores (a per-machine
   ``.git/info/exclude``, a global ignore file or an untracked ``.gitignore`` does not
   count: another clone would not have it);
2. a tracked file that matches a sensitive pattern;
3. an untracked file under ``src/qradar_soar_mcp/`` that no tracked ``.gitignore``
   ignores: the sdist and the wheel take it (Hatch reads ``.gitignore`` only;
   release-readiness §5 H-5, §12.1).

The report (never a failure) lists local artefacts that the retention rules of
``docs/runbooks/artifact-hygiene.md`` ask a human to review, and every git worktree,
which must be removed only with ``git worktree remove`` after review.
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "src/qradar_soar_mcp"

# Sample paths that must be ignored by the tracked .gitignore alone.
MUST_BE_IGNORED = (
    ".env",
    ".env.local",
    "audit.jsonl",
    "state/audit.jsonl",
    "approvals/APR-1.json",
    "snapshots/s.res",
    "debug.log",
    ".playwright-mcp/console.log",
    ".playwright-mcp/page.png",
    ".claude/settings.local.json",
    ".claude/worktrees/w/README.md",
    ".local/ca.pem",
    ".local/notes.txt",
    "key.pem",
    "id.key",
    "client.p12",
    "lab-evidence/t4/audit.jsonl",
    ".coverage",
    ".venv/pyvenv.cfg",
    "dist/qradar_soar_mcp-0.2.0.tar.gz",
    "src/qradar_soar_mcp/__pycache__/x.cpython-312.pyc",
    "src/qradar_soar_mcp/x.log",
    ".pytest_cache/README.md",
    ".mypy_cache/x",
    ".ruff_cache/x",
    ".hypothesis/x",
    "scripts/probe/raw/x.json",
    "tests/fixtures/raw/x.json",
)
# Paths that must stay trackable (the ignore rules must not swallow them).
MUST_NOT_BE_IGNORED = (".env.example", "config/action_policy.example.yaml", "uv.lock")

SENSITIVE_TRACKED = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.crt",
    "*.jsonl",
    "*.log",
    "*.res",
    "*.resz",
    ".playwright-mcp/*",
    ".claude/*",
    ".local/*",
    "approvals/*",
    "snapshots/*",
)
TRACKED_ALLOWED = {".env.example"}

REVIEW_GLOBS = (
    ".playwright-mcp/*",
    "audit.jsonl",
    "*.jsonl",
    ".local/*",
    ".coverage",
    "dist/*",
    "lab-evidence/**/*",
)


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    detail: str


def _git(
    args: Sequence[str], root: Path, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args],  # noqa: S607 - git from PATH, as every developer runs it
        cwd=root,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def ignored_by_tracked_gitignore(paths: Iterable[str], root: Path) -> dict[str, bool]:
    """For each path: does a tracked ``.gitignore`` rule ignore it?

    ``git check-ignore -v -n -z --no-index`` names the deciding rule's source. The path
    counts as ignored only if that source is a ``.gitignore`` **tracked by git**: a
    match from ``.git/info/exclude``, the global excludes file or an untracked
    ``.gitignore`` (which another clone would not have) is reported as *not* ignored,
    and so is a negation (``!``) rule. This errs towards a failure: if an untracked
    ``.gitignore`` decides, a tracked rule that would also match is not consulted.
    NUL-separated bytes, so no platform newline or quoting changes a path.
    """
    items = list(paths)
    tracked = set(filter(None, _git(["ls-files", "-z"], root).stdout.split("\0")))
    proc = subprocess.run(
        ["git", "check-ignore", "-v", "-n", "-z", "--no-index", "--stdin"],  # noqa: S607
        cwd=root,
        input=b"\0".join(i.encode("utf-8") for i in items) + b"\0",
        capture_output=True,
        check=False,
    )
    fields = proc.stdout.decode("utf-8").split("\0")
    result = dict.fromkeys(items, False)
    for i in range(0, len(fields) - 3, 4):
        source, _line, pattern, path = fields[i : i + 4]
        if path in result and source and pattern and not pattern.startswith("!"):
            rel = "/".join(source.split("\\")).removeprefix("./")
            result[path] = Path(rel).name == ".gitignore" and rel in tracked
    return result


def check_ignore_rules(root: Path) -> list[Finding]:
    findings = []
    ignored = ignored_by_tracked_gitignore(MUST_BE_IGNORED + MUST_NOT_BE_IGNORED, root)
    for path in MUST_BE_IGNORED:
        if not ignored[path]:
            findings.append(Finding("not-ignored", path, "not ignored by the tracked .gitignore"))
    for path in MUST_NOT_BE_IGNORED:
        if ignored[path]:
            findings.append(Finding("over-ignored", path, "must stay trackable"))
    return findings


def check_tracked_files(root: Path) -> list[Finding]:
    tracked = _git(["ls-files", "-z"], root).stdout.split("\0")
    findings = []
    for path in filter(None, tracked):
        name = path.rsplit("/", 1)[-1]
        if path in TRACKED_ALLOWED:
            continue
        if any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in SENSITIVE_TRACKED):
            findings.append(
                Finding("tracked-sensitive", path, "tracked file matches a sensitive pattern")
            )
    return findings


def check_package_tree(root: Path) -> list[Finding]:
    """Every untracked file under the package that no *tracked* ``.gitignore`` ignores.

    Hatch honours ``.gitignore`` only (release-readiness H-5), so git's standard
    exclusions (``.git/info/exclude``, the global excludes file) must not hide a file
    here: list every untracked file, then keep those the tracked rules do not ignore.
    """
    proc = _git(["ls-files", "--others", "-z", "--", PACKAGE], root)
    untracked = list(filter(None, proc.stdout.split("\0")))
    ignored = ignored_by_tracked_gitignore(untracked, root) if untracked else {}
    return [
        Finding("untracked-in-package", p, "would be packed into the sdist and wheel")
        for p in untracked
        if not ignored.get(p)
    ]


def run_checks(root: Path = ROOT) -> list[Finding]:
    return check_ignore_rules(root) + check_tracked_files(root) + check_package_tree(root)


def local_report(root: Path = ROOT, now: float | None = None) -> list[str]:
    """Names, sizes and ages of local artefacts to review, and the git worktrees."""
    now = time.time() if now is None else now
    lines = []
    seen: set[Path] = set()
    for pattern in REVIEW_GLOBS:
        for path in sorted(root.glob(pattern)):
            if not path.is_file() or path in seen or ".venv" in path.parts:
                continue
            seen.add(path)
            stat = path.stat()
            age = int((now - stat.st_mtime) // 86_400)
            rel = path.relative_to(root).as_posix()
            lines.append(f"review  {rel}  {stat.st_size} bytes  {age} days old")
    worktrees = _git(["worktree", "list", "--porcelain"], root).stdout
    for block in worktrees.strip().split("\n\n"):
        fields = dict(line.split(" ", 1) for line in block.splitlines() if " " in line)
        if "worktree" in fields:
            branch = fields.get("branch", "(detached)").removeprefix("refs/heads/")
            lines.append(
                f"worktree  {fields['worktree']}  {branch}  (keep; remove only after review)"
            )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--quiet", action="store_true", help="checks only, no local report")
    args = parser.parse_args(argv)
    findings = run_checks(ROOT)
    for f in findings:
        print(f"FAIL  {f.kind}  {f.path}: {f.detail}")
    if not args.quiet:
        for line in local_report(ROOT):
            print(line)
    if findings:
        print(f"check_artifact_hygiene: {len(findings)} problem(s)", file=sys.stderr)
        return 1
    print("check_artifact_hygiene: clean (nothing was deleted or opened)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
