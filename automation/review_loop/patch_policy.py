"""Validation of the patch an automated fix produced, and of its verdicts.

The patch comes from a model that read untrusted review text, so it is treated
as untrusted: it is checked by this code (from the default branch) in the
unprivileged test job and again in the push job, before anything is pushed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from review_loop import policy

# Where an automated fix may write. Everything else is refused.
ALLOWED_PREFIXES: tuple[str, ...] = (
    "src/qradar_soar_mcp/",
    "tests/",
    "docs/",
    "examples/",
    "config/",
    "README.md",
)
_ALLOWED_MODES = {"100644"}
_DIFF_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$")
_PATH_OK = re.compile(r"[A-Za-z0-9._/-]+")
_TEST_FILE = re.compile(r"^tests/(?:.+/)?test_[A-Za-z0-9_]+\.py$")

VERDICTS = frozenset({"fixed", "not_a_bug", "already_fixed", "needs_human"})


@dataclass
class PatchReport:
    ok: bool
    files: list[str] = field(default_factory=list)
    changed_lines: int = 0
    problems: list[str] = field(default_factory=list)
    touches_tests: bool = False

    @property
    def empty(self) -> bool:
        return not self.files


def path_allowed(path: str) -> str | None:
    """None when ``path`` may be written by an automated fix, else the reason.

    Protected prefixes are matched case-insensitively, and components that
    Windows would alias (a trailing dot or space) are refused, so `.GITHUB/` or
    `security./` cannot reach a protected directory on a case-insensitive
    checkout.
    """
    parts = path.split("/")
    if not _PATH_OK.fullmatch(path) or path.startswith("/") or ".." in parts:
        return f"{path!r}: unusual path"
    if any(not p or p.endswith((".", " ")) for p in parts):
        return f"{path!r}: unusual path component"
    if policy.path_matches(path, policy.FIX_FORBIDDEN_PATH_PREFIXES):
        return f"{path}: protected path"
    if not any(path == p or path.startswith(p) for p in ALLOWED_PREFIXES):
        return f"{path}: outside the paths a fix may change"
    return None


def secret_hits(text: str) -> list[str]:
    """Names of credential patterns found in ``text`` (the values are never returned)."""
    return [p.pattern[:20] for p in policy.SECRET_PATTERNS if p.search(text)]


def check_patch(text: str) -> PatchReport:
    report = PatchReport(ok=True)
    if "\0" in text:
        report.problems.append("patch contains NUL bytes")
    if secret_hits(text):
        report.problems.append("patch contains a credential-shaped value")
    files: list[str] = []
    added_in_tests = 0
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("diff --git "):
            match = _DIFF_HEADER.match(line)
            current = None
            if not match:
                report.problems.append("unparseable or quoted diff header")
                continue
            current = match.group(2)
            for path in {match.group(1), match.group(2)}:
                files.append(path)
                if (why := path_allowed(path)) is not None:
                    report.problems.append(why)
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            path = line.split(" ", 2)[2]
            if (why := path_allowed(path)) is not None:
                report.problems.append(why)
        elif line.startswith("deleted file mode "):
            report.problems.append("an automated fix may not delete files")
        elif line.startswith(("new file mode ", "new mode ", "old mode ")):
            mode = line.rsplit(" ", 1)[1]
            if mode not in _ALLOWED_MODES:
                report.problems.append(f"file mode {mode} is not allowed")
        elif line.startswith(("GIT binary patch", "Binary files ")):
            report.problems.append("binary changes are not allowed")
        elif line.startswith(("+++ ", "--- ")):
            continue
        elif line.startswith(("+", "-")):
            report.changed_lines += 1
            if line.startswith("+") and current is not None and _TEST_FILE.match(current):
                added_in_tests += 1
    report.files = sorted(set(files))
    report.touches_tests = added_in_tests > 0
    if len(report.files) > policy.MAX_PATCH_FILES:
        report.problems.append(
            f"{len(report.files)} files changed (limit {policy.MAX_PATCH_FILES})"
        )
    if report.changed_lines > policy.MAX_PATCH_CHANGED_LINES:
        report.problems.append(
            f"{report.changed_lines} changed lines (limit {policy.MAX_PATCH_CHANGED_LINES})"
        )
    if report.files and not report.touches_tests:
        report.problems.append("a fix must add a regression test in a tests/test_*.py file")
    report.ok = not report.problems
    return report


def check_existing_modes(ls_files_output: str) -> list[str]:
    """Problems with the current modes of files the patch touches.

    ``ls_files_output`` is ``git ls-files -s -- <paths>`` from the checkout the
    patch applies to. A diff does not repeat the mode of an existing file, so an
    edit to an existing symlink, submodule or executable is caught here.
    """
    problems = []
    for line in ls_files_output.splitlines():
        mode = line.split(" ", 1)[0]
        if mode and mode not in _ALLOWED_MODES:
            problems.append(f"existing file has mode {mode}: {line.rsplit('\t', 1)[-1]}")
    return problems


@dataclass
class VerdictReport:
    ok: bool
    needs_human: list[int] = field(default_factory=list)
    fixed: list[int] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    summary: str = ""
    rows: list[dict[str, Any]] = field(default_factory=list)


def check_verdicts(raw: Any, finding_ids: list[int], patch: PatchReport) -> VerdictReport:
    """Every finding gets exactly one known verdict, consistent with the patch."""
    out = VerdictReport(ok=True)
    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
        out.problems.append("verdicts are missing or malformed")
        out.ok = False
        return out
    if secret_hits(json.dumps(raw)):
        out.problems.append("verdicts contain a credential-shaped value")
    summary = raw.get("summary")
    out.summary = summary[:4000] if isinstance(summary, str) else ""
    seen: dict[int, str] = {}
    for row in raw["findings"]:
        if not isinstance(row, dict):
            out.problems.append("a verdict row is not an object")
            continue
        cid, verdict, reason = row.get("comment_id"), row.get("verdict"), row.get("reason")
        if not isinstance(cid, int) or cid not in finding_ids:
            out.problems.append(f"verdict for unknown finding {cid!r}")
            continue
        if verdict not in VERDICTS:
            out.problems.append(f"finding {cid}: unknown verdict {verdict!r}")
            continue
        if cid in seen:
            out.problems.append(f"finding {cid}: more than one verdict")
            continue
        seen[cid] = str(verdict)
        out.rows.append({"comment_id": cid, "verdict": verdict, "reason": str(reason or "")[:2000]})
    missing = [i for i in finding_ids if i not in seen]
    if missing:
        out.problems.append(f"no verdict for finding(s) {missing}")
    out.needs_human = [i for i, v in seen.items() if v == "needs_human"]
    out.fixed = [i for i, v in seen.items() if v == "fixed"]
    if out.fixed and patch.empty:
        out.problems.append("findings marked fixed but the patch is empty")
    if not out.fixed and not patch.empty:
        out.problems.append("the patch changes code but no finding is marked fixed")
    out.ok = not out.problems
    return out
