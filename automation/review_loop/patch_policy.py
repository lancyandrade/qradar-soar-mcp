"""Validation of the patch an automated fix produced, and of its verdicts.

The patch comes from a model that read untrusted review text, so it is
untrusted input. This module parses it strictly (a format it does not fully
understand is refused, never skipped) and applies the path and content rules.
``gitcheck.py`` then makes git itself confirm the same file list before and
after applying, so a patch that this parser and git read differently is
refused. All of it runs from the default branch, in the test job and again in
the push job.
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
ALLOWED_MODE = "100644"
_P = r"[A-Za-z0-9._/-]+"
_DIFF_HEADER = re.compile(rf"^diff --git a/({_P}) b/({_P})$")
_OLD_FILE = re.compile(rf"^--- (?:a/({_P})|(/dev/null))$")
_NEW_FILE = re.compile(rf"^\+\+\+ (?:b/({_P})|(/dev/null))$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_EXT = {
    "old mode": re.compile(r"^old mode (\d{6})$"),
    "new mode": re.compile(r"^new mode (\d{6})$"),
    "deleted file mode": re.compile(r"^deleted file mode (\d{6})$"),
    "new file mode": re.compile(r"^new file mode (\d{6})$"),
    "rename from": re.compile(rf"^rename from ({_P})$"),
    "rename to": re.compile(rf"^rename to ({_P})$"),
    "copy from": re.compile(rf"^copy from ({_P})$"),
    "copy to": re.compile(rf"^copy to ({_P})$"),
    "similarity index": re.compile(r"^similarity index \d{1,3}%$"),
    "dissimilarity index": re.compile(r"^dissimilarity index \d{1,3}%$"),
    "index": re.compile(r"^index [0-9a-f]{4,64}\.\.[0-9a-f]{4,64}(?: (\d{6}))?$"),
}
_NO_EOL = "\\ No newline at end of file"
_PATH_OK = re.compile(r"[A-Za-z0-9._/-]+")
_TEST_FILE = re.compile(r"^tests/(?:.+/)?test_[A-Za-z0-9_]+\.py$")
# C0 controls except tab and newline, DEL, C1 controls, and the Unicode
# characters used for "Trojan Source" and invisible-text tricks.
_BAD_RANGES = (
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),  # DEL and C1 controls
    (0x200B, 0x200F),  # zero-width and directional marks
    (0x2028, 0x202E),  # line/paragraph separators, bidi embeddings and overrides
    (0x2060, 0x2069),  # word joiner, invisible operators, bidi isolates
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
)
_BAD_CHARS = re.compile(
    "[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _BAD_RANGES) + "]"
)

VERDICTS = frozenset({"fixed", "not_a_bug", "already_fixed", "needs_human"})


class PatchFormatError(ValueError):
    """The patch is not in the exact git format this parser accepts."""


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    status: str = "modify"  # modify | add | delete | rename | copy
    old_mode: str | None = None
    new_mode: str | None = None
    index_mode: str | None = None
    binary: bool = False
    added: int = 0
    removed: int = 0

    @property
    def paths(self) -> set[str]:
        return {self.old_path, self.new_path}


def parse_patch(text: str) -> list[FileDiff]:
    """Parse ``git diff`` output strictly. Hunks are consumed by their counts,
    so a content line that looks like a header is never read as one."""
    if text == "":
        return []
    if not text.endswith("\n"):
        raise PatchFormatError("patch does not end with a newline")
    lines = text[:-1].split("\n")  # split on LF only, exactly like git
    files: list[FileDiff] = []
    i, n = 0, len(lines)
    while i < n:
        head = _DIFF_HEADER.match(lines[i])
        if not head:
            raise PatchFormatError(f"line {i + 1}: expected a 'diff --git a/... b/...' header")
        fd = FileDiff(head.group(1), head.group(2))
        i += 1
        while i < n and not lines[i].startswith(("--- ", "@@", "diff --git ")):
            line = lines[i]
            if line.startswith(("GIT binary patch", "Binary files ")):
                fd.binary = True
                i += 1
                while i < n and not lines[i].startswith("diff --git "):
                    i += 1
                break
            for name, rx in _EXT.items():
                m = rx.match(line)
                if m:
                    _extended(fd, name, m)
                    break
            else:
                raise PatchFormatError(f"line {i + 1}: unexpected header line")
            i += 1
        if fd.binary:
            files.append(fd)
            continue
        if fd.status in ("modify", "add", "delete") and fd.old_path != fd.new_path:
            raise PatchFormatError(f"{fd.new_path}: header names differ without a rename")
        if i < n and lines[i].startswith("@@"):
            raise PatchFormatError(f"line {i + 1}: hunk without ---/+++ file lines")
        if i < n and lines[i].startswith("--- "):
            i = _file_lines(fd, lines, i)
            if i >= n or not lines[i].startswith("@@"):
                raise PatchFormatError(f"{fd.new_path}: file lines without a hunk")
            while i < n and lines[i].startswith("@@"):
                i = _hunk(fd, lines, i)
        files.append(fd)
    return files


def _extended(fd: FileDiff, name: str, m: re.Match[str]) -> None:
    value = m.group(1) if m.groups() else None
    if name == "old mode":
        fd.old_mode = value
    elif name == "new mode":
        fd.new_mode = value
    elif name == "deleted file mode":
        fd.status, fd.old_mode = "delete", value
    elif name == "new file mode":
        fd.status, fd.new_mode = "add", value
    elif name in ("rename from", "rename to", "copy from", "copy to"):
        fd.status = name.split()[0]
        expected = fd.old_path if name.endswith("from") else fd.new_path
        if value != expected:
            raise PatchFormatError(f"{name} does not match the diff header")
    elif name == "index":
        fd.index_mode = value


def _file_lines(fd: FileDiff, lines: list[str], i: int) -> int:
    old = _OLD_FILE.match(lines[i])
    new = _NEW_FILE.match(lines[i + 1]) if i + 1 < len(lines) else None
    if not old or not new:
        raise PatchFormatError(f"line {i + 1}: malformed ---/+++ file lines")
    if (old.group(2) is not None) != (fd.status == "add"):
        raise PatchFormatError(f"{fd.new_path}: /dev/null source does not match the file status")
    if (new.group(2) is not None) != (fd.status == "delete"):
        raise PatchFormatError(f"{fd.new_path}: /dev/null target does not match the file status")
    if old.group(1) is not None and old.group(1) != fd.old_path:
        raise PatchFormatError(f"{fd.new_path}: '---' path differs from the diff header")
    if new.group(1) is not None and new.group(1) != fd.new_path:
        raise PatchFormatError(f"{fd.new_path}: '+++' path differs from the diff header")
    return i + 2


def _hunk(fd: FileDiff, lines: list[str], i: int) -> int:
    m = _HUNK.match(lines[i])
    if not m:
        raise PatchFormatError(f"line {i + 1}: malformed hunk header")
    old_left = int(m.group(2)) if m.group(2) is not None else 1
    new_left = int(m.group(4)) if m.group(4) is not None else 1
    if old_left + new_left == 0:
        raise PatchFormatError(f"line {i + 1}: empty hunk")
    i += 1
    while old_left or new_left:
        if i >= len(lines):
            raise PatchFormatError("patch ends inside a hunk")
        line = lines[i]
        tag = line[:1]
        if tag == " " and old_left and new_left:
            old_left, new_left = old_left - 1, new_left - 1
        elif tag == "-" and old_left:
            old_left -= 1
            fd.removed += 1
        elif tag == "+" and new_left:
            new_left -= 1
            fd.added += 1
        elif line == _NO_EOL:
            pass
        else:
            raise PatchFormatError(f"line {i + 1}: hunk line does not match the hunk counts")
        i += 1
    if i < len(lines) and lines[i] == _NO_EOL:
        i += 1
    return i


@dataclass
class PatchReport:
    ok: bool
    files: list[str] = field(default_factory=list)
    changed_lines: int = 0
    problems: list[str] = field(default_factory=list)
    touches_tests: bool = False
    diffs: list[FileDiff] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.files


def path_allowed(path: str) -> str | None:
    """None when ``path`` may be written by an automated fix, else the reason.

    Protected prefixes are matched case-insensitively, and components that
    Windows would alias (a trailing dot or space) are refused, so `.GITHUB/` or
    `security./` cannot reach a protected directory on a case-insensitive
    checkout. Paths are ASCII only: no Unicode look-alikes or normalisation
    differences between file systems.
    """
    parts = path.split("/")
    if not _PATH_OK.fullmatch(path) or path.startswith("/") or ".." in parts:
        return f"{path!r}: unusual path"
    if any(not p or p in (".", "..") or p.endswith((".", " ")) for p in parts):
        return f"{path!r}: unusual path component"
    if any(p.casefold() == ".git" for p in parts):
        return f"{path!r}: git metadata"
    if policy.path_matches(path, policy.FIX_FORBIDDEN_PATH_PREFIXES):
        return f"{path}: protected path"
    if policy.has_sensitive_name(path):
        return f"{path}: protected file name (at any depth)"
    if not any(path == p or path.startswith(p) for p in ALLOWED_PREFIXES):
        return f"{path}: outside the paths a fix may change"
    return None


def secret_hits(text: str) -> list[str]:
    """Names of credential patterns found in ``text`` (the values are never returned)."""
    return [p.pattern[:20] for p in policy.SECRET_PATTERNS if p.search(text)]


def decode_patch(data: bytes) -> tuple[str | None, list[str]]:
    """Decode the raw patch bytes; refuse anything but clean UTF-8 text."""
    if len(data) > policy.MAX_PATCH_BYTES:
        return None, [f"patch is {len(data)} bytes (limit {policy.MAX_PATCH_BYTES})"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, ["patch is not valid UTF-8"]
    if "\r" in text:
        return None, ["patch contains carriage returns"]
    return text, []


def check_patch(patch: bytes | str) -> PatchReport:
    report = PatchReport(ok=True)
    data = patch.encode("utf-8") if isinstance(patch, str) else patch
    text, problems = decode_patch(data)
    if text is None:
        report.problems = problems
        report.ok = False
        return report
    if _BAD_CHARS.search(text):
        report.problems.append("patch contains control or invisible Unicode characters")
    if secret_hits(text):
        report.problems.append("patch contains a credential-shaped value")
    try:
        diffs = parse_patch(text)
    except PatchFormatError as err:
        report.problems.append(f"malformed patch: {err}")
        report.ok = False
        return report
    report.diffs = diffs
    paths: list[str] = []
    seen_targets: set[str] = set()
    added_in_tests = 0
    for fd in diffs:
        for path in sorted(fd.paths):
            paths.append(path)
            if (why := path_allowed(path)) is not None:
                report.problems.append(why)
        if fd.new_path.casefold() in seen_targets:
            report.problems.append(f"{fd.new_path}: changed twice in one patch")
        seen_targets.add(fd.new_path.casefold())
        if fd.binary:
            report.problems.append(f"{fd.new_path}: binary changes are not allowed")
        if fd.status == "delete":
            report.problems.append(f"{fd.new_path}: an automated fix may not delete files")
        if fd.status in ("rename", "copy"):
            report.problems.append(f"{fd.new_path}: an automated fix may not {fd.status} files")
        for mode in (fd.old_mode, fd.new_mode, fd.index_mode):
            if mode is not None and mode != ALLOWED_MODE:
                report.problems.append(f"{fd.new_path}: file mode {mode} is not allowed")
        if fd.old_mode is not None and fd.new_mode is not None and fd.status == "modify":
            report.problems.append(f"{fd.new_path}: mode changes are not allowed")
        if fd.status == "modify" and not (fd.added or fd.removed):
            report.problems.append(f"{fd.new_path}: entry changes no content")
        report.changed_lines += fd.added + fd.removed
        if _TEST_FILE.match(fd.new_path):
            added_in_tests += fd.added
    report.files = sorted(set(paths))
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
        if mode and mode != ALLOWED_MODE:
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
