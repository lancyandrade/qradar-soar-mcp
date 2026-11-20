"""T3 golden-file harness (LAB-03 §4 to §7; PILOT, scope pending owner decision D22).

A golden test renders a deterministic output to canonical JSON and compares it byte for
byte with a committed expected file under ``tests/golden/<group>/<case>.json``.

Rules (LAB-03 §6), each tested in ``tests/test_golden.py``:

- any difference fails, with a bounded unified diff and the expected file's path;
- a normal run never writes an expected file; regeneration needs ``--golden-update``,
  which CI never passes (asserted);
- a missing expected file fails (never "created on first run");
- an expected file no test declares fails (orphan check, ``orphans``);
- an output or expected file holding the suite's sentinel secret or a private address
  fails, whatever the comparison says.

This module reads no ``SOAR_*`` variable and opens no socket.
"""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any

from tests.conftest import SENTINEL

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
UPDATE_OPTION = "--golden-update"
MAX_DIFF_LINES = 60
# RFC 1918 and link-local ranges; a golden file is synthetic and names none of them.
PRIVATE_ADDRESS = re.compile(
    r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|169\.254)\.\d{1,3}\.\d{1,3}\b"
)


class GoldenMismatchError(AssertionError):
    """The output differs from, or cannot be compared with, its expected file."""


def canonical(data: Any) -> str:
    """Canonical text: sorted keys, two-space indent, UTF-8 as is, ``\\n``, one final newline."""
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def unsafe_content(text: str) -> str | None:
    """Why ``text`` may not be a golden output, or None. Names the problem, never the value."""
    if SENTINEL in text:
        return "it contains the suite's sentinel secret"
    if PRIVATE_ADDRESS.search(text):
        return "it contains a private or link-local IPv4 address"
    return None


def check(case: str, data: Any, *, update: bool = False, root: Path = GOLDEN_DIR) -> Path:
    """Compare ``data`` with ``root/<case>.json``; with ``update``, write it instead.

    Raises:
        GoldenMismatchError: on unsafe content, a missing file (without ``update``) or any
            byte difference.
    """
    if not re.fullmatch(r"[a-z0-9_]+/[a-z0-9_]+", case):
        raise ValueError(f"golden case {case!r} must be '<group>/<case>' in [a-z0-9_]")
    path = root / f"{case}.json"
    actual = canonical(data)
    problem = unsafe_content(actual)
    if problem:
        raise GoldenMismatchError(f"{case}: refused as a golden output because {problem}")
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(actual.encode("utf-8"))
        return path
    if not path.is_file():
        raise GoldenMismatchError(
            f"{case}: expected file {path.relative_to(root.parent)} is missing; "
            f"generate it with `uv run pytest -m golden {UPDATE_OPTION}` and review it"
        )
    expected = path.read_bytes().decode("utf-8")
    problem = unsafe_content(expected)
    if problem:
        raise GoldenMismatchError(f"{case}: the expected file is refused because {problem}")
    if expected != actual:
        diff = list(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                fromfile=f"expected/{case}.json",
                tofile=f"actual/{case}.json",
            )
        )
        shown = "".join(diff[:MAX_DIFF_LINES])
        more = (
            f"\n... {len(diff) - MAX_DIFF_LINES} more diff lines"
            if len(diff) > MAX_DIFF_LINES
            else ""
        )
        raise GoldenMismatchError(f"{case}: output differs from {path.name}\n{shown}{more}")
    return path


def orphans(declared: set[str], root: Path = GOLDEN_DIR) -> list[str]:
    """Expected files under ``root`` that no golden test declares, as ``<group>/<case>``."""
    found = {p.relative_to(root).with_suffix("").as_posix() for p in root.rglob("*.json")}
    return sorted(found - declared)
