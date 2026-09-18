"""Outer guard for live runs: capture, verify, and only then show.

    uv run python scripts/probe/guarded.py tls_check.py
    uv run python scripts/probe/guarded.py probe.py --smoke

The probe scripts already emit only status and shape metadata. This wrapper is
the second line: it runs the script in a child process, captures everything it
writes (stdout *and* stderr, so an unexpected traceback is covered too), runs
the same verifier the fixtures go through against the live connection values
and the generic patterns, and prints the output only if it is clean. Otherwise
it prints the categories and the line numbers, never the text.

Nothing is written to disk by this wrapper.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from probe_env import load_env
from sanitise import violations

HERE = Path(__file__).resolve().parent
ALLOWED = frozenset({"tls_check.py", "probe.py", "probe_env.py", "sanitise.py", "selftest.py"})


def main(argv: list[str]) -> int:
    # "tls_check.py" and "scripts/probe/tls_check.py" both name the same closed-set script;
    # whatever directory was typed, only the copy next to this file is ever run.
    script = Path(argv[0]).name if argv else ""
    if script not in ALLOWED:
        print("usage: guarded.py {" + ",".join(sorted(ALLOWED)) + "} [args...]")
        return 2
    literals = load_env(required=False).literals()
    proc = subprocess.run(  # noqa: S603 - fixed interpreter, script name from a closed set
        [sys.executable, str(HERE / script), *argv[1:]],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=HERE.parents[1],
        check=False,
    )
    output = proc.stdout + (("\n[stderr]\n" + proc.stderr) if proc.stderr.strip() else "")
    found = violations(output, literals)
    checked = (
        f"{len(output.splitlines())} line(s) checked against {len(literals)} connection value(s)"
    )
    if found:
        categories = sorted({category for _, category in found})
        lines = sorted({lineno for lineno, _ in found})
        print(f"OUTPUT WITHHELD: {len(found)} finding(s) on line(s) {lines[:20]}: {categories}")
        print(f"[guard] {checked}; child exit={proc.returncode}")
        return 3
    print(output.rstrip())
    print(f"[guard] clean: {checked} and the generic patterns; child exit={proc.returncode}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
