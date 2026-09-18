"""``qradar-soar-audit verify [path]`` — walk the audit hash chain (P1-08)."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from qradar_soar_mcp.security.audit import verify


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qradar-soar-audit", description="Audit log tools.")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify the hash chain of an audit log")
    v.add_argument(
        "path",
        nargs="?",
        default=None,
        help="audit log path (default: $SOAR_AUDIT_LOG_PATH or ./audit.jsonl)",
    )
    args = parser.parse_args(argv)
    path = Path(args.path or os.environ.get("SOAR_AUDIT_LOG_PATH") or "audit.jsonl")
    result = verify(path)
    if result.ok:
        print(f"OK: {result.records} records, chain intact ({path})")
        return 0
    print(
        f"BROKEN: first bad link at seq {result.first_broken_seq}: {result.reason} "
        f"({result.records} records verified before it, {path})",
        file=sys.stderr,
    )
    return 1
