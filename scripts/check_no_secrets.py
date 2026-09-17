"""Fail if the tracked tree contains anything that looks like a real environment.

This is a public repository. Nothing captured from, or pointing at, a real
QRadar SOAR deployment may be committed: no private IP addresses, no internal
hostnames, no API keys, no bearer tokens, no certificates.

Run from the repository root:

    python scripts/check_no_secrets.py

Exit status is non-zero on any hit. Every tracked file is scanned, the design
baseline (docs/design/00- to 07-) included: being authoritative does not exempt
a document from topology detection. The allowances are narrow and deliberate:
the generic placeholder domains the documentation uses on purpose, deny-list
CIDR ranges, an explicit per-line marker for fake test values, and the
illustrative addresses listed in ``ALLOWED_EXAMPLES`` by file and literal value
(docs/design/08-GREENFIELD-AMENDMENTS.md §17).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Placeholders that documentation and fixtures are allowed to use.
ALLOWED_HOSTS = {
    "soar.example.internal",
    "soar.example.com",
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",  # noqa: S104 - documented as a bind-address example, never a default
}

# Illustrative addresses the design pack uses on purpose (owner decision, 08 §17).
# Keyed by file *and* literal value, so nothing else in that file is exempt.
ALLOWED_EXAMPLES: dict[str, frozenset[str]] = {
    # 06 P1-06 AC: "policy denying 10.0.0.0/8 blocks <this address>".
    "docs/design/06-ROADMAP-TICKETS.md": frozenset({"10.4.2.9"}),
}

PATTERNS: dict[str, re.Pattern[str]] = {
    "rfc1918 10/8": re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "rfc1918 172.16/12": re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    "rfc1918 192.168/16": re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    "private key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    "bearer token": re.compile(r"(?i)\bbearer\s+[a-z0-9._\-]{24,}"),
    "api key assignment": re.compile(
        r"(?i)\b(soar_api_key_secret|api_key_secret|api_secret|http_auth_token)\s*[=:]\s*['\"]?[a-z0-9._\-]{16,}"
    ),
    # Hostnames (at least two labels) on obviously-internal TLDs that are not the
    # documented placeholders. One label ("field.internal") is attribute access.
    "internal hostname": re.compile(
        r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(internal|corp|lan|local|intranet)\b"
    ),
}

# The sentinel the secret-leak tests inject; it must never match anything real.
SENTINEL = "SENTINEL-SECRET-DO-NOT-LEAK-7f3a"
# A line carrying this marker is a deliberate, obviously-fake example.
ALLOW_MARKER = "check_no_secrets:allow"
# CIDR ranges in the policy example/tests are *deny-lists*, not addresses.
CIDR_CONTEXT = re.compile(r"/(8|12|16|24)\b")


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return [p for p in out.decode().split("\0") if p]


def scan(root: Path, rel: str) -> list[str]:
    path = root / rel
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                token = match.group(0)
                if label == "internal hostname" and (
                    token in ALLOWED_HOSTS or token.endswith((".example.internal", ".example.com"))
                ):
                    continue  # RFC 2606-style placeholder domains used by docs and fixtures
                if label == "api key assignment" and SENTINEL in line:
                    continue
                if label.startswith("rfc1918") and CIDR_CONTEXT.search(
                    line[match.end() : match.end() + 4]
                ):
                    continue  # a deny-list range such as 10.0.0.0/8
                if token in ALLOWED_EXAMPLES.get(rel, frozenset()):
                    continue  # an owner-approved illustrative value, in that file only
                hits.append(f"{rel}:{lineno}: {label}: {token}")
    return hits


def collect_hits(root: Path, files: list[str]) -> list[str]:
    """Scan ``files`` under ``root``. No path is exempt but this script and images."""
    hits: list[str] = []
    for rel in files:
        if rel.endswith("check_no_secrets.py") or rel.endswith((".png", ".jpg", ".gif")):
            continue
        hits.extend(scan(root, rel))
    return hits


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    files = tracked_files(root)
    hits = collect_hits(root, files)
    if hits:
        sys.stderr.write("Possible real-environment data found:\n")
        for hit in hits:
            sys.stderr.write(f"  {hit}\n")
        return 1
    sys.stderr.write(f"check_no_secrets: clean ({len(files)} files, design baseline included)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
