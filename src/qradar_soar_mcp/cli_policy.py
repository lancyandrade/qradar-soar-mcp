"""``qradar-soar-policy scaffold`` — write a deny-everything action policy (P2-06; 08 §34).

The actions come from a catalog: a catalog JSON file given with ``--catalog`` (offline;
the schema of ``Catalog.to_json``), or else a catalog loaded from SOAR with the
connection in the environment, through the configured catalog backend: the same
read-only requests ``soar_refresh_catalog`` sends, and nothing else.

The output file is created exclusively (``O_CREAT | O_EXCL``): an existing file, or a
symlink at that path, is never written over, and the command fails instead. ``-``
writes to stdout. The text is fully built and checked before the file is created, so a
refused scaffold leaves nothing behind.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import httpx

from qradar_soar_mcp.catalog import Catalog, CatalogFormatError, build_backend
from qradar_soar_mcp.config import ConfigError, Settings
from qradar_soar_mcp.errors import SoarError
from qradar_soar_mcp.security.policy_scaffold import ScaffoldError, build_scaffold

PROG = "qradar-soar-policy"
MAX_CATALOG_BYTES = 50_000_000

EXIT_OK = 0
EXIT_FAILED = 1  # no catalog, no scaffold, or the output file exists
EXIT_CONFIG = 2  # refused configuration (live mode)


class _CommandError(Exception):
    def __init__(self, message: str, code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=PROG, description="Action policy tools.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser(
        "scaffold",
        help="write an action policy that denies every action in the catalog",
        description="Write an action policy with one tier-5 / deny entry per catalog "
        "action and a suggested tier in a comment, for a human to review. Never "
        "writes over an existing file.",
    )
    s.add_argument(
        "--output",
        "-o",
        required=True,
        help="the policy file to create (must not exist), or - for stdout",
    )
    s.add_argument(
        "--catalog",
        default=None,
        help="a catalog JSON file to read instead of loading the catalog from SOAR",
    )
    return p


def _catalog_from_file(path: Path) -> Catalog:
    try:
        if not path.is_file():
            raise _CommandError(f"{path}: catalog file does not exist")
        if path.stat().st_size > MAX_CATALOG_BYTES:
            raise _CommandError(f"{path}: catalog file is larger than {MAX_CATALOG_BYTES} bytes")
        data = path.read_bytes()
    except OSError as exc:
        problem = f"cannot read the catalog file ({type(exc).__name__})"
        raise _CommandError(f"{path}: {problem}") from None
    try:
        return Catalog.from_json(data)
    except CatalogFormatError as exc:
        raise _CommandError(f"{path}: {exc}") from None


async def load_live_catalog(
    env: Mapping[str, str], *, http_transport: httpx.AsyncBaseTransport | None = None
) -> Catalog:
    from qradar_soar_mcp.client.base import SoarClient

    try:
        settings = Settings.load(env)
    except ConfigError as exc:
        raise _CommandError(f"refused configuration: {exc}", EXIT_CONFIG) from None
    try:
        async with SoarClient(settings, transport=http_transport) as client:
            return await build_backend(settings.catalog_source, client).load()
    except SoarError as exc:
        raise _CommandError(f"cannot load the catalog from SOAR: {exc.safe_message}") from None


def _write_exclusive(path: Path, text: str) -> None:
    try:
        handle = path.open("x", encoding="utf-8", newline="\n")
    except FileExistsError:
        raise _CommandError(f"{path}: already exists; refusing to write over it") from None
    except OSError as exc:
        raise _CommandError(f"{path}: cannot create the file ({type(exc).__name__})") from None
    try:
        with handle:
            handle.write(text)
    except OSError as exc:
        # The file is ours (created exclusively above): remove the partial text.
        path.unlink(missing_ok=True)
        problem = f"cannot write the file ({type(exc).__name__}); nothing was left behind"
        raise _CommandError(f"{path}: {problem}") from None


def run_scaffold(
    output: str,
    catalog_path: str | None,
    env: Mapping[str, str],
    *,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """Build and write the scaffold; return the line to report. Raises :class:`_CommandError`."""
    target = None if output == "-" else Path(output)
    if target is not None and (target.exists() or target.is_symlink()):
        # Checked again, atomically, on create; this only saves a catalog load.
        raise _CommandError(f"{target}: already exists; refusing to write over it")
    if catalog_path is not None:
        catalog = _catalog_from_file(Path(catalog_path))
    else:
        import anyio

        catalog = anyio.run(lambda: load_live_catalog(env, http_transport=http_transport))
    try:
        result = build_scaffold(catalog)
    except ScaffoldError as exc:
        raise _CommandError(str(exc)) from None
    where = "stdout" if target is None else str(target)
    if target is None:
        try:
            sys.stdout.buffer.write(result.text.encode("utf-8"))
            sys.stdout.flush()
        except OSError as exc:
            raise _CommandError(f"cannot write to stdout ({type(exc).__name__})") from None
    else:
        _write_exclusive(target, result.text)
    return (
        f"wrote {result.entries} deny entries for {result.actions} actions to {where} "
        f"({result.functions} functions have no entry); every entry is tier 5 / deny "
        "until a human edits it"
    )


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    *,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> int:
    args = _parser().parse_args(argv)
    env = os.environ if env is None else env
    try:
        report = run_scaffold(args.output, args.catalog, env, http_transport=http_transport)
    except _CommandError as exc:
        sys.stderr.write(f"{PROG}: {exc}\n")
        return exc.code
    sys.stderr.write(f"{PROG}: {report}\n")
    return EXIT_OK
