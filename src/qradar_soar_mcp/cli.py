"""``qradar-soar-mcp``: serve (default) or ``--check`` (P1-14; 08 §3).

Serving writes nothing to stdout — in stdio transport stdout *is* the MCP
channel. ``--check`` is an operator command and prints a JSON report to
stdout on purpose; it contains no secret. Approvals and audit verification
are separate entry points (``qradar-soar-approve``, ``qradar-soar-audit``).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from qradar_soar_mcp import __version__
from qradar_soar_mcp.logging import configure_logging
from qradar_soar_mcp.tools.runtime import Runtime

logger = logging.getLogger(__name__)

TRANSPORT_CHOICES = ("stdio", "streamable-http", "http")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qradar-soar-mcp",
        description="A security-first MCP server for IBM QRadar SOAR. Serves over stdio "
        "unless SOAR_MCP_TRANSPORT or --transport says otherwise.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--check",
        action="store_true",
        help="validate the configuration, reach SOAR via incidents/query_paged, print a "
        "JSON report and exit (0 ok, 1 unreachable/not configured, 2 refused config)",
    )
    p.add_argument(
        "--transport",
        choices=TRANSPORT_CHOICES,
        default=None,
        help="override SOAR_MCP_TRANSPORT",
    )
    return p


def _normalise_transport(value: str | None) -> str | None:
    return "streamable-http" if value == "http" else value


async def run_check(
    env: Mapping[str, str], *, http_transport: httpx.AsyncBaseTransport | None = None
) -> tuple[int, dict[str, Any]]:
    rt = Runtime.build(env, http_transport=http_transport)
    report: dict[str, Any] = rt.describe()
    code = 0
    if not rt.usable:
        report["ping"] = {"ok": False, "error": {"code": "not_configured"}}
        code = 2
    elif rt.client is None:
        report["ping"] = {
            "ok": False,
            "error": {"code": "not_configured", "message": "SOAR connection is not configured"},
        }
        code = 1
    else:
        try:
            report["ping"] = {"ok": True, **(await rt.client.ping())}
        except Exception as exc:
            to_dict = getattr(exc, "to_dict", None)
            report["ping"] = {
                "ok": False,
                "error": to_dict() if callable(to_dict) else {"code": "internal"},
            }
            code = 1
    await rt.aclose()
    return code, report


def cmd_check(env: Mapping[str, str]) -> int:
    import anyio

    code, report = anyio.run(run_check, env)
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    return code


def cmd_serve(env: Mapping[str, str], transport: str | None) -> int:
    rt = Runtime.build(env, transport=transport)
    if not rt.usable or rt.settings is None:
        sys.stderr.write(f"qradar-soar-mcp: refusing to start: {rt.config_error}\n")
        return 2
    # Re-arm logging with the configured level and every secret now known.
    configure_logging(rt.settings.log_level, rt.settings.secret_values())
    from qradar_soar_mcp.server import serve

    serve(rt)
    return 0


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = _parser().parse_args(argv)
    env = os.environ if env is None else env
    # Before anything else, so no library ever installs a stdout handler.
    configure_logging(env.get("SOAR_LOG_LEVEL") or "INFO")
    if args.check:
        return cmd_check(env)
    return cmd_serve(env, _normalise_transport(args.transport))
