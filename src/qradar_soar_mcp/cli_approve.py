"""``qradar-soar-approve`` — the human side of the out-of-band broker (P1-10; 02 §4.2).

Runs in the approver's environment with the Ed25519 **private** key
(``SOAR_APPROVAL_PRIVATE_KEY_FILE``). The MCP server never reads that file.

    qradar-soar-approve keygen --private KEY --public PUB
    qradar-soar-approve list [--broker DIR]
    qradar-soar-approve APR-2026-0917-a1b2c3 [--broker DIR] [--key KEY] [--approver NAME]
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from qradar_soar_mcp.security.approvals import (
    ApprovalBroker,
    ApprovalError,
    generate_keypair,
    is_approval_id,
    load_private_key,
    sign_request,
)


def _render(request_plan: str, request: dict[str, object]) -> str:
    flags = f"Tier {request['tier']}" + ("  (destructive)" if request.get("destructive") else "")
    action = request.get("action") or {}
    action_name = action.get("name") if isinstance(action, dict) else None
    lines = [
        f"Reference: {request['approval_id']}",
        f"Tool:      {request['tool']}     {flags}",
    ]
    if action_name:
        lines.append(f"Action:    {action_name}")
    target = request.get("target") or {}
    if isinstance(target, dict) and target:
        lines.append("Target:    " + ", ".join(f"{k} {v}" for k, v in target.items()))
    lines.append(f"Requested: {request['requested_at']}   Expires: {request['expires_at']}")
    if request_plan:
        lines.append("")
        lines.append(request_plan)
    return "\n".join(lines)


def cmd_keygen(private: Path, public: Path) -> int:
    if private.exists() or public.exists():
        print("refusing to overwrite an existing key file", file=sys.stderr)
        return 1
    generate_keypair(private, public)
    print(f"private key: {private} (mode 0600; keep it in the approver's environment only)")
    print(f"public key:  {public} (give this one to the MCP server: SOAR_APPROVAL_PUBLIC_KEY_FILE)")
    return 0


def cmd_list(broker_dir: Path) -> int:
    if not broker_dir.is_dir():
        print(f"no broker directory at {broker_dir}")
        return 0
    found = 0
    for path in sorted(broker_dir.glob("APR-*.request.json")):
        approval_id = path.name.removesuffix(".request.json")
        state = "pending"
        for kind in ("consumed", "approved", "rejected"):
            if (broker_dir / f"{approval_id}.{kind}.json").is_file():
                state = kind
                break
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        tool = data.get("tool", "?")
        expires = data.get("expires_at", "?")
        print(f"{approval_id}  {state:9}  {tool}  expires {expires}")
        found += 1
    if not found:
        print("no approval requests")
    return 0


def cmd_approve(
    approval_id: str,
    *,
    broker_dir: Path,
    key_path: Path | None,
    approver: str,
    ttl_seconds: int,
    ask: Callable[[str], str],
    now: Callable[[], float] = time.time,
) -> int:
    if not is_approval_id(approval_id):
        print("that is not an approval reference (APR-YYYY-MMDD-xxxxxx)", file=sys.stderr)
        return 2
    if key_path is None:
        print("no private key: set SOAR_APPROVAL_PRIVATE_KEY_FILE or pass --key", file=sys.stderr)
        return 2
    broker = ApprovalBroker(broker_dir, public_key=None, ttl_seconds=ttl_seconds, now=now)
    try:
        request = broker.load_request(approval_id)
    except ApprovalError as exc:
        print(f"cannot read request: {exc}", file=sys.stderr)
        return 1
    if request is None:
        print(f"no request {approval_id} in {broker_dir}", file=sys.stderr)
        return 1
    status = broker.status(approval_id)
    if status["state"] != "pending":
        print(f"{approval_id} is {status['state']}; nothing to do", file=sys.stderr)
        return 1
    try:
        private = load_private_key(key_path)
    except ApprovalError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(_render(request.plan, request.to_dict()))
    print()
    typed = ask("Type the reference to approve, anything else to reject: ").strip()
    if typed != approval_id:
        broker_dir.mkdir(parents=True, exist_ok=True)
        (broker_dir / f"{approval_id}.rejected.json").write_text(
            json.dumps({"approval_id": approval_id, "approver": approver, "rejected_at": now()})
            + "\n",
            encoding="utf-8",
        )
        print(f"REJECTED {approval_id}")
        return 3
    approved = sign_request(
        request, private_key=private, approver=approver, now=now(), ttl_seconds=ttl_seconds
    )
    target = broker_dir / f"{approval_id}.approved.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(approved, indent=2, sort_keys=True) + "\n")
    print(f"APPROVED {approval_id} by {approver}; valid until {approved['expires_at']}")
    return 0


def main(argv: Sequence[str] | None = None, *, ask: Callable[[str], str] = input) -> int:
    env = os.environ
    parser = argparse.ArgumentParser(
        prog="qradar-soar-approve",
        description="Approve or reject a pending qradar-soar-mcp action (out of band).",
    )
    parser.add_argument(
        "--broker",
        type=Path,
        default=Path(env.get("SOAR_APPROVAL_BROKER_PATH") or "approvals"),
        help="broker directory (default: $SOAR_APPROVAL_BROKER_PATH or ./approvals)",
    )
    sub = parser.add_subparsers(dest="command")
    k = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    k.add_argument("--private", type=Path, required=True)
    k.add_argument("--public", type=Path, required=True)
    sub.add_parser("list", help="list requests in the broker")
    a = sub.add_parser("approve", help="approve a reference")
    a.add_argument("approval_id")
    a.add_argument(
        "--key",
        type=Path,
        default=None,
        help="private key (default: $SOAR_APPROVAL_PRIVATE_KEY_FILE)",
    )
    a.add_argument(
        "--approver",
        default=None,
        help="approver identity recorded in the audit (default: current user)",
    )
    a.add_argument(
        "--ttl",
        type=int,
        default=None,
        help="approval validity in seconds (default: $SOAR_APPROVAL_TTL_SECONDS or 900)",
    )

    # `qradar-soar-approve [--broker DIR] APR-...` is the documented short form.
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not any(token in {"keygen", "list", "approve"} for token in args_list):
        for index, token in enumerate(args_list):
            if is_approval_id(token):
                args_list.insert(index, "approve")
                break
    args = parser.parse_args(args_list)

    if args.command == "keygen":
        return cmd_keygen(args.private, args.public)
    if args.command == "list":
        return cmd_list(args.broker)
    if args.command == "approve":
        key = args.key or (
            Path(env["SOAR_APPROVAL_PRIVATE_KEY_FILE"])
            if env.get("SOAR_APPROVAL_PRIVATE_KEY_FILE")
            else None
        )
        ttl_raw = env.get("SOAR_APPROVAL_TTL_SECONDS", "")
        ttl = args.ttl or (int(ttl_raw) if ttl_raw.isdigit() else 900)
        approver = args.approver or getpass.getuser()
        return cmd_approve(
            args.approval_id,
            broker_dir=args.broker,
            key_path=key,
            approver=approver,
            ttl_seconds=ttl,
            ask=ask,
        )
    parser.print_help()
    return 2
