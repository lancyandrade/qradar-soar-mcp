"""Out-of-band approval broker (P1-10; 02 §4; 08 §5).

Flow:

1. A tool call reaches a ``require_approval`` decision. The server writes
   ``{approval_id}.request.json`` to ``SOAR_APPROVAL_BROKER_PATH`` with the
   tool, tier, resolved action, target, the full rendered plan, the argument
   hash and an expiry, and returns the reference to the model.
2. A human runs ``qradar-soar-approve <approval_id>`` in *their* environment.
   The CLI prints the plan, requires the reference typed back, and writes
   ``{approval_id}.approved.json`` signed with the **Ed25519 private key** only
   that environment holds.
3. The retried tool call (or ``soar_check_approval``) verifies the signature
   with the **public key** (``SOAR_APPROVAL_PUBLIC_KEY_FILE``), the argument
   hash, and the TTL, then consumes the approval **atomically** by renaming it
   to ``{approval_id}.consumed.json``. A replay finds nothing to rename.

The server never reads a private key: it can verify but cannot forge (08 §5).

``in_band`` mode (lab only) hands the model a token to echo back. That
prevents accidents; it is **not** human approval, and every response says so.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from qradar_soar_mcp.config import Settings

APPROVAL_ARG = "approval_id"
IN_BAND_DISCLAIMER = (
    "IN-BAND CONFIRMATION IS NOT HUMAN APPROVAL. This token came from the server and is "
    "being echoed by the model; it prevents accidents, not misuse. SOAR_APPROVAL_MODE=in_band "
    "is for labs only (docs/design/02-SECURITY-MODEL.md §4.1)."
)
_SIGNED_FIELDS = ("approval_id", "arguments_hash", "approver", "approved_at", "expires_at")
_ID_ALPHABET = "0123456789abcdef"


class ApprovalError(ValueError):
    """A broker file is malformed or a key cannot be loaded."""


# ------------------------------------------------------------- helpers
def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _from_iso(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def canonical_args_hash(tool: str, args: Mapping[str, Any]) -> str:
    """``sha256:<hex>`` over the tool name and its arguments, minus the approval id."""
    clean = {k: v for k, v in args.items() if k != APPROVAL_ARG}
    canonical = json.dumps(
        {"tool": tool, "args": clean}, sort_keys=True, separators=(",", ":"), default=str
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def new_approval_id(now: float) -> str:
    day = datetime.fromtimestamp(now, UTC)
    suffix = "".join(secrets.choice(_ID_ALPHABET) for _ in range(6))
    return f"APR-{day:%Y}-{day:%m%d}-{suffix}"


def is_approval_id(value: str) -> bool:
    parts = value.split("-")
    return (
        len(parts) == 4
        and parts[0] == "APR"
        and parts[1].isdigit()
        and len(parts[1]) == 4
        and parts[2].isdigit()
        and len(parts[2]) == 4
        and 4 <= len(parts[3]) <= 8
        and all(c in _ID_ALPHABET for c in parts[3])
    )


def _signing_payload(fields: Mapping[str, Any]) -> bytes:
    payload = {k: fields[k] for k in _SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------- keys
def generate_keypair(private_path: Path, public_path: Path) -> None:
    """Write a new Ed25519 keypair as PEM. The private key is mode 0600."""
    private = ed25519.Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    public_path.write_bytes(public_pem)


def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ApprovalError(
            f"cannot load approval public key {path}: {type(exc).__name__}"
        ) from None
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ApprovalError(f"{path} is not an Ed25519 public key")
    return key


def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ApprovalError(
            f"cannot load approval private key {path}: {type(exc).__name__}"
        ) from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ApprovalError(f"{path} is not an Ed25519 private key")
    return key


# ------------------------------------------------------------- records
@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    tool: str
    tier: int
    capability: str | None
    action: dict[str, Any] | None
    target: dict[str, Any]
    plan: str
    arguments_hash: str
    requested_at: str
    expires_at: str
    transport: str
    destructive: bool
    policy_rule: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalRequest:
        try:
            return cls(
                approval_id=str(data["approval_id"]),
                tool=str(data["tool"]),
                tier=int(data["tier"]),
                capability=data.get("capability"),
                action=data.get("action"),
                target=dict(data.get("target") or {}),
                plan=str(data.get("plan") or ""),
                arguments_hash=str(data["arguments_hash"]),
                requested_at=str(data["requested_at"]),
                expires_at=str(data["expires_at"]),
                transport=str(data.get("transport") or "stdio"),
                destructive=bool(data.get("destructive", False)),
                policy_rule=data.get("policy_rule"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalError(f"request file is malformed ({type(exc).__name__})") from None


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    ok: bool
    state: str  # approved | pending | consumed | rejected | expired | unknown | invalid
    reason: str
    approval_id: str | None = None
    approver: str | None = None


# --------------------------------------------------------------- broker
class ApprovalBroker:
    def __init__(
        self,
        broker_path: Path,
        *,
        public_key: ed25519.Ed25519PublicKey | None,
        ttl_seconds: int,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.path = broker_path
        self._public = public_key
        self.ttl = int(ttl_seconds)
        self._now = now
        self._in_band: dict[str, tuple[str, str, float]] = {}  # token -> (tool, hash, exp)
        self._lock = threading.Lock()

    @classmethod
    def from_settings(
        cls, settings: Settings, *, now: Callable[[], float] = time.time
    ) -> ApprovalBroker:
        public = None
        if settings.approval_public_key_file is not None:
            public = load_public_key(settings.approval_public_key_file)
        return cls(
            settings.approval_broker_path,
            public_key=public,
            ttl_seconds=settings.approval_ttl_seconds,
            now=now,
        )

    @property
    def can_verify(self) -> bool:
        return self._public is not None

    # ------------------------------------------------------------ files
    def _file(self, approval_id: str, kind: str) -> Path:
        if not is_approval_id(approval_id):
            raise ApprovalError("approval id is malformed")
        return self.path / f"{approval_id}.{kind}.json"

    @staticmethod
    def _write_json(path: Path, data: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(data, indent=2, sort_keys=True, default=str)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ApprovalError(f"{path.name} is unreadable ({type(exc).__name__})") from None
        if not isinstance(data, dict):
            raise ApprovalError(f"{path.name} is not an object")
        return data

    # ---------------------------------------------------------- request
    def request(
        self,
        *,
        tool: str,
        tier: int,
        capability: str | None,
        args: Mapping[str, Any],
        target: Mapping[str, Any],
        plan: str,
        action: Mapping[str, Any] | None = None,
        transport: str = "stdio",
        destructive: bool = False,
        policy_rule: str | None = None,
    ) -> ApprovalRequest:
        now = self._now()
        request = ApprovalRequest(
            approval_id=new_approval_id(now),
            tool=tool,
            tier=int(tier),
            capability=capability,
            action=dict(action) if action else None,
            target=dict(target),
            plan=plan,
            arguments_hash=canonical_args_hash(tool, args),
            requested_at=_iso(now),
            expires_at=_iso(now + self.ttl),
            transport=transport,
            destructive=destructive,
            policy_rule=policy_rule,
        )
        self._write_json(self._file(request.approval_id, "request"), request.to_dict())
        return request

    def load_request(self, approval_id: str) -> ApprovalRequest | None:
        path = self._file(approval_id, "request")
        if not path.is_file():
            return None
        return ApprovalRequest.from_dict(self._read_json(path))

    # ----------------------------------------------------------- status
    def status(self, approval_id: str) -> dict[str, Any]:
        """What ``soar_check_approval`` returns. Never includes the signature."""
        if not is_approval_id(approval_id):
            return {"approval_id": approval_id, "state": "invalid"}
        request = self.load_request(approval_id)
        if request is None:
            return {"approval_id": approval_id, "state": "unknown"}
        state = "pending"
        approver = None
        for kind in ("consumed", "approved", "rejected"):
            path = self._file(approval_id, kind)
            if path.is_file():
                state = kind
                if kind != "rejected":
                    with_data = self._read_json(path)
                    approver = with_data.get("approver")
                break
        if state == "pending" and self._now() > _from_iso(request.expires_at):
            state = "expired"
        return {
            "approval_id": approval_id,
            "state": state,
            "tool": request.tool,
            "tier": request.tier,
            "plan": request.plan,
            "requested_at": request.requested_at,
            "expires_at": request.expires_at,
            "approver": approver,
        }

    # ------------------------------------------------------ verify+consume
    def verify_and_consume(
        self, approval_id: str, *, tool: str, args: Mapping[str, Any]
    ) -> ApprovalOutcome:
        """Signature → binding → TTL → atomic consumption. Exactly once."""
        if not is_approval_id(approval_id):
            return ApprovalOutcome(False, "invalid", "approval id is malformed")
        try:
            request = self.load_request(approval_id)
        except ApprovalError as exc:
            return ApprovalOutcome(False, "invalid", str(exc), approval_id)
        if request is None:
            return ApprovalOutcome(
                False, "unknown", f"no request {approval_id} in the broker", approval_id
            )
        if request.tool != tool:
            return ApprovalOutcome(
                False,
                "invalid",
                f"{approval_id} was requested for {request.tool}, not {tool}",
                approval_id,
            )
        if request.arguments_hash != canonical_args_hash(tool, args):
            return ApprovalOutcome(
                False,
                "invalid",
                f"{approval_id} was requested for different arguments; repeat the identical call",
                approval_id,
            )
        now = self._now()
        if now > _from_iso(request.expires_at):
            return ApprovalOutcome(
                False, "expired", f"{approval_id} expired at {request.expires_at}", approval_id
            )

        approved_path = self._file(approval_id, "approved")
        if not approved_path.is_file():
            if self._file(approval_id, "consumed").is_file():
                return ApprovalOutcome(
                    False, "consumed", f"{approval_id} was already used", approval_id
                )
            if self._file(approval_id, "rejected").is_file():
                return ApprovalOutcome(
                    False, "rejected", f"{approval_id} was rejected by the approver", approval_id
                )
            return ApprovalOutcome(
                False,
                "pending",
                f"{approval_id} is awaiting a human; do not retry, poll soar_check_approval",
                approval_id,
            )

        if self._public is None:
            return ApprovalOutcome(
                False,
                "invalid",
                "SOAR_APPROVAL_PUBLIC_KEY_FILE is not configured; no approval can be verified",
                approval_id,
            )
        try:
            approved = self._read_json(approved_path)
            fields = {k: approved[k] for k in _SIGNED_FIELDS}
            signature = base64.b64decode(str(approved["signature"]), validate=True)
            self._public.verify(signature, _signing_payload(fields))
        except (ApprovalError, KeyError, TypeError, ValueError):
            return ApprovalOutcome(
                False, "invalid", f"{approval_id}.approved.json is malformed", approval_id
            )
        except InvalidSignature:
            return ApprovalOutcome(
                False, "invalid", f"{approval_id} carries an invalid signature", approval_id
            )
        if (
            fields["approval_id"] != approval_id
            or fields["arguments_hash"] != request.arguments_hash
        ):
            return ApprovalOutcome(
                False, "invalid", f"{approval_id} approval does not match the request", approval_id
            )
        try:
            if now > _from_iso(str(fields["expires_at"])):
                return ApprovalOutcome(
                    False, "expired", f"{approval_id} approval expired", approval_id
                )
        except ValueError:
            return ApprovalOutcome(
                False, "invalid", f"{approval_id} approval has a bad expiry", approval_id
            )

        # Atomic single use: the first rename wins; a replay finds nothing to rename.
        try:
            approved_path.replace(self._file(approval_id, "consumed"))
        except OSError:
            return ApprovalOutcome(
                False, "consumed", f"{approval_id} was already used", approval_id
            )
        return ApprovalOutcome(True, "approved", "approved", approval_id, str(fields["approver"]))

    # ---------------------------------------------------------- in-band
    def issue_in_band_token(self, tool: str, args: Mapping[str, Any]) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._in_band[token] = (tool, canonical_args_hash(tool, args), self._now() + self.ttl)
        return token

    def consume_in_band_token(
        self, token: str, tool: str, args: Mapping[str, Any]
    ) -> ApprovalOutcome:
        with self._lock:
            entry = self._in_band.pop(token, None)
        if entry is None:
            return ApprovalOutcome(False, "invalid", "unknown or already-used confirmation token")
        t_tool, t_hash, exp = entry
        if self._now() > exp:
            return ApprovalOutcome(False, "expired", "confirmation token expired")
        if t_tool != tool or t_hash != canonical_args_hash(tool, args):
            return ApprovalOutcome(
                False, "invalid", "confirmation token was issued for a different call"
            )
        return ApprovalOutcome(True, "approved", IN_BAND_DISCLAIMER, approver="in_band")


# ----------------------------------------------------------- signing (CLI side)
def sign_request(
    request: ApprovalRequest,
    *,
    private_key: ed25519.Ed25519PrivateKey,
    approver: str,
    now: float,
    ttl_seconds: int,
) -> dict[str, Any]:
    """Build the ``approved.json`` content. Used by ``qradar-soar-approve`` only."""
    fields = {
        "approval_id": request.approval_id,
        "arguments_hash": request.arguments_hash,
        "approver": approver,
        "approved_at": _iso(now),
        "expires_at": _iso(min(now + ttl_seconds, _from_iso(request.expires_at))),
    }
    signature = private_key.sign(_signing_payload(fields))
    return {**fields, "signature": base64.b64encode(signature).decode("ascii")}
