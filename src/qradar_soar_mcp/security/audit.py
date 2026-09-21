"""Hash-chained, append-only audit log (P1-08; 02 §6).

One record per security decision and per mutation attempt. ``prev_hash`` →
``hash`` links each record to the previous one, so selective deletion or
edits are detectable by :func:`verify`. Pre-images come from the fetch
``apply_patch`` already performs; post-images from the response.

A record is redacted string by string, keys included, before it is hashed, so the hash
covers exactly the line on disk; a record that cannot be redacted without losing a field
is not written (:class:`AuditError`, 08 §27).

``SOAR_AUDIT_REQUIRED=true`` makes an unwritable log a startup failure; a
mid-session write failure raises :class:`AuditError`, and the chokepoint
fails the mutation closed. Audit content is never returned in tool output.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qradar_soar_mcp.redaction import KeyCollisionError, redact_strings
from qradar_soar_mcp.security.limits import iter_jsonl

GENESIS = "sha256:" + "0" * 64
_MAX_STRING = 2000
_MAX_DEPTH = 8
_MAX_ITEMS = 200

EVENTS = frozenset(
    {
        "STARTUP",
        "DECISION_DENIED",
        "APPROVAL_REQUESTED",
        "APPROVAL_CONSUMED",
        "MUTATION_PENDING",
        "MUTATION_COMMITTED",
        "MUTATION_FAILED",
        "BREAKER_TRIPPED",
    }
)


class AuditError(RuntimeError):
    """The audit record could not be written. Callers fail closed."""


def new_request_id() -> str:
    return uuid.uuid4().hex


def _clip(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return "…"
    if isinstance(value, str):
        return (
            value if len(value) <= _MAX_STRING else value[:_MAX_STRING] + f"…[{len(value)} chars]"
        )
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, Mapping):
        return {str(k): _clip(v, depth + 1) for k, v in list(value.items())[:_MAX_ITEMS]}
    if isinstance(value, list | tuple | set | frozenset):
        return [_clip(v, depth + 1) for v in list(value)[:_MAX_ITEMS]]
    return _clip(str(value), depth)


def _canonical(record: Mapping[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(record: Mapping[str, Any]) -> str:
    unhashed = {k: v for k, v in record.items() if k != "hash"}
    return "sha256:" + hashlib.sha256(_canonical(unhashed).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    records: int
    first_broken_seq: int | None = None
    reason: str | None = None


def verify(path: Path) -> VerifyResult:
    """Walk the chain; name the first broken link."""
    prev = GENESIS
    expected_seq = 1
    count = 0
    if not path.is_file():
        return VerifyResult(ok=True, records=0)
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return VerifyResult(False, count, expected_seq, "record is not valid JSON")
            if not isinstance(record, dict):
                return VerifyResult(False, count, expected_seq, "record is not an object")
            seq = record.get("seq")
            if seq != expected_seq:
                return VerifyResult(
                    False, count, expected_seq, f"expected seq {expected_seq}, found {seq!r}"
                )
            if record.get("prev_hash") != prev:
                return VerifyResult(
                    False, count, expected_seq, "prev_hash does not match the previous record"
                )
            if record.get("hash") != _digest(record):
                return VerifyResult(
                    False, count, expected_seq, "hash does not match the record content"
                )
            prev = str(record["hash"])
            expected_seq += 1
            count += 1
    return VerifyResult(ok=True, records=count)


class AuditLog:
    def __init__(
        self,
        path: Path,
        *,
        required: bool = True,
        server_version: str = "",
        redact: Callable[[str], str] = lambda s: s,
    ) -> None:
        self.path = path
        self.required = required
        self.server_version = server_version
        self._redact = redact
        self._seq = 0
        self._prev = GENESIS
        self._opened = False

    # ---------------------------------------------------------------- open
    def open(self) -> None:
        """Load the chain tail and prove the log is writable.

        Raises:
            AuditError: when the log cannot be written. With
                ``SOAR_AUDIT_REQUIRED=true`` the server refuses to start.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            last: dict[str, Any] | None = None
            for record in iter_jsonl(self.path):
                last = record
            if last is not None:
                seq = last.get("seq")
                self._seq = seq if isinstance(seq, int) else 0
                self._prev = str(last.get("hash") or GENESIS)
            with self.path.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise AuditError(
                f"audit log {self.path} is not writable ({type(exc).__name__})"
            ) from None
        self._opened = True

    @property
    def opened(self) -> bool:
        return self._opened

    # -------------------------------------------------------------- append
    def append(
        self,
        event: str,
        *,
        tool: str | None = None,
        tier: int | None = None,
        capability: str | None = None,
        decision: str | None = None,
        policy_rule: str | None = None,
        approval_id: str | None = None,
        approver: str | None = None,
        target: Mapping[str, Any] | None = None,
        arguments_hash: str | None = None,
        pre_image: Any = None,
        post_image: Any = None,
        soar_response: Any = None,
        duration_ms: int | None = None,
        transport: str | None = None,
        request_id: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        if event not in EVENTS:
            raise AuditError(f"unknown audit event {event!r}")
        if not self._opened:
            self.open()
        record: dict[str, Any] = {
            "seq": self._seq + 1,
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "prev_hash": self._prev,
            "event": event,
            "tool": tool,
            "tier": tier,
            "capability": capability,
            "decision": decision,
            "policy_rule": policy_rule,
            "approval_id": approval_id,
            "approver": approver,
            "target": _clip(target),
            "arguments_hash": arguments_hash,
            "pre_image": _clip(pre_image),
            "post_image": _clip(post_image),
            "soar_response": _clip(soar_response),
            "duration_ms": duration_ms,
            "transport": transport,
            "server_version": self.server_version,
            "request_id": request_id,
            "reason": _clip(reason),
        }
        # Redact before hashing so the hash covers exactly what is on disk. Each string of
        # the record, keys included, is redacted as the text it is (08 §27): whatever a
        # string holds, the record keeps its structure. Nothing is written, and the chain
        # does not advance, unless the whole record could be redacted, hashed and serialised.
        try:
            redacted: dict[str, Any] = redact_strings(record, self._redact, unique_keys=True)
            redacted["hash"] = _digest(redacted)
            line = _canonical(redacted)
        except KeyCollisionError:
            # Two fields under one key: one of them would be lost, so there is no record.
            raise AuditError(
                "audit record cannot be written: two keys are equal after redaction"
            ) from None
        except Exception as exc:
            # The type only: the message of the exception may quote the text it failed on.
            raise AuditError(
                f"audit record cannot be redacted and serialised: {type(exc).__name__}"
            ) from None
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise AuditError(f"cannot write audit log {self.path}: {type(exc).__name__}") from None
        self._seq = int(redacted["seq"])
        self._prev = str(redacted["hash"])
        return redacted

    def iter_records(self) -> Iterable[dict[str, Any]]:
        return iter_jsonl(self.path)
