"""P1-08: hash-chained append-only audit log, verifier CLI, fail-closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qradar_soar_mcp import cli_audit
from qradar_soar_mcp.security.audit import GENESIS, AuditError, AuditLog, new_request_id, verify
from tests.conftest import SENTINEL


def _redact(s: str) -> str:
    return s.replace(SENTINEL, "[REDACTED]")


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_records_are_chained_and_verify(tmp_path: Path):
    path = tmp_path / "state" / "audit.jsonl"
    log = AuditLog(path, server_version="0.2.0", redact=_redact)
    log.open()
    rid = new_request_id()
    log.append(
        "MUTATION_PENDING",
        tool="soar_update_incident",
        tier=2,
        capability="SOAR_ALLOW_INCIDENT_WRITES",
        decision="allow",
        target={"incident_id": 42},
        arguments_hash="h",
        pre_image={"vers": 3},
        transport="stdio",
        request_id=rid,
    )
    log.append(
        "MUTATION_COMMITTED",
        tool="soar_update_incident",
        tier=2,
        decision="allow",
        post_image={"vers": 4},
        soar_response={"success": True},
        duration_ms=12,
        request_id=rid,
    )
    records = _lines(path)
    assert [r["seq"] for r in records] == [1, 2]
    assert records[0]["prev_hash"] == GENESIS and records[1]["prev_hash"] == records[0]["hash"]
    assert records[0]["hash"].startswith("sha256:") and records[0]["server_version"] == "0.2.0"
    assert records[0]["ts"].endswith("Z") and records[0]["pre_image"] == {"vers": 3}
    assert records[1]["post_image"] == {"vers": 4} and records[1]["duration_ms"] == 12
    expected_keys = {
        "seq",
        "ts",
        "prev_hash",
        "hash",
        "event",
        "tool",
        "tier",
        "capability",
        "decision",
        "policy_rule",
        "approval_id",
        "approver",
        "target",
        "arguments_hash",
        "pre_image",
        "post_image",
        "soar_response",
        "duration_ms",
        "transport",
        "server_version",
        "request_id",
        "reason",
    }
    assert set(records[0]) == expected_keys
    assert verify(path) == verify(path) and verify(path).ok and verify(path).records == 2


def test_chain_continues_across_reopen(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("STARTUP", reason="one")
    log2 = AuditLog(path)
    log2.append("STARTUP", reason="two")
    records = _lines(path)
    assert records[1]["seq"] == 2 and records[1]["prev_hash"] == records[0]["hash"]
    assert verify(path).ok


@pytest.mark.parametrize("edit", ["reason", "tier", "seq", "prev_hash", "hash", "delete", "insert"])
def test_tampering_is_detected_and_first_link_named(tmp_path: Path, edit: str):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.append("DECISION_DENIED", tool="t", tier=3, decision="deny", reason=f"r{i}")
    records = _lines(path)
    target = records[2]
    if edit == "delete":
        del records[2]
    elif edit == "insert":
        records.insert(2, dict(target))
    elif edit == "hash":
        target["hash"] = "sha256:" + "f" * 64
    elif edit == "seq":
        target["seq"] = 99
    elif edit == "prev_hash":
        target["prev_hash"] = GENESIS
    elif edit == "tier":
        target["tier"] = 1
    else:
        target["reason"] = "edited"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    result = verify(path)
    assert not result.ok
    if edit == "insert":
        # A byte-identical duplicate is indistinguishable from an honest record; the
        # chain breaks at the very next link instead.
        assert result.first_broken_seq == 4 and result.records == 3
    else:
        assert result.first_broken_seq == 3 and result.records == 2
    assert result.reason


def test_verify_reports_garbage(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    assert verify(path).reason == "record is not valid JSON"
    path.write_text("[1]\n", encoding="utf-8")
    assert verify(path).reason == "record is not an object"
    assert verify(tmp_path / "missing.jsonl").ok


def test_secrets_redacted_before_hashing(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=_redact)
    log.append(
        "MUTATION_FAILED",
        tool="t",
        tier=1,
        decision="allow",
        target={"note": f"k {SENTINEL}"},
        pre_image=[SENTINEL],
        reason=f"e {SENTINEL}",
    )
    text = path.read_text(encoding="utf-8")
    assert SENTINEL not in text and text.count("[REDACTED]") == 3
    assert verify(path).ok  # the hash covers the redacted content


def test_values_are_clipped(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    deep: dict = {}
    cur = deep
    for _ in range(12):
        cur["n"] = {}
        cur = cur["n"]
    log.append(
        "MUTATION_PENDING",
        tool="t",
        tier=1,
        target={"big": "x" * 5000, "many": list(range(500)), "deep": deep, "obj": object()},
    )
    rec = _lines(path)[0]
    assert rec["target"]["big"].endswith("…[5000 chars]") and len(rec["target"]["many"]) == 200
    assert rec["target"]["obj"].startswith("<object object")
    assert "…" in json.dumps(rec["target"]["deep"], ensure_ascii=False)


def test_unknown_event_and_unwritable_path(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AuditError, match="unknown audit event"):
        log.append("SOMETHING")
    blocker = tmp_path / "file"
    blocker.write_text("")
    log2 = AuditLog(blocker / "audit.jsonl")
    with pytest.raises(AuditError) as info:
        log2.open()
    assert info.value.__cause__ is None
    log3 = AuditLog(blocker / "audit.jsonl")
    with pytest.raises(AuditError):
        log3.append("STARTUP")


def test_midsession_write_failure_raises_audit_error(tmp_path: Path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.open()

    def boom(self, *a, **k):
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(Path, "open", boom)
    with pytest.raises(AuditError, match="cannot write"):
        log.append("MUTATION_PENDING", tool="t", tier=1)


def test_open_is_idempotent_and_loads_tail(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("STARTUP")
    log.append("STARTUP")
    reopened = AuditLog(path)
    reopened.open()
    assert reopened.opened
    rec = reopened.append("STARTUP")
    assert rec["seq"] == 3 and verify(path).ok
    assert len(list(reopened.iter_records())) == 3


def test_request_ids_unique_hex():
    ids = {new_request_id() for _ in range(50)}
    assert len(ids) == 50 and all(len(i) == 32 for i in ids)


# ------------------------------------------------------------- CLI


def test_cli_verify_ok_and_broken(tmp_path: Path, capsys, monkeypatch):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append("STARTUP")
    assert cli_audit.main(["verify", str(path)]) == 0
    assert "chain intact" in capsys.readouterr().out
    monkeypatch.setenv("SOAR_AUDIT_LOG_PATH", str(path))
    assert cli_audit.main(["verify"]) == 0
    records = _lines(path)
    records[0]["reason"] = "edited"
    path.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")
    assert cli_audit.main(["verify", str(path)]) == 1
    assert "first bad link at seq 1" in capsys.readouterr().err
