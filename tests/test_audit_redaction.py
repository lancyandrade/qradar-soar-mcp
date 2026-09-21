"""Audit records are redacted string by string, never as serialised JSON (08 §27).

The audit log once redacted the serialised record as one string, as the pipeline's
output redactor did before PR #8. There a pattern can run past the end of a value into
the JSON around it. These tests use the server's real redactor (``logging.redact``),
because its patterns are what misbehaved, and text an attacker may control.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest

from qradar_soar_mcp import logging as soar_logging
from qradar_soar_mcp.logging import redact
from qradar_soar_mcp.security.audit import (
    GENESIS,
    AuditError,
    AuditLog,
    _canonical,
    _digest,
    verify,
)
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import Runtime, ToolResult, ToolSpec, run_pipeline, soar_tool
from tests.conftest import SENTINEL
from tests.fake_soar import FakeSoar
from tests.tool_harness import audit_records, build_runtime, make_local_registry

# A credential that JSON escaping changes: redacting serialised JSON never matched it.
QUOTED_SECRET = 'pw"with\\quote-and-backslash'

BASIC = "Basic " + base64.b64encode(b"id:synthetic-value").decode()

BEFORE, AFTER = "untouched before", "untouched after: value"

ADVERSARIAL = {
    "ends_with_the_keyword": "see the header authorization:",
    "ends_with_keyword_and_equals": "note authorization =",
    "keyword_then_more_lines": "authorization = cfg.value\nnext_line = 2",
    "keyword_then_crlf_lines": "x\r\nAuthorization: abc\r\nHost: soar.example.internal",
    "quoted": 'she wrote "authorization: abc" and "left", {"a": 1}',
    "ends_with_a_quote": 'authorization: "',
    "backslashes": "C:\\dir\\authorization=\\\\share\\x and \\n is no newline",
    "ends_with_a_backslash": "authorization:\\",
    "json_punctuation": 'authorization: x"},{"seq":99,"hash":"sha256:0"',
    "basic_header": f"{BASIC} and more text",
    "the_credential": f"key {SENTINEL} tail",
    "the_escaped_credential": f"x {QUOTED_SECRET} y",
}

# What each string is once redacted as the text it is. Written out, not computed, for the
# cases that went wrong: the line after the value and the text around it survive.
EXPECTED = {
    "ends_with_the_keyword": "see the header authorization:",
    "ends_with_keyword_and_equals": "note authorization =",
    "keyword_then_more_lines": "authorization = [REDACTED]\nnext_line = 2",
    "keyword_then_crlf_lines": "x\r\nAuthorization: [REDACTED]\r\nHost: soar.example.internal",
    "ends_with_a_quote": "authorization: [REDACTED]",
    "ends_with_a_backslash": "authorization:[REDACTED]",
    "basic_header": "Basic [REDACTED] and more text",
    "the_credential": "key [REDACTED] tail",
    "the_escaped_credential": "x [REDACTED] y",
}


@pytest.fixture(autouse=True)
def _known_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(soar_logging._FILTER, "_secrets", (QUOTED_SECRET, SENTINEL))


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _append_hostile(log: AuditLog, text: str) -> dict[str, Any]:
    return log.append(
        "MUTATION_COMMITTED",
        tool="soar_add_comment",
        tier=1,
        decision="ALLOW",
        target={"before": BEFORE, "hostile": text, "after": AFTER, "incident_id": 42},
        pre_image=[BEFORE, text, AFTER],
        post_image={"nested": [{"text": text, "n": 1.5, "flag": True, "none": None}, AFTER]},
        soar_response={"message": text},
        request_id="r1",
        reason=text,
    )


def _secret_free(text: str) -> bool:
    escaped = json.dumps(QUOTED_SECRET)[1:-1]
    return SENTINEL not in text and QUOTED_SECRET not in text and escaped not in text


# ------------------------------------------------------ structural integrity


def test_the_expected_table_is_the_redactor_applied_to_each_string_alone():
    for name, text in ADVERSARIAL.items():
        assert EXPECTED.get(name, redact(text)) == redact(text), name


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_adversarial_text_stays_inside_its_own_string(tmp_path: Path, name: str):
    text = ADVERSARIAL[name]
    expected = redact(text)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, server_version="0.0.0", redact=redact)
    log.append("STARTUP", reason="first")
    returned = _append_hostile(log, text)

    raw = path.read_text(encoding="utf-8").splitlines()
    assert len(raw) == 2  # one line per record: no string broke out of its line
    records = [json.loads(line) for line in raw]  # and every line is valid JSON
    record = records[1]
    assert record == returned
    assert record["seq"] == 2 and record["prev_hash"] == records[0]["hash"]
    # The hostile strings are redacted as the text they are ...
    assert record["target"]["hostile"] == expected
    assert record["pre_image"][1] == expected
    assert record["post_image"]["nested"][0]["text"] == expected
    assert record["soar_response"] == {"message": expected} and record["reason"] == expected
    # ... and nothing beside them was touched: no field, no adjacent key or value, no scalar.
    assert record["target"] == {
        "before": BEFORE,
        "hostile": expected,
        "after": AFTER,
        "incident_id": 42,
    }
    assert record["pre_image"] == [BEFORE, expected, AFTER]
    assert record["post_image"] == {
        "nested": [{"text": expected, "n": 1.5, "flag": True, "none": None}, AFTER]
    }
    assert record["event"] == "MUTATION_COMMITTED" and record["tool"] == "soar_add_comment"
    assert record["tier"] == 1 and record["decision"] == "ALLOW" and record["request_id"] == "r1"
    assert record["server_version"] == "0.0.0" and record["hash"].startswith("sha256:")
    assert set(record) == set(records[0])  # the schema is what it was
    assert _secret_free(path.read_text(encoding="utf-8"))
    assert verify(path).ok and verify(path).records == 2


def test_the_strings_that_used_to_refuse_the_record_are_now_recorded(tmp_path: Path):
    """``authorization:`` at the end of a value ate the closing quote of the JSON string."""
    for name in ("ends_with_the_keyword", "ends_with_keyword_and_equals"):
        text = ADVERSARIAL[name]
        with pytest.raises(ValueError):  # the former construct, kept here as the witness
            json.loads(redact(_canonical({"reason": text, "tool": "t"})))
        log = AuditLog(tmp_path / f"{name}.jsonl", redact=redact)
        assert log.append("MUTATION_PENDING", tool="t", tier=1, reason=text)["reason"] == text


def test_a_value_no_longer_consumes_the_line_after_it(tmp_path: Path):
    text = ADVERSARIAL["keyword_then_more_lines"]
    former = json.loads(redact(_canonical({"reason": text})))["reason"]
    assert former == "authorization = [REDACTED] = 2"  # the next line's name was eaten
    log = AuditLog(tmp_path / "audit.jsonl", redact=redact)
    record = log.append("MUTATION_PENDING", tool="t", tier=1, reason=text)
    assert record["reason"] == "authorization = [REDACTED]\nnext_line = 2"


# ------------------------------------------------------------ secret removal


def test_planted_secrets_are_in_neither_the_returned_record_nor_the_file(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=redact)
    returned = log.append(
        "MUTATION_FAILED",
        tool="t",
        tier=2,
        target={"note": f"k {SENTINEL}", "deep": {"list": [[f"{SENTINEL}"], {"x": QUOTED_SECRET}]}},
        pre_image=[SENTINEL, QUOTED_SECRET],
        soar_response={"headers": f"Authorization: Basic {SENTINEL}\nNext: kept"},
        approver=f"user {QUOTED_SECRET}",
        reason=f"e {SENTINEL}",
    )
    text = path.read_text(encoding="utf-8")
    assert _secret_free(text) and _secret_free(json.dumps(returned, ensure_ascii=False))
    assert _secret_free(repr(returned))
    assert returned["target"] == {
        "note": "k [REDACTED]",
        "deep": {"list": [["[REDACTED]"], {"x": "[REDACTED]"}]},
    }
    assert returned["pre_image"] == ["[REDACTED]", "[REDACTED]"]
    assert returned["soar_response"] == {
        "headers": "Authorization: [REDACTED] [REDACTED]\nNext: kept"
    }
    assert returned["approver"] == "user [REDACTED]" and returned["reason"] == "e [REDACTED]"
    assert verify(path).ok  # the hash covers the redacted record, which is the line on disk


def test_a_credential_that_json_escaping_changes_is_redacted(tmp_path: Path):
    """Inside serialised JSON the quote and the backslash are escaped, so the configured
    secret never matched there and the former construct wrote it to the log."""
    former = redact(_canonical({"reason": f"x {QUOTED_SECRET} y"}))
    assert json.loads(former)["reason"] == f"x {QUOTED_SECRET} y"
    path = tmp_path / "audit.jsonl"
    record = AuditLog(path, redact=redact).append("STARTUP", reason=f"x {QUOTED_SECRET} y")
    assert record["reason"] == "x [REDACTED] y" and _secret_free(path.read_text(encoding="utf-8"))


def test_a_key_that_holds_a_credential_is_redacted(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=redact)
    log.append(
        "MUTATION_COMMITTED",
        tool="t",
        tier=1,
        post_image={"props": {f"token {SENTINEL}": "v", "plain": {f"{QUOTED_SECRET}": [1, 2]}}},
    )
    text = path.read_text(encoding="utf-8")
    assert _secret_free(text)
    (record,) = _lines(path)  # still one valid JSON document
    assert record["post_image"] == {
        "props": {"token [REDACTED]": "v", "plain": {"[REDACTED]": [1, 2]}}
    }
    assert verify(path).ok


# ---------------------------------------------------------------- hash chain


def test_a_chain_of_adversarial_records_verifies_and_tampering_is_still_detected(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=redact)
    for name in sorted(ADVERSARIAL):
        _append_hostile(log, ADVERSARIAL[name])
    records = _lines(path)
    assert [r["seq"] for r in records] == list(range(1, len(ADVERSARIAL) + 1))
    assert records[0]["prev_hash"] == GENESIS
    for previous, record in pairwise(records):
        assert record["prev_hash"] == previous["hash"]
    for record in records:  # the hash is over the redacted record: exactly what is on disk
        assert record["hash"] == _digest(record)
    result = verify(path)
    assert result.ok and result.records == len(ADVERSARIAL)

    # A second process continues the chain from the redacted tail.
    AuditLog(path, redact=redact).append("STARTUP", reason=ADVERSARIAL["json_punctuation"])
    assert verify(path).ok and verify(path).records == len(ADVERSARIAL) + 1

    lines = path.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[3])
    edited["target"]["after"] = "edited"
    lines[3] = _canonical(edited)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    broken = verify(path)
    assert not broken.ok and broken.first_broken_seq == 4 and broken.records == 3


def test_the_line_on_disk_is_the_canonical_form_of_the_returned_record(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    returned = _append_hostile(AuditLog(path, redact=redact), ADVERSARIAL["the_credential"])
    assert path.read_text(encoding="utf-8") == _canonical(returned) + "\n"


# ---------------------------------------------------- backward compatibility


def _former_append(path: Path, seq: int, prev: str, **fields: Any) -> dict[str, Any]:
    """What ``append`` did before this change, for a record it could handle."""
    record = {"seq": seq, "ts": "2026-09-01T00:00:00.000Z", "prev_hash": prev, **fields}
    redacted: dict[str, Any] = json.loads(redact(_canonical(record)))
    redacted["hash"] = _digest(redacted)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(_canonical(redacted) + "\n")
    return redacted


def test_a_log_written_by_the_former_code_verifies_and_is_continued(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    first = _former_append(path, 1, GENESIS, event="STARTUP", reason=f"k {SENTINEL}")
    _former_append(path, 2, first["hash"], event="MUTATION_PENDING", target={"incident_id": 42})
    before = path.read_bytes()
    assert verify(path).ok and verify(path).records == 2
    log = AuditLog(path, redact=redact)
    record = log.append("MUTATION_COMMITTED", tool="t", tier=1, post_image={"vers": 4})
    assert record["seq"] == 3 and verify(path).ok and verify(path).records == 3
    assert path.read_bytes().startswith(before)  # nothing already written was rewritten


def test_an_ordinary_record_is_byte_for_byte_what_the_former_code_wrote(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, server_version="0.2.0", redact=redact)
    record = log.append(
        "MUTATION_COMMITTED",
        tool="soar_update_incident",
        tier=2,
        decision="ALLOW",
        target={"incident_id": 42, "note": f"k {SENTINEL}"},
        pre_image={"vers": 3, "ratio": 0.5, "name": "Ünïcode ✓", "tags": ["a", None, True]},
        duration_ms=12,
    )
    # The record as it was before redaction: what this process generated (seq, ts, chain
    # tail) from the result, and what the caller passed in, unredacted.
    unredacted = {k: v for k, v in record.items() if k != "hash"}
    unredacted["target"] = {"incident_id": 42, "note": f"k {SENTINEL}"}
    assert unredacted["target"] != record["target"]
    former = json.loads(redact(_canonical(unredacted)))
    former["hash"] = _digest(former)
    assert _canonical(former) + "\n" == path.read_text(encoding="utf-8")


# ------------------------------------------------------ fail closed: collision


def _state(log: AuditLog) -> tuple[int, str]:
    return log._seq, log._prev


@pytest.mark.parametrize(
    "field",
    [
        {"target": {f"k {SENTINEL}": "first", "k [REDACTED]": "second"}},
        {"post_image": {"rows": [{"deep": {SENTINEL: 1, QUOTED_SECRET: 2}}]}},
        # No configured secret is needed: the pattern alone makes two keys equal.
        {"post_image": {"authorization: first": 1, "authorization: second": 2}},
    ],
)
def test_a_key_collision_after_redaction_refuses_the_record(tmp_path: Path, field):
    """Two fields under one key: writing either alone would silently lose evidence."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=redact)
    log.append("STARTUP", reason="first")
    on_disk, state = path.read_bytes(), _state(log)
    with pytest.raises(AuditError) as info:
        log.append("MUTATION_PENDING", tool="t", tier=1, **field)
    assert "two keys are equal after redaction" in str(info.value)
    assert _secret_free(str(info.value)) and "first" not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__
    assert path.read_bytes() == on_disk  # no partial record
    assert _state(log) == state  # neither _seq nor _prev moved
    record = log.append("MUTATION_PENDING", tool="t", tier=1, target={"incident_id": 42})
    assert record["seq"] == 2 and verify(path).ok and verify(path).records == 2


# ---------------------------------------- fail closed: redaction or encoding


def test_a_redactor_that_raises_becomes_an_audit_error_without_the_value(tmp_path: Path):
    def exploding(text: str) -> str:
        if SENTINEL in text:
            raise RuntimeError(f"cannot redact {text!r}")
        return text

    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=exploding)
    log.append("STARTUP")
    on_disk, state = path.read_bytes(), _state(log)
    with pytest.raises(AuditError) as info:
        log.append("MUTATION_PENDING", tool="t", tier=1, reason=f"e {SENTINEL}")
    assert str(info.value) == "audit record cannot be redacted and serialised: RuntimeError"
    assert info.value.__cause__ is None and info.value.__suppress_context__
    assert path.read_bytes() == on_disk and _state(log) == state
    assert log.append("STARTUP")["seq"] == 2 and verify(path).ok


def test_a_redactor_that_returns_no_string_refuses_the_record(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=lambda text: None)  # type: ignore[arg-type, return-value]
    with pytest.raises(AuditError, match="TypeError"):
        log.append("STARTUP")
    assert path.read_bytes() == b"" and _state(log) == (0, GENESIS)


def test_text_that_cannot_be_encoded_is_an_audit_error_not_a_crash(tmp_path: Path):
    """A lone surrogate parses from JSON but has no UTF-8 form; it used to escape as
    ``UnicodeEncodeError``, which no caller of ``append`` handles."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=redact)
    log.append("STARTUP")
    on_disk, state = path.read_bytes(), _state(log)
    with pytest.raises(AuditError, match="UnicodeEncodeError"):
        log.append("MUTATION_COMMITTED", tool="t", tier=1, post_image={"name": "\ud800"})
    assert path.read_bytes() == on_disk and _state(log) == state


# ------------------------------------------------- fail closed: write failure


@pytest.mark.parametrize("failing", ["open", "fsync"])
def test_the_chain_advances_only_after_the_record_is_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing: str
):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, redact=redact)
    log.append("STARTUP")
    state = _state(log)

    def boom(*a: Any, **k: Any) -> Any:
        raise OSError(f"disk failure near {SENTINEL}")

    with monkeypatch.context() as patch:
        if failing == "open":
            patch.setattr(Path, "open", boom)
        else:
            patch.setattr(os, "fsync", boom)
        with pytest.raises(AuditError, match="cannot write") as info:
            _append_hostile(log, ADVERSARIAL["the_credential"])
    assert _secret_free(str(info.value)) and info.value.__cause__ is None
    assert _state(log) == state


# ------------------------------------------------------------ the chokepoint


def _labelled_registry() -> dict[str, ToolSpec]:
    """A Tier-1 tool whose audited target carries a caller-supplied mapping."""
    reg: dict[str, ToolSpec] = {}

    def describe(args: Any, policy: Any) -> dict[str, Any]:
        target = {"incident_id": args.get("incident_id"), "labels": args.get("labels")}
        return {"target": target, "plan": "comment"}

    @soar_tool(
        name="soar_t_labelled",
        tier=Tier.DOCUMENTATION,
        capability="SOAR_ALLOW_COMMENTS",
        describe=describe,
        registry=reg,
    )
    async def t_labelled(rt: Runtime, incident_id: int, labels: dict[str, Any]) -> ToolResult:
        """add a comment"""
        created = await rt.require_client().comments.add(incident_id, "hi")
        return ToolResult(data={"comment_id": created["id"]}, target={"incident_id": incident_id})

    return reg


async def test_a_pending_record_that_cannot_be_written_still_stops_the_mutation(
    fake: FakeSoar, tmp_path: Path, caplog
):
    """The correction makes valid records robust; it does not let a mutation through
    when its required PENDING record is refused."""
    rt = build_runtime(fake, tmp_path, SOAR_ALLOW_COMMENTS="true")
    spec = _labelled_registry()["soar_t_labelled"]
    colliding = {f"k {SENTINEL}": 1, "k [REDACTED]": 2}
    with caplog.at_level(logging.DEBUG):
        out = await run_pipeline(spec, rt, {"incident_id": 42, "labels": colliding})
    assert out["ok"] is False and out["error"]["code"] == "DENY_AUDIT"
    assert fake.mutating_requests == []  # nothing was sent to SOAR
    assert audit_records(tmp_path) == []  # and no partial record exists
    assert _secret_free(json.dumps(out)) and _secret_free(caplog.text)
    assert "refusing mutation" in caplog.text

    # The same tool with a representable target goes through, PENDING first.
    out = await run_pipeline(spec, rt, {"incident_id": 42, "labels": {f"k {SENTINEL}": 1}})
    assert out["ok"] is True and len(fake.mutating_requests) == 1
    records = audit_records(tmp_path)
    assert [r["event"] for r in records] == ["MUTATION_PENDING", "MUTATION_COMMITTED"]
    assert records[0]["target"]["labels"] == {"k [REDACTED]": 1}
    assert verify(tmp_path / "state" / "audit.jsonl").ok
    await rt.aclose()


async def test_a_committed_mutation_with_adversarial_text_gets_its_committed_record(
    fake: FakeSoar, tmp_path: Path, caplog
):
    """Before, SOAR echoing such text in the post-image lost the COMMITTED record: that
    write is best effort, so the mutation had happened and only an error was logged."""
    rt = build_runtime(fake, tmp_path, SOAR_ALLOW_COMMENTS="true")
    reg = make_local_registry()
    text = "please check the header authorization:"
    with caplog.at_level(logging.ERROR):
        out = await run_pipeline(reg["soar_t_comment"], rt, {"incident_id": 42, "text": text})
    assert out["ok"] is True and len(fake.mutating_requests) == 1
    assert "audit write failed" not in caplog.text
    pending, committed = audit_records(tmp_path)
    assert (pending["event"], committed["event"]) == ("MUTATION_PENDING", "MUTATION_COMMITTED")
    assert pending["seq"] == 1 and committed["prev_hash"] == pending["hash"]
    assert text in json.dumps(committed["post_image"])
    assert verify(tmp_path / "state" / "audit.jsonl").ok
    await rt.aclose()
