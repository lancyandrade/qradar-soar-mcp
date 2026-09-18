"""P1-10: Ed25519 out-of-band broker, the approve CLI, in-band tokens (02 §4; 08 §5)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from qradar_soar_mcp import cli_approve
from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.security.approvals import (
    IN_BAND_DISCLAIMER,
    ApprovalBroker,
    ApprovalError,
    ApprovalRequest,
    canonical_args_hash,
    generate_keypair,
    is_approval_id,
    load_private_key,
    load_public_key,
    new_approval_id,
    sign_request,
)

TOOL = "soar_invoke_action"
ARGS = {"incident_id": 42, "action_id": 47, "approval_id": None}


class Clock:
    def __init__(self, t: float = 1_760_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private, public = tmp_path / "keys" / "approval.key", tmp_path / "keys" / "approval.pub"
    generate_keypair(private, public)
    return private, public


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def broker(tmp_path: Path, keys, clock) -> ApprovalBroker:
    return ApprovalBroker(
        tmp_path / "approvals", public_key=load_public_key(keys[1]), ttl_seconds=900, now=clock
    )


def _request(broker: ApprovalBroker, **overrides):
    kwargs = dict(
        tool=TOOL,
        tier=3,
        capability="SOAR_ALLOW_ACTIONS",
        args=ARGS,
        target={"incident_id": 42},
        plan="Block 203.0.113.44",
        action={"id": 47, "name": "Firewall — Block IP"},
        destructive=True,
        policy_rule="Firewall — Block IP",
    )
    kwargs.update(overrides)
    return broker.request(**kwargs)


def _approve(
    broker: ApprovalBroker,
    keys,
    request: ApprovalRequest,
    clock: Clock,
    *,
    approver="j.rossi",
    ttl=900,
    private=None,
):
    key = private or load_private_key(keys[0])
    approved = sign_request(
        request, private_key=key, approver=approver, now=clock(), ttl_seconds=ttl
    )
    (broker.path / f"{request.approval_id}.approved.json").write_text(
        json.dumps(approved), encoding="utf-8"
    )
    return approved


# ------------------------------------------------------------- helpers


def test_ids_and_hash():
    aid = new_approval_id(1_760_000_000.0)
    assert is_approval_id(aid) and aid.startswith("APR-2025-1009-")
    for bad in (
        "APR-2025-1009",
        "apr-2025-1009-abcdef",
        "APR-25-1009-abcdef",
        "APR-2025-1009-zz",
        "x",
    ):
        assert not is_approval_id(bad)
    a = canonical_args_hash(TOOL, {"b": 1, "a": [1, 2], "approval_id": "APR-x"})
    assert a == canonical_args_hash(TOOL, {"a": [1, 2], "b": 1}) and a.startswith("sha256:")
    assert canonical_args_hash(TOOL, {"a": [2, 1], "b": 1}) != a


def test_keygen_and_loading(tmp_path: Path, keys):
    private, public = keys
    assert load_private_key(private) and load_public_key(public)
    assert b"PRIVATE" in private.read_bytes() and b"PUBLIC" in public.read_bytes()
    with pytest.raises(ApprovalError, match="cannot load"):
        load_public_key(tmp_path / "missing.pub")
    with pytest.raises(ApprovalError, match="cannot load"):
        load_private_key(public)  # wrong kind of PEM
    bad = tmp_path / "bad.pem"
    bad.write_text("nope")
    with pytest.raises(ApprovalError):
        load_public_key(bad)


# ------------------------------------------------------- request/status


def test_request_writes_file_and_status_reports_pending(broker: ApprovalBroker):
    req = _request(broker)
    path = broker.path / f"{req.approval_id}.request.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert (
        data["tool"] == TOOL
        and data["plan"] == "Block 203.0.113.44"
        and data["destructive"] is True
    )
    assert data["arguments_hash"] == canonical_args_hash(TOOL, ARGS)
    assert "approval_id" not in json.dumps(data["target"])
    status = broker.status(req.approval_id)
    assert status["state"] == "pending" and status["approver"] is None and "signature" not in status
    assert broker.status("APR-2025-1009-ffffff")["state"] == "unknown"
    assert broker.status("garbage")["state"] == "invalid"
    assert broker.load_request("APR-2025-1009-ffffff") is None


def test_status_expired_and_rejected(broker: ApprovalBroker, clock: Clock):
    req = _request(broker)
    clock.t += 901
    assert broker.status(req.approval_id)["state"] == "expired"
    clock.t -= 901
    (broker.path / f"{req.approval_id}.rejected.json").write_text("{}", encoding="utf-8")
    assert broker.status(req.approval_id)["state"] == "rejected"


# ------------------------------------------------------ verify+consume


def test_happy_path_is_exactly_once(broker: ApprovalBroker, keys, clock: Clock):
    req = _request(broker)
    pending = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert not pending.ok and pending.state == "pending" and "soar_check_approval" in pending.reason
    _approve(broker, keys, req, clock)
    assert broker.status(req.approval_id)["state"] == "approved"
    ok = broker.verify_and_consume(
        req.approval_id, tool=TOOL, args={**ARGS, "approval_id": req.approval_id}
    )
    assert ok.ok and ok.state == "approved" and ok.approver == "j.rossi"
    assert (broker.path / f"{req.approval_id}.consumed.json").is_file()
    assert not (broker.path / f"{req.approval_id}.approved.json").exists()
    replay = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert not replay.ok and replay.state == "consumed" and "already used" in replay.reason
    assert broker.status(req.approval_id)["state"] == "consumed"
    assert broker.status(req.approval_id)["approver"] == "j.rossi"


def test_argument_change_invalidates(broker: ApprovalBroker, keys, clock: Clock):
    req = _request(broker)
    _approve(broker, keys, req, clock)
    out = broker.verify_and_consume(req.approval_id, tool=TOOL, args={**ARGS, "action_id": 49})
    assert not out.ok and "different arguments" in out.reason
    out = broker.verify_and_consume(req.approval_id, tool="soar_add_comment", args=ARGS)
    assert not out.ok and "not soar_add_comment" in out.reason
    assert (broker.path / f"{req.approval_id}.approved.json").is_file()  # untouched


def test_expired_request_and_expired_approval(broker: ApprovalBroker, keys, clock: Clock):
    req = _request(broker)
    _approve(broker, keys, req, clock, ttl=60)
    clock.t += 61
    out = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert not out.ok and out.state == "expired" and "approval expired" in out.reason
    clock.t += 900
    out = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert out.state == "expired" and "expired at" in out.reason


def test_forged_approval_rejected(broker: ApprovalBroker, keys, clock: Clock):
    req = _request(broker)
    attacker = ed25519.Ed25519PrivateKey.generate()
    _approve(broker, keys, req, clock, private=attacker)
    out = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert not out.ok and "invalid signature" in out.reason
    assert (broker.path / f"{req.approval_id}.approved.json").is_file()  # nothing consumed


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(approver="someone else"),
        lambda d: d.update(expires_at="2999-01-01T00:00:00Z"),
        lambda d: d.update(arguments_hash="sha256:" + "0" * 64),
        lambda d: d.update(signature=base64.b64encode(b"x" * 64).decode()),
        lambda d: d.update(signature="not base64!"),
        lambda d: d.pop("signature"),
        lambda d: d.pop("approved_at"),
    ],
)
def test_tampered_approval_files_rejected(broker: ApprovalBroker, keys, clock: Clock, mutate):
    req = _request(broker)
    approved = _approve(broker, keys, req, clock)
    mutate(approved)
    (broker.path / f"{req.approval_id}.approved.json").write_text(
        json.dumps(approved), encoding="utf-8"
    )
    out = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert not out.ok and out.state == "invalid"


def test_approval_for_another_request_id_rejected(broker: ApprovalBroker, keys, clock: Clock):
    a = _request(broker)
    b = _request(broker)
    approved_a = _approve(broker, keys, a, clock)
    # Copy A's (validly signed) approval under B's id: signature matches A's fields, not B.
    (broker.path / f"{b.approval_id}.approved.json").write_text(
        json.dumps(approved_a), encoding="utf-8"
    )
    out = broker.verify_and_consume(b.approval_id, tool=TOOL, args=ARGS)
    assert not out.ok and out.state == "invalid"


def test_no_public_key_means_nothing_verifies(tmp_path: Path, keys, clock: Clock):
    broker = ApprovalBroker(tmp_path / "approvals", public_key=None, ttl_seconds=900, now=clock)
    assert not broker.can_verify
    req = _request(broker)
    _approve(broker, keys, req, clock)
    out = broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS)
    assert not out.ok and "SOAR_APPROVAL_PUBLIC_KEY_FILE" in out.reason


def test_unknown_malformed_and_rejected_states(broker: ApprovalBroker, keys, clock: Clock):
    assert broker.verify_and_consume("nope", tool=TOOL, args=ARGS).state == "invalid"
    assert (
        broker.verify_and_consume("APR-2025-1009-ffffff", tool=TOOL, args=ARGS).state == "unknown"
    )
    req = _request(broker)
    (broker.path / f"{req.approval_id}.rejected.json").write_text("{}", encoding="utf-8")
    assert broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS).state == "rejected"
    (broker.path / f"{req.approval_id}.request.json").write_text("{not json", encoding="utf-8")
    assert broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS).state == "invalid"
    (broker.path / f"{req.approval_id}.request.json").write_text('{"tool": "x"}', encoding="utf-8")
    assert broker.verify_and_consume(req.approval_id, tool=TOOL, args=ARGS).state == "invalid"


def test_from_settings_and_private_key_never_read_by_server(tmp_path: Path, keys):
    settings = Settings.load(
        {
            "SOAR_APPROVAL_PUBLIC_KEY_FILE": str(keys[1]),
            "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "b"),
            "SOAR_APPROVAL_PRIVATE_KEY_FILE": str(keys[0]),
        }
    )
    assert not any("private" in name for name in Settings.model_fields)
    broker = ApprovalBroker.from_settings(settings)
    assert broker.can_verify and broker.path == tmp_path / "b" and broker.ttl == 900
    assert not ApprovalBroker.from_settings(Settings.load({})).can_verify
    with pytest.raises(ApprovalError):
        ApprovalBroker.from_settings(
            Settings.load({"SOAR_APPROVAL_PUBLIC_KEY_FILE": str(tmp_path / "missing")})
        )


# ---------------------------------------------------------- in-band


def test_in_band_token_single_use_bound_and_expiring(broker: ApprovalBroker, clock: Clock):
    token = broker.issue_in_band_token(TOOL, ARGS)
    bad = broker.consume_in_band_token(token, TOOL, {**ARGS, "action_id": 1})
    assert not bad.ok and "different call" in bad.reason
    token = broker.issue_in_band_token(TOOL, ARGS)
    ok = broker.consume_in_band_token(token, TOOL, ARGS)
    assert ok.ok and ok.reason == IN_BAND_DISCLAIMER and "NOT HUMAN APPROVAL" in ok.reason
    assert not broker.consume_in_band_token(token, TOOL, ARGS).ok
    token = broker.issue_in_band_token(TOOL, ARGS)
    clock.t += 901
    assert broker.consume_in_band_token(token, TOOL, ARGS).state == "expired"


# --------------------------------------------------------------- CLI


def test_cli_keygen_list_and_approve_requires_typed_reference(
    tmp_path: Path, capsys, monkeypatch, clock: Clock
):
    private, public = tmp_path / "k" / "a.key", tmp_path / "k" / "a.pub"
    assert cli_approve.main(["keygen", "--private", str(private), "--public", str(public)]) == 0
    assert "SOAR_APPROVAL_PUBLIC_KEY_FILE" in capsys.readouterr().out
    assert cli_approve.main(["keygen", "--private", str(private), "--public", str(public)]) == 1

    broker_dir = tmp_path / "approvals"
    # Real time here: the CLI runs on the wall clock and must see the request as pending.
    broker = ApprovalBroker(broker_dir, public_key=load_public_key(public), ttl_seconds=900)
    assert cli_approve.main(["--broker", str(broker_dir), "list"]) == 0
    assert "no broker directory" in capsys.readouterr().out
    req = _request(broker)
    assert cli_approve.main(["--broker", str(broker_dir), "list"]) == 0
    assert f"{req.approval_id}  pending" in capsys.readouterr().out

    # Wrong reference typed back → rejected, nothing signed.
    code = cli_approve.main(
        [
            "--broker",
            str(broker_dir),
            req.approval_id,
            "--key",
            str(private),
            "--approver",
            "j.rossi",
        ],
        ask=lambda prompt: "no",
    )
    out = capsys.readouterr().out
    assert (
        code == 3
        and "REJECTED" in out
        and "Firewall — Block IP" in out
        and "Block 203.0.113.44" in out
    )
    assert broker.status(req.approval_id)["state"] == "rejected"
    assert (
        cli_approve.main(
            ["--broker", str(broker_dir), req.approval_id, "--key", str(private)],
            ask=lambda p: req.approval_id,
        )
        == 1
    )  # already rejected

    # Fresh request, correct reference typed back → signed approval the broker accepts.
    req2 = _request(broker)
    monkeypatch.setenv("SOAR_APPROVAL_PRIVATE_KEY_FILE", str(private))
    monkeypatch.setenv("SOAR_APPROVAL_BROKER_PATH", str(broker_dir))
    monkeypatch.setenv("SOAR_APPROVAL_TTL_SECONDS", "120")
    code = cli_approve.main(
        [req2.approval_id, "--approver", "j.rossi"], ask=lambda p: req2.approval_id
    )
    out = capsys.readouterr().out
    assert code == 0 and "APPROVED" in out and "Type the reference" not in out
    outcome = broker.verify_and_consume(req2.approval_id, tool=TOOL, args=ARGS)
    assert outcome.ok and outcome.approver == "j.rossi"


def test_cli_errors(tmp_path: Path, capsys, keys):
    broker_dir = tmp_path / "approvals"
    assert (
        cli_approve.main(
            ["--broker", str(broker_dir), "APR-2025-1009-ffffff", "--key", str(keys[0])],
            ask=lambda p: "",
        )
        == 1
    )
    assert "no request" in capsys.readouterr().err
    assert (
        cli_approve.main(["--broker", str(broker_dir), "approve", "garbage"], ask=lambda p: "") == 2
    )
    assert (
        cli_approve.main(["--broker", str(broker_dir), "APR-2025-1009-ffffff"], ask=lambda p: "")
        == 2
    )
    assert "no private key" in capsys.readouterr().err
    broker = ApprovalBroker(broker_dir, public_key=None, ttl_seconds=900)
    req = _request(broker)
    bad_key = tmp_path / "bad.key"
    bad_key.write_text("nope")
    assert (
        cli_approve.main(
            ["--broker", str(broker_dir), req.approval_id, "--key", str(bad_key)], ask=lambda p: ""
        )
        == 2
    )
    assert cli_approve.main([]) == 2
