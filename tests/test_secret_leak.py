"""P1-14 keystone (08 §13): the API key secret never appears anywhere observable.

The fake SOAR authenticates with ``SENTINEL-SECRET-DO-NOT-LEAK-7f3a``. Every
registered tool is driven to success and through every failure class — HTTP
statuses that echo the credential, timeouts, a genuine TLS verification
failure, malformed and oversized bodies — at DEBUG logging, and the sentinel
is asserted absent from: the tool response, every log record (raw, before
any filter), the redacted stderr stream, the audit log.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import ssl
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from qradar_soar_mcp.logging import configure_logging
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from tests.conftest import SENTINEL
from tests.fake_soar import FakeSoar
from tests.test_permission_matrix import MINIMAL_ARGS
from tests.tool_harness import base_env, write_policy

ALL_ON = {
    "SOAR_ALLOW_COMMENTS": "true",
    "SOAR_ALLOW_ARTIFACTS": "true",
    "SOAR_ALLOW_INCIDENT_WRITES": "true",
    "SOAR_ALLOW_TASK_WRITES": "true",
    "SOAR_ALLOW_INCIDENT_CLOSE": "true",
    "SOAR_ALLOW_ACTIONS": "true",
    "SOAR_ALLOW_DESTRUCTIVE_ACTIONS": "true",
    "SOAR_APPROVAL_MODE": "disabled",  # lab only: lets Tier 3 execute in the matrix
    "SOAR_LAB_MODE": "true",
    "SOAR_LOG_LEVEL": "DEBUG",
}

FAULTS: dict[str, dict[str, Any]] = {
    "ok": {},
    "401": {"status": 401, "body": {"message": f"bad key {SENTINEL}"}},
    "403": {"status": 403, "body": {"message": f"forbidden {SENTINEL}"}},
    "404": {"status": 404, "body": {"message": "gone"}},
    "409": {"status": 409, "body": {"message": f"conflict {SENTINEL}"}},
    "422": {"status": 422, "body": {"message": f"invalid {SENTINEL}"}},
    "500": {"status": 500, "raw_body": f"<html>{SENTINEL}</html>".encode()},
    "timeout": {"exc": httpx.ReadTimeout},
    "refused": {"exc": httpx.ConnectError},
    "malformed": {"status": 200, "raw_body": f'{{"x": "{SENTINEL}'.encode()},
    "oversized": {
        "status": 200,
        "raw_body": b'{"pad": "' + SENTINEL.encode() * 20_000 + b'"}',
        "chunked": True,
    },
    "tls": {},  # genuine SSLCertVerificationError cause; see _tls_transport
}
TOOLS_WITHOUT_SOAR = {"soar_check_approval"}
# Declared unsupported: refused before anything is sent, whatever SOAR would answer
# (P1-CORR-01 D4; 08 §21). soar_update_task_status is no longer one of them (P1-CORR-02):
# it runs the fault matrix like every other tool. There every method is faulted, so its
# first GET fails; the ``put_*`` cases fault the PUT alone so the write path leaks nothing,
# and the ``putdone_*`` cases do the same after the fake has applied the write, which is
# the path where an unusable answer is settled by the read-back (08 §24).
TOOLS_REFUSED_BEFORE_SOAR = {"soar_invoke_action"}
TASK_TOOL = "soar_update_task_status"
PUT_ONLY = "put_"
PUT_DONE = "putdone_"
# PUT outcomes that do not rule the write out: read back, and reported as unverified.
# Every HTTP error status is one of them; only "refused" (no connection) is not.
AMBIGUOUS_PUT_FAULTS = {
    "401",
    "403",
    "404",
    "409",
    "422",
    "500",
    "timeout",
    "malformed",
    "oversized",
}


def _tls_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        exc = httpx.ConnectError(f"handshake with {SENTINEL}", request=request)
        exc.__cause__ = ssl.SSLCertVerificationError(f"CERTIFICATE_VERIFY_FAILED {SENTINEL}")
        raise exc

    return httpx.MockTransport(handler)


class LeakProbe(logging.Handler):
    """Captures every record raw, before any redaction, from every logger."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.texts: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        parts = [str(record.msg), repr(record.args)]
        with contextlib.suppress(Exception):
            parts.append(record.getMessage())
        if record.exc_info:
            parts.append(repr(record.exc_info))
            exc = record.exc_info[1]
            chain = []
            while exc is not None and len(chain) < 10:
                chain.append(f"{type(exc).__name__}: {exc!s} {exc!r}")
                exc = exc.__cause__ or exc.__context__
            parts.extend(chain)
        self.texts.append("\n".join(parts))


def _cases():
    for tool in sorted(TOOL_REGISTRY):
        for fault in FAULTS:
            yield pytest.param(tool, fault, id=f"{tool}-{fault}")
    for fault in FAULTS:
        if fault not in ("ok", "tls"):
            yield pytest.param(TASK_TOOL, PUT_ONLY + fault, id=f"{TASK_TOOL}-{PUT_ONLY}{fault}")
    for fault in sorted(AMBIGUOUS_PUT_FAULTS):
        yield pytest.param(TASK_TOOL, PUT_DONE + fault, id=f"{TASK_TOOL}-{PUT_DONE}{fault}")


@pytest.mark.parametrize(("tool", "fault"), list(_cases()))
async def test_no_secret_anywhere(
    tool: str, fault: str, fake: FakeSoar, tmp_path: Path, monkeypatch
):
    put_only = fault.startswith(PUT_ONLY)
    put_done = fault.startswith(PUT_DONE)
    if put_only or put_done:
        fault = fault.removeprefix(PUT_DONE if put_done else PUT_ONLY)
        fake.fault("PUT", r".*", processed=put_done, **FAULTS[fault])
    elif fault not in ("ok", "tls"):
        for method in ("GET", "POST", "PATCH", "PUT"):
            fake.fault(method, r".*", **FAULTS[fault])
    env = base_env(tmp_path, SOAR_ACTION_POLICY_FILE=str(write_policy(tmp_path)), **ALL_ON)

    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    handler = configure_logging("DEBUG", secrets=[SENTINEL])
    probe = LeakProbe()
    logging.getLogger().addHandler(probe)
    try:
        rt = Runtime.build(
            env, transport="stdio", http_transport=_tls_transport() if fault == "tls" else None
        )
        assert rt.usable and rt.client is not None
        rt.client.max_response_bytes = 100_000
        out = await run_pipeline(TOOL_REGISTRY[tool], rt, dict(MINIMAL_ARGS[tool]))
        await rt.aclose()
    finally:
        logging.getLogger().removeHandler(probe)
        logging.getLogger().removeHandler(handler)

    rendered = json.dumps(out, default=str)
    assert SENTINEL not in rendered, f"tool response leaked the secret: {rendered[:300]}"
    assert "Basic " not in rendered
    if tool in TOOLS_REFUSED_BEFORE_SOAR:
        assert out["ok"] is False and out["error"]["code"] == "DENY_UNSUPPORTED", out
    elif put_done:
        assert out["ok"] is True, out  # the write took effect and the read-back proved it
    elif put_only and fault in AMBIGUOUS_PUT_FAULTS:
        assert out["ok"] is False and out["error"]["code"] == "unverified_write", out
    elif fault == "ok" or tool in TOOLS_WITHOUT_SOAR:
        assert out["ok"] is True, out
    else:
        assert out["ok"] is False, out
        assert out["error"]["code"] not in ("internal",), out
        if fault == "tls":
            assert out["error"]["code"] == "tls" and "SOAR_CA_BUNDLE" in out["error"]["message"]
        if fault == "oversized":
            assert out["error"]["code"] == "response_too_large"

    raw_logs = "\n".join(probe.texts)
    assert SENTINEL not in raw_logs, "a raw log record contained the secret"
    assert SENTINEL not in stderr.getvalue(), "stderr contained the secret"
    audit = tmp_path / "state" / "audit.jsonl"
    if audit.exists():
        assert SENTINEL not in audit.read_text(encoding="utf-8"), "audit log contained the secret"


async def test_redaction_backstop_catches_a_logged_secret(monkeypatch):
    """If some future code path logs the secret, the handler still hides it."""
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    handler = configure_logging("DEBUG", secrets=[SENTINEL])
    try:
        logging.getLogger("qradar_soar_mcp.future").error("oops %s", SENTINEL)
    finally:
        logging.getLogger().removeHandler(handler)
    assert SENTINEL not in stderr.getvalue()
    assert "[REDACTED]" in stderr.getvalue()
