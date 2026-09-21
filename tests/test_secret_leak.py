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
# P2-02 (08 §26): soar_get_script reads the catalog and then one script. With every method
# faulted it fails at the catalog; the ``detail_*`` cases fault the script read alone, so
# the on-demand path that carries script source leaks nothing either.
SCRIPT_TOOL = "soar_get_script"
DETAIL_ONLY = "detail_"
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
    for fault in FAULTS:
        if fault not in ("ok", "tls"):
            yield pytest.param(
                SCRIPT_TOOL, DETAIL_ONLY + fault, id=f"{SCRIPT_TOOL}-{DETAIL_ONLY}{fault}"
            )


@pytest.mark.parametrize(("tool", "fault"), list(_cases()))
async def test_no_secret_anywhere(
    tool: str, fault: str, fake: FakeSoar, tmp_path: Path, monkeypatch
):
    put_only = fault.startswith(PUT_ONLY)
    put_done = fault.startswith(PUT_DONE)
    detail_only = fault.startswith(DETAIL_ONLY)
    if detail_only:
        fault = fault.removeprefix(DETAIL_ONLY)
        fake.fault("GET", r"/scripts/\d+$", **FAULTS[fault])
        # The body itself echoes the credential too, should the fault let it through.
        fake.discovery["script:400"]["script_text"] = f"key = '{SENTINEL}'"
    elif put_only or put_done:
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
        if detail_only:  # the catalog loads untouched; only the script read is faulted
            assert (await run_pipeline(TOOL_REGISTRY["soar_list_scripts"], rt, {}))["ok"]
            rt.client.max_response_bytes = 10_000
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


# ------------------------------------------------------------- P2-01 catalog
PW_DEFAULT = "PW-DEFAULT-DO-NOT-LEAK-91c4"


def _plant_password_input(fake: FakeSoar) -> None:
    """A ``password``-typed function input whose definition holds a default everywhere one
    could hide: the selected value, a placeholder, a tooltip, a template, and keys the
    verified shape does not even have. The API key is echoed into configuration text too."""
    field = fake.discovery["function_fields"][0]
    field.update(
        input_type="password",
        placeholder=PW_DEFAULT,
        tooltip=f"default is {PW_DEFAULT}",
        default_value=PW_DEFAULT,
        default=PW_DEFAULT,
        values=[{"label": PW_DEFAULT, "value": PW_DEFAULT, "default": True, "enabled": True}],
        templates=[{"id": 1, "name": "t", "template": PW_DEFAULT, "uuid": "uuid-t"}],
    )
    fake.discovery["function:200"]["description"] = f"connects with {SENTINEL}"
    fake.discovery["scripts"]["entities"][0]["description"] = f"Authorization: Basic {SENTINEL}"


async def test_catalog_loading_and_refresh_leak_no_password_default_and_no_credential(
    fake: FakeSoar, tmp_path: Path, monkeypatch
):
    _plant_password_input(fake)
    env = base_env(tmp_path, SOAR_LOG_LEVEL="DEBUG")
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    handler = configure_logging("DEBUG", secrets=[SENTINEL])
    probe = LeakProbe()
    logging.getLogger().addHandler(probe)
    try:
        rt = Runtime.build(env, transport="stdio")
        out = await run_pipeline(TOOL_REGISTRY["soar_refresh_catalog"], rt, {})
        catalog = await rt.require_catalog().get()
        await rt.aclose()
    finally:
        logging.getLogger().removeHandler(probe)
        logging.getLogger().removeHandler(handler)

    assert out["ok"] is True, out
    # Sanitised at ingestion: the model holds the input, and nothing a value could hide in.
    secret_input = catalog.functions["function_200"].inputs[0]
    assert secret_input.input_type == "password" and secret_input.name == "input_100"
    assert secret_input.values == () and secret_input.placeholder is None
    assert secret_input.tooltip is None
    stored = catalog.to_json()
    assert PW_DEFAULT not in stored and PW_DEFAULT not in repr(catalog)
    # The API key echoed into configuration text is scrubbed at ingestion as well, with
    # anything shaped like a credential; the output redactor is only the backstop.
    assert SENTINEL not in stored and "Basic " + SENTINEL not in stored
    assert "[REDACTED]" in catalog.functions["function_200"].description
    assert "[REDACTED]" in (next(iter(catalog.scripts.values())).description or "")
    rendered = json.dumps(out, default=str)
    for secret in (PW_DEFAULT, SENTINEL):
        assert secret not in rendered
        assert secret not in "\n".join(probe.texts), "a raw log record contained it"
        assert secret not in stderr.getvalue()
    assert "Basic " not in rendered
    assert audit_text(tmp_path) == ""  # a read writes no audit record at all


def audit_text(tmp_path: Path) -> str:
    audit = tmp_path / "state" / "audit.jsonl"
    return audit.read_text(encoding="utf-8") if audit.exists() else ""


async def test_the_raw_catalog_payloads_are_never_logged(
    fake: FakeSoar, tmp_path: Path, monkeypatch
):
    marker = "RAW-PAYLOAD-MARKER-5d20"
    fake.discovery["actions"]["entities"][0]["name"] = marker
    fake.discovery["playbooks"][0]["description"] = marker
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    handler = configure_logging("DEBUG", secrets=[SENTINEL])
    probe = LeakProbe()
    logging.getLogger().addHandler(probe)
    try:
        rt = Runtime.build(base_env(tmp_path, SOAR_LOG_LEVEL="DEBUG"), transport="stdio")
        out = await run_pipeline(TOOL_REGISTRY["soar_refresh_catalog"], rt, {})
        await rt.aclose()
    finally:
        logging.getLogger().removeHandler(probe)
        logging.getLogger().removeHandler(handler)
    assert out["ok"] is True
    assert marker not in "\n".join(probe.texts) and marker not in stderr.getvalue()
    assert marker not in json.dumps(out)


async def test_a_malformed_catalog_row_does_not_put_its_values_anywhere(
    fake: FakeSoar, tmp_path: Path, monkeypatch
):
    fake.discovery["scripts"]["entities"][0]["id"] = PW_DEFAULT  # not the verified type
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    handler = configure_logging("DEBUG", secrets=[SENTINEL])
    probe = LeakProbe()
    logging.getLogger().addHandler(probe)
    try:
        rt = Runtime.build(base_env(tmp_path, SOAR_LOG_LEVEL="DEBUG"), transport="stdio")
        out = await run_pipeline(TOOL_REGISTRY["soar_refresh_catalog"], rt, {})
        await rt.aclose()
    finally:
        logging.getLogger().removeHandler(probe)
        logging.getLogger().removeHandler(handler)
    assert out["ok"] is False and out["error"]["code"] == "malformed_response"
    assert PW_DEFAULT not in json.dumps(out)
    assert PW_DEFAULT not in "\n".join(probe.texts) and PW_DEFAULT not in stderr.getvalue()


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
