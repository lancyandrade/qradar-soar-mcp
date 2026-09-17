"""P1-09: stderr only; secrets, Basic credentials and Authorization values redacted."""

from __future__ import annotations

import base64
import io
import json
import logging
import sys

import pytest

from qradar_soar_mcp.logging import (
    REDACTED,
    JsonFormatter,
    RedactingFilter,
    add_secrets,
    configure_logging,
    redact,
)
from tests.conftest import SENTINEL

BASIC = "Basic " + base64.b64encode(f"id:{SENTINEL}".encode()).decode()


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch):
    err, out = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(sys, "stdout", out)
    handler = configure_logging("DEBUG", secrets=[SENTINEL])
    yield err, out
    logging.getLogger().removeHandler(handler)


@pytest.mark.parametrize(
    "level", [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]
)
def test_secret_redacted_at_every_level_and_nothing_on_stdout(captured, level):
    err, out = captured
    logging.getLogger("qradar_soar_mcp.test").log(level, "key is %s here", SENTINEL)
    text = err.getvalue()
    assert "key is" in text and SENTINEL not in text and REDACTED in text
    assert out.getvalue() == ""
    record = json.loads(text.strip().splitlines()[-1])
    assert set(record) == {"ts", "level", "logger", "msg"} and record[
        "level"
    ] == logging.getLevelName(level)


def test_basic_and_authorization_patterns_redacted_without_configured_secret(monkeypatch):
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    handler = configure_logging("INFO", secrets=[])  # no literal secret known
    try:
        logging.getLogger("httpx").info("hdr %s", BASIC)
        logging.getLogger("httpx").info("Authorization: Bearer abc.def.ghi and authorization=xyz")
    finally:
        logging.getLogger().removeHandler(handler)
    text = err.getvalue()
    assert BASIC not in text and SENTINEL not in text
    assert f"Basic {REDACTED}" in text
    assert "Bearer" not in text and "xyz" not in text
    assert text.count(REDACTED) == 3


def test_secret_redacted_in_traceback_and_stack(captured):
    err, _ = captured
    try:
        raise RuntimeError(f"boom {SENTINEL} {BASIC}")
    except RuntimeError:
        logging.getLogger("x").exception("failed")
    logging.getLogger("x").info("msg %s", SENTINEL, stack_info=True)
    text = err.getvalue()
    assert "RuntimeError" in text and SENTINEL not in text and BASIC not in text
    assert '"exc"' in text and '"stack"' in text


def test_broken_format_string_does_not_crash_or_leak(captured):
    err, _ = captured
    logging.getLogger("x").info("%d items", SENTINEL)
    text = err.getvalue()
    assert SENTINEL not in text and "items" in text


def test_configure_twice_installs_one_handler_and_disables_last_resort(captured):
    root = logging.getLogger()
    before = len(root.handlers)
    handler = configure_logging("INFO", secrets=[SENTINEL])
    assert len(root.handlers) == before and handler in root.handlers
    assert all(getattr(h, "stream", None) is not sys.stdout for h in root.handlers)
    assert logging.lastResort is None


def test_add_secrets_and_redact_helper(captured):
    err, _ = captured
    add_secrets(["OTHER-SECRET-VALUE-9911"])
    logging.getLogger("x").info("%s and %s", SENTINEL, "OTHER-SECRET-VALUE-9911")
    assert "OTHER-SECRET-VALUE-9911" not in err.getvalue()
    assert redact(f"a {SENTINEL} b {BASIC}") == f"a {REDACTED} b Basic {REDACTED}"


def test_filter_edge_cases():
    f = RedactingFilter(["", "ab", "abc", "secret", "secret-longer"])
    assert f.redact("abc abc") == "abc abc"
    assert f.redact("x secret-longer y") == f"x {REDACTED} y"
    assert f.redact("Basic short") == "Basic short"  # too short to be a credential


def test_json_formatter_shape():
    record = logging.LogRecord("n", logging.INFO, __file__, 1, "hello %s", ("w",), None)
    out = json.loads(JsonFormatter().format(record))
    assert out["msg"] == "hello w" and out["logger"] == "n" and out["ts"].endswith("+00:00")
