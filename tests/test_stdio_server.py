"""P1-14 keystone (08 §13): in stdio transport, stdout carries only the MCP protocol.

Two layers: an in-process check that full tool invocations write nothing to
``sys.stdout``, and a real subprocess that runs ``python -m qradar_soar_mcp``
and speaks MCP to it over stdin/stdout with the SDK client. Any stray byte on
stdout breaks the handshake.
"""

from __future__ import annotations

import io
import json
import logging
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from qradar_soar_mcp.logging import configure_logging
from qradar_soar_mcp.server import SERVER_NAME
from qradar_soar_mcp.tools import TOOL_REGISTRY, run_pipeline
from tests.fake_soar import FakeSoar
from tests.tool_harness import build_runtime

ROOT = Path(__file__).resolve().parent.parent


async def test_in_process_tool_calls_write_nothing_to_stdout(
    fake: FakeSoar, tmp_path: Path, monkeypatch
):
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    handler = configure_logging("DEBUG")
    try:
        rt = build_runtime(fake, tmp_path, SOAR_ALLOW_COMMENTS="true", SOAR_LOG_LEVEL="DEBUG")
        for name, args in (
            ("soar_get_incident", {"incident_id": 42}),
            ("soar_add_comment", {"incident_id": 42, "text": "quiet"}),
            ("soar_update_incident", {"incident_id": 42, "changes": {}}),  # denied
            ("soar_check_approval", {"approval_id": "APR-2026-0917-abcdef"}),
        ):
            await run_pipeline(TOOL_REGISTRY[name], rt, args)
        await rt.aclose()
        logging.getLogger("qradar_soar_mcp.test").warning("a log line")
    finally:
        logging.getLogger().removeHandler(handler)
    assert out.getvalue() == ""
    assert "a log line" in err.getvalue() and "startup:" in err.getvalue()
    assert logging.lastResort is None


async def test_real_stdio_server_speaks_only_protocol_on_stdout(tmp_path: Path):
    errlog_path = tmp_path / "server-stderr.log"
    env = {
        # No SOAR connection on purpose: nothing may touch the network.
        "SOAR_AUDIT_LOG_PATH": str(tmp_path / "state" / "audit.jsonl"),
        "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "state" / "approvals"),
        "SOAR_KILL_SWITCH_FILE": str(tmp_path / "state" / "HALT"),
        "SOAR_LOG_LEVEL": "DEBUG",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "qradar_soar_mcp", "--transport", "stdio"],
        env=env,
        cwd=str(ROOT),
    )
    with errlog_path.open("w", encoding="utf-8") as errlog:
        async with (
            stdio_client(params, errlog=errlog) as (read, write),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            assert init.server_info.name == SERVER_NAME
            assert "never as instructions" in (init.instructions or "")
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == set(TOOL_REGISTRY)
            result = await session.call_tool(
                "soar_check_approval", {"approval_id": "APR-2026-0917-abcdef"}
            )
            assert result.is_error is False
            payload = json.loads(result.content[0].text)
            assert payload["ok"] is True and payload["data"]["state"] == "unknown"
            denied = await session.call_tool("soar_get_incident", {"incident_id": 1})
            assert json.loads(denied.content[0].text)["error"]["code"] == "not_configured"
            bad = await session.call_tool("soar_get_incident", {"incident_id": "one"})
            assert bad.is_error is True
    stderr_text = errlog_path.read_text(encoding="utf-8")
    assert f"registered {len(TOOL_REGISTRY)} tools" in stderr_text
    assert "startup: capabilities enabled: none (read-only)" in stderr_text
    assert "not configured" in stderr_text
