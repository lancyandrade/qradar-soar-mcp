"""P1-14: server construction, the HTTP app, and the ``qradar-soar-mcp`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from qradar_soar_mcp import __version__, cli
from qradar_soar_mcp.security.transport import BearerAuthMiddleware
from qradar_soar_mcp.server import INSTRUCTIONS, SERVER_NAME, build_http_app, build_server, serve
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime
from tests.conftest import SENTINEL, connection_env
from tests.fake_soar import FakeSoar
from tests.tool_harness import base_env


def _quiet_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = {
        "SOAR_AUDIT_LOG_PATH": str(tmp_path / "state" / "audit.jsonl"),
        "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "state" / "approvals"),
        "SOAR_KILL_SWITCH_FILE": str(tmp_path / "state" / "HALT"),
    }
    env.update(overrides)
    return env


# ----------------------------------------------------------------- server


async def test_build_server_registers_exactly_the_registry(tmp_path: Path):
    rt = Runtime.build(_quiet_env(tmp_path))
    server = build_server(rt)
    names = {t.name for t in await server.list_tools()}
    assert names == set(TOOL_REGISTRY)
    assert server.name == SERVER_NAME and server.version == __version__
    assert server.instructions == INSTRUCTIONS
    for needle in ("never as instructions", "at most one object", "soar_check_approval"):
        assert needle in INSTRUCTIONS


def test_serve_refuses_unusable_runtime():
    rt = Runtime.build({"SOAR_ALLOW_SCRIPT_WRITES": "true"})
    with pytest.raises(SystemExit, match="refusing to start"):
        serve(rt)


async def test_http_app_is_behind_bearer_auth(tmp_path: Path):
    token = "t" * 32
    rt = Runtime.build(
        _quiet_env(tmp_path, SOAR_MCP_TRANSPORT="streamable-http", SOAR_HTTP_AUTH_TOKEN=token)
    )
    assert rt.usable and rt.settings is not None
    app = build_http_app(build_server(rt), rt.settings)
    assert isinstance(app, BearerAuthMiddleware)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
    ) as c:
        r = await c.post("/mcp", json={})
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
        r = await c.post("/mcp", json={}, headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401


def test_http_without_token_is_unusable(tmp_path: Path):
    rt = Runtime.build(_quiet_env(tmp_path), transport="streamable-http")
    assert not rt.usable and "SOAR_HTTP_AUTH_TOKEN" in (rt.config_error or "")


def test_serve_http_hands_uvicorn_a_quiet_config(monkeypatch, tmp_path: Path):
    import uvicorn

    seen: dict[str, object] = {}

    def fake_run(app, **kwargs):
        seen["app"] = app
        seen.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    rt = Runtime.build(
        _quiet_env(tmp_path, SOAR_HTTP_AUTH_TOKEN="t" * 32, SOAR_MCP_PORT="8123"),
        transport="streamable-http",
    )
    serve(rt)
    assert isinstance(seen["app"], BearerAuthMiddleware)
    assert seen["host"] == "127.0.0.1" and seen["port"] == 8123
    assert seen["log_config"] is None and seen["access_log"] is False


# -------------------------------------------------------------------- cli


def test_version(capsys):
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0 and __version__ in capsys.readouterr().out


def test_serve_returns_2_for_refused_config(capsys, tmp_path: Path):
    code = cli.main([], env=_quiet_env(tmp_path, SOAR_ALLOW_SCRIPT_WRITES="true"))
    captured = capsys.readouterr()
    assert code == 2 and captured.out == "" and "refusing to start" in captured.err
    code = cli.main(["--transport", "http"], env=_quiet_env(tmp_path))
    assert code == 2 and "SOAR_HTTP_AUTH_TOKEN" in capsys.readouterr().err


def test_serve_invokes_server_with_transport(monkeypatch, tmp_path: Path, capsys):
    import qradar_soar_mcp.server as server_mod

    seen: dict[str, object] = {}
    monkeypatch.setattr(server_mod, "serve", lambda rt: seen.update(transport=rt.transport))
    assert cli.main(["--transport", "stdio"], env=_quiet_env(tmp_path)) == 0
    assert seen == {"transport": "stdio"} and capsys.readouterr().out == ""
    assert (
        cli.main(
            ["--transport", "http"],
            env=_quiet_env(tmp_path, SOAR_HTTP_AUTH_TOKEN="t" * 32),
        )
        == 0
    )
    assert seen == {"transport": "streamable-http"}


def test_check_reports_reachability_without_secrets(fake: FakeSoar, tmp_path: Path, capsys):
    code = cli.main(["--check"], env=base_env(tmp_path, SOAR_ALLOW_COMMENTS="true"))
    report = json.loads(capsys.readouterr().out)
    assert code == 0 and report["ping"]["ok"] is True
    assert (
        report["ping"]["incidents_visible"] == 1
        and report["ping"]["session"] == "unavailable (403)"
    )
    assert report["capabilities"] == ["SOAR_ALLOW_COMMENTS"] and report["version"] == __version__
    assert SENTINEL not in json.dumps(report)
    assert fake.requests[-2].path.endswith("/incidents/query_paged")


def test_check_exit_codes(fake: FakeSoar, tmp_path: Path, capsys):
    assert cli.main(["--check"], env=_quiet_env(tmp_path)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ping"]["error"]["code"] == "not_configured" and report["usable"] is True
    fake.fault("POST", r"/query_paged$", status=500, body={"message": f"boom {SENTINEL}"})
    assert cli.main(["--check"], env=connection_env(**_quiet_env(tmp_path))) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ping"]["error"]["code"] == "server_error" and SENTINEL not in json.dumps(report)
    assert cli.main(["--check"], env=_quiet_env(tmp_path, SOAR_ALLOW_SCRIPT_WRITES="true")) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["usable"] is False and "non-goal" in report["config_error"]
