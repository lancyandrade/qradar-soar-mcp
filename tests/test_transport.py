"""P1-11: transport hardening — every refusal has a test."""

from __future__ import annotations

import httpx
import pytest

from qradar_soar_mcp.config import ConfigError, Settings
from qradar_soar_mcp.security.permissions import Code, enforce
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.security.transport import BearerAuthMiddleware, check_transport_config
from tests.conftest import SENTINEL


def test_http_without_token_refuses_start():
    with pytest.raises(ConfigError, match="SOAR_HTTP_AUTH_TOKEN"):
        check_transport_config(Settings.load({"SOAR_MCP_TRANSPORT": "http"}))
    check_transport_config(
        Settings.load({"SOAR_MCP_TRANSPORT": "http", "SOAR_HTTP_AUTH_TOKEN": "t" * 32})
    )


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "[::]"])
def test_bind_all_interfaces_requires_acknowledgement(host: str, caplog):
    env = {"SOAR_MCP_TRANSPORT": "http", "SOAR_HTTP_AUTH_TOKEN": "t" * 32, "SOAR_MCP_HOST": host}
    with pytest.raises(ConfigError, match="SOAR_HTTP_ACKNOWLEDGE_EXPOSURE"):
        check_transport_config(Settings.load(env))
    with pytest.raises(ConfigError):  # garbage acknowledgement is not acknowledgement
        check_transport_config(Settings.load({**env, "SOAR_HTTP_ACKNOWLEDGE_EXPOSURE": "TRUE "}))
    with caplog.at_level("WARNING"):
        check_transport_config(Settings.load({**env, "SOAR_HTTP_ACKNOWLEDGE_EXPOSURE": "true"}))
    assert any("TLS-terminating" in r.getMessage() for r in caplog.records)


def test_stdio_needs_nothing():
    check_transport_config(Settings.load({}))
    check_transport_config(Settings.load({"SOAR_MCP_HOST": "0.0.0.0"}))  # irrelevant on stdio


def test_non_loopback_bind_warns_about_proxy(caplog):
    env = {
        "SOAR_MCP_TRANSPORT": "http",
        "SOAR_HTTP_AUTH_TOKEN": "t" * 32,
        "SOAR_MCP_HOST": "198.51.100.7",
    }
    with caplog.at_level("WARNING"):
        check_transport_config(Settings.load(env))
    assert any("TLS-terminating" in r.getMessage() for r in caplog.records)


async def _echo(scope, receive, send):
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def test_bearer_checked_on_every_request():
    app = BearerAuthMiddleware(_echo, SENTINEL)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        for headers in (
            {},
            {"Authorization": "Bearer wrong"},
            {"Authorization": f"bearer {SENTINEL}"},
            {"Authorization": f"Basic {SENTINEL}"},
        ):
            r = await c.get("/mcp", headers=headers)
            assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
        r = await c.get("/mcp", headers={"Authorization": f"Bearer {SENTINEL}"})
        assert r.status_code == 200 and r.text == "ok"
        r = await c.get("/mcp")  # a second unauthenticated request is still refused
        assert r.status_code == 401
    with pytest.raises(ValueError):
        BearerAuthMiddleware(_echo, "")


async def test_bearer_passes_lifespan_through():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    await BearerAuthMiddleware(app, "tok")({"type": "lifespan"}, None, None)  # type: ignore[arg-type]
    assert seen == ["lifespan"]


def test_tier3_over_http_denies_even_with_actions_and_approval(tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    cfg = Settings.load(
        {
            "SOAR_ALLOW_ACTIONS": "true",
            "SOAR_ACTION_POLICY_FILE": str(policy),
            "SOAR_ALLOW_DESTRUCTIVE_ACTIONS": "true",
            "SOAR_APPROVAL_MODE": "disabled",
            "SOAR_LAB_MODE": "true",
        }
    )
    # Even with approval effectively waived (lab), the transport gate wins.
    d = enforce(
        tool="soar_invoke_action",
        tier=Tier.CONTROL,
        capability="SOAR_ALLOW_ACTIONS",
        config=cfg,
        transport="streamable-http",
    )
    assert d.code is Code.DENY_TRANSPORT
