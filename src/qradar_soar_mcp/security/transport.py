"""Transport hardening for streamable-HTTP (P1-11; 01 §2.1; 02 §8).

* Refuse to start without ``SOAR_HTTP_AUTH_TOKEN``.
* Refuse a bind to ``0.0.0.0`` / ``::`` without ``SOAR_HTTP_ACKNOWLEDGE_EXPOSURE=true``.
* Bearer-token check on every request, in constant time.
* Tier ≥ 3 is hard-disabled over HTTP inside ``enforce()`` regardless of config.

The TLS-terminating proxy the design requires cannot be verified from inside
the process; it is logged as an operator obligation.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from qradar_soar_mcp.config import ConfigError, Settings, is_loopback_host

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

ALL_INTERFACES = frozenset({"0.0.0.0", "::", "[::]", ""})  # noqa: S104 - these are what we refuse


def check_transport_config(settings: Settings) -> None:
    """Startup gate for the HTTP transport (P1-11 AC). Raises ConfigError."""
    if settings.mcp_transport != "streamable-http":
        return
    if not settings.http_auth_token.get_secret_value():
        raise ConfigError(
            "SOAR_MCP_TRANSPORT=streamable-http requires SOAR_HTTP_AUTH_TOKEN; refusing to start "
            "an unauthenticated HTTP listener (01 §2.1)"
        )
    if settings.mcp_host.strip() in ALL_INTERFACES and not settings.http_acknowledge_exposure:
        raise ConfigError(
            f"SOAR_MCP_HOST={settings.mcp_host!r} binds every interface; set "
            "SOAR_HTTP_ACKNOWLEDGE_EXPOSURE=true to confirm you mean it (01 §2.1)"
        )
    if not is_loopback_host(settings.mcp_host):
        logger.warning(
            "HTTP transport bound to %s: a TLS-terminating reverse proxy in front of this "
            "listener is required (01 §2.1); this process cannot verify it",
            settings.mcp_host,
        )


class BearerAuthMiddleware:
    """Pure ASGI middleware: every HTTP request needs ``Authorization: Bearer <token>``."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token:
            raise ValueError("bearer token must not be empty")
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        given = b""
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                given = value
                break
        if not hmac.compare_digest(given, self._expected):
            body = b'{"error": "unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._app(scope, receive, send)
