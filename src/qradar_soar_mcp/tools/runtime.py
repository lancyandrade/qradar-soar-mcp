"""Everything a tool call needs, built once per server process (P1-13; 01 §4).

``Runtime.build`` never raises. Anything that must stop the server — a
refused configuration, an unusable transport, a malformed action policy, an
unloadable approval key, an unwritable audit log with
``SOAR_AUDIT_REQUIRED=true`` — makes the runtime *unusable*: ``settings`` is
``None``, ``config_error`` says why, and every tool call is denied with
``DENY_CONFIG``. The CLI refuses to serve an unusable runtime.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from qradar_soar_mcp import __version__
from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.config import ConfigError, Settings
from qradar_soar_mcp.errors import SoarConfigError
from qradar_soar_mcp.logging import add_secrets, redact
from qradar_soar_mcp.security.action_policy import ActionPolicy, PolicyError
from qradar_soar_mcp.security.approvals import ApprovalBroker, ApprovalError
from qradar_soar_mcp.security.audit import AuditError, AuditLog
from qradar_soar_mcp.security.limits import Limits
from qradar_soar_mcp.security.transport import check_transport_config

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Runtime:
    transport: str
    settings: Settings | None
    config_error: str | None
    policy: ActionPolicy | None
    client: SoarClient | None
    limits: Limits | None
    broker: ApprovalBroker | None
    audit: AuditLog | None
    warnings: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ build
    @classmethod
    def unusable(cls, reason: str, transport: str = "stdio") -> Runtime:
        logger.error("refusing to start: %s", reason)
        return cls(
            transport=transport,
            settings=None,
            config_error=reason,
            policy=None,
            client=None,
            limits=None,
            broker=None,
            audit=None,
        )

    @classmethod
    def build(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        transport: str | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], float] = time.time,
    ) -> Runtime:
        try:
            settings = Settings.load(env)
        except ConfigError as exc:
            return cls.unusable(str(exc), transport or "stdio")
        effective = transport or settings.mcp_transport
        if effective != settings.mcp_transport:
            # A CLI override is still subject to every transport rule (P1-11).
            settings = settings.model_copy(update={"mcp_transport": effective})
        warnings = list(settings.warnings)
        add_secrets(settings.secret_values())
        try:
            settings.assert_secrets_hidden()
            if effective == "streamable-http":
                check_transport_config(settings)
        except ConfigError as exc:
            return cls.unusable(str(exc), effective)

        policy: ActionPolicy | None = None
        if settings.allow_actions:
            try:
                policy = ActionPolicy.load(settings.action_policy_file)
            except PolicyError as exc:
                return cls.unusable(f"action policy: {exc}", effective)

        try:
            broker = ApprovalBroker.from_settings(settings, now=now)
        except ApprovalError as exc:
            return cls.unusable(str(exc), effective)
        if (
            settings.allow_actions
            and settings.approval_mode == "out_of_band"
            and not broker.can_verify
        ):
            warnings.append(
                "SOAR_ALLOW_ACTIONS=true with out_of_band approval but no "
                "SOAR_APPROVAL_PUBLIC_KEY_FILE: no approval can ever be verified, so every "
                "action that needs one will be denied"
            )

        audit: AuditLog | None = AuditLog(
            settings.audit_log_path,
            required=settings.audit_required,
            server_version=__version__,
            redact=redact,
        )
        try:
            if audit is not None:
                audit.open()
        except AuditError as exc:
            if settings.audit_required:
                return cls.unusable(f"{exc} (SOAR_AUDIT_REQUIRED=true)", effective)
            warnings.append(
                f"{exc}; SOAR_AUDIT_REQUIRED=false so mutations will be refused but reads continue"
            )
            audit = None

        limits = Limits.from_audit_log(settings, clock=clock, wall=now)

        client: SoarClient | None = None
        if settings.connection_ready:
            try:
                client = SoarClient(settings, transport=http_transport)
            except SoarConfigError as exc:  # e.g. an unloadable CA bundle (08 §22)
                return cls.unusable(exc.safe_message, effective)
            except Exception as exc:
                return cls.unusable(
                    f"SOAR client could not be created ({type(exc).__name__})", effective
                )
            warnings.extend(client.tls.warnings)
        else:
            warnings.append(
                "SOAR connection is not configured; every tool that reaches SOAR fails "
                "with not_configured"
            )

        for message in warnings:
            logger.warning("startup: %s", message)
        logger.info("startup: %s", settings.startup_summary())
        return cls(
            transport=effective,
            settings=settings,
            config_error=None,
            policy=policy,
            client=client,
            limits=limits,
            broker=broker,
            audit=audit,
            warnings=warnings,
        )

    # ------------------------------------------------------------ helpers
    @property
    def usable(self) -> bool:
        return self.settings is not None

    def require_client(self) -> SoarClient:
        if self.client is None:
            raise SoarConfigError(
                "SOAR connection is not configured: set SOAR_BASE_URL, SOAR_ORG_ID, "
                "SOAR_API_KEY_ID and SOAR_API_KEY_SECRET"
            )
        return self.client

    async def aclose(self) -> None:
        if self.client is not None:
            await self.client.aclose()

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": __version__,
            "transport": self.transport,
            "usable": self.usable,
            "config_error": self.config_error,
            "connection_configured": self.client is not None,
            "warnings": list(self.warnings),
        }
        if self.settings is not None:
            out["capabilities"] = self.settings.enabled_capabilities()
            out["approval_mode"] = self.settings.approval_mode
            out["tls"] = {
                "verify": self.settings.tls_verify,
                "trust": self.settings.tls_trust,
            }
            out["audit"] = {
                "path": str(self.settings.audit_log_path),
                "open": bool(self.audit and self.audit.opened),
            }
        if self.policy is not None:
            out["policy"] = self.policy.describe()
        if self.limits is not None:
            out["limits"] = self.limits.describe()
        if self.broker is not None:
            out["approvals"] = {
                "broker": str(self.broker.path),
                "can_verify": self.broker.can_verify,
            }
        return out
