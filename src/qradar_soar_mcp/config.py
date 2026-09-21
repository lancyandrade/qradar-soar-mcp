"""Typed, validated, frozen settings (P1-02; 02 §2; 08 §14).

Every capability flag is off unless its value is exactly one of
``true``/``1``/``yes``/``on`` (case-insensitive, no whitespace trimming).
Empty-but-present or unrecognised values log a warning naming the variable and
resolve to the *safe* side: ``false`` for capabilities, ``true`` for the
safety switches (``SOAR_REQUIRE_*``, ``SOAR_AUDIT_REQUIRED``). Numbers fall
back to their documented default with a warning. The only inputs that refuse
to start are the ones where guessing either way would be wrong: a forbidden
capability set to true, an unusable TLS setting, a base URL that is not
HTTPS, and the cross-field rules of 02 §2/§4 (actions need a policy file;
in-band approval for Tier 3 needs lab mode; HTTP transport needs a token) and of
the TLS trust model (08 §22): a CA bundle that is not a file, a bundle given
twice with different values, a bundle together with disabled verification, and
``SOAR_VERIFY_SSL=false`` without ``SOAR_LAB_MODE=true``.

Settings are loaded from the environment (``SOAR_*``). Tests inject a mapping
through :meth:`Settings.load` and get the same source semantics.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BeforeValidator, SecretStr, ValidationError, ValidationInfo, model_validator
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from pydantic_settings.sources.utils import parse_env_vars

logger = logging.getLogger(__name__)

TRUE_VALUES = frozenset({"true", "1", "yes", "on"})
FALSE_VALUES = frozenset({"false", "0", "no", "off"})

Transport = Literal["stdio", "streamable-http"]
ApprovalMode = Literal["out_of_band", "in_band", "disabled"]
CatalogSource = Literal["export", "collections"]

# Env var names of every capability flag, in tier order (02 §2).
CAPABILITY_FLAGS: tuple[str, ...] = (
    "SOAR_ALLOW_COMMENTS",
    "SOAR_ALLOW_ARTIFACTS",
    "SOAR_ALLOW_INCIDENT_WRITES",
    "SOAR_ALLOW_TASK_WRITES",
    "SOAR_ALLOW_INCIDENT_CLOSE",
    "SOAR_ALLOW_ACTIONS",
    "SOAR_ALLOW_DESTRUCTIVE_ACTIONS",
    "SOAR_ALLOW_PLAYBOOK_DRAFT",
    "SOAR_ALLOW_PLAYBOOK_EXPORT",
    "SOAR_ALLOW_PLAYBOOK_CREATE",
    "SOAR_ALLOW_PLAYBOOK_MODIFY",
    "SOAR_ALLOW_PLAYBOOK_DEPLOY",
    "SOAR_ALLOW_PLAYBOOK_ENABLE",
)
# Legacy SOAR_ALLOW_WRITES maps to exactly these (02 §2.1) and never to ACTIONS.
LEGACY_WRITES_TARGETS: tuple[str, ...] = (
    "SOAR_ALLOW_COMMENTS",
    "SOAR_ALLOW_ARTIFACTS",
    "SOAR_ALLOW_INCIDENT_WRITES",
    "SOAR_ALLOW_TASK_WRITES",
    "SOAR_ALLOW_INCIDENT_CLOSE",
)

# Emitted once, when the settings are loaded, whenever verification is off (08 §22).
TLS_INSECURE_WARNING = (
    "TLS certificate verification is DISABLED (SOAR_VERIFY_SSL=false with SOAR_LAB_MODE=true): "
    "the SOAR API key can be intercepted by anyone on the network path. Lab use only; for a "
    "private or self-signed CA use SOAR_CA_BUNDLE instead"
)

_WARNINGS: ContextVar[list[str] | None] = ContextVar("soar_config_warnings", default=None)
_ENV_OVERRIDE: ContextVar[Mapping[str, str] | None] = ContextVar(
    "soar_config_env_override", default=None
)


class ConfigError(ValueError):
    """The configuration must not be used. The server does not start."""


def _warn(message: str) -> None:
    sink = _WARNINGS.get()
    if sink is not None:
        sink.append(message)
    logger.warning("config: %s", message)


# ------------------------------------------------------------------ parsers
def _bool_parser(name: str, *, safe: bool) -> Callable[[Any], bool]:
    def parse(value: Any) -> bool:
        if value is None:
            return safe
        if isinstance(value, bool):
            return value
        raw = str(value)
        lowered = raw.lower()  # deliberately no strip(): "TRUE " is not true (P1-02 AC)
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
        _warn(f"{name}={raw!r} is not a recognised boolean; treating as {str(safe).lower()}")
        return safe

    return parse


def _int_parser(
    name: str, *, default: int, minimum: int, maximum: int | None = None
) -> Callable[[Any], int]:
    def parse(value: Any) -> int:
        if value is None or (isinstance(value, str) and value.strip() == ""):
            return default
        try:
            number = int(str(value).strip())
        except ValueError:
            _warn(f"{name}={value!r} is not an integer; using {default}")
            return default
        if number < minimum:
            _warn(f"{name}={number} is below the minimum {minimum}; using {default}")
            return default
        if maximum is not None and number > maximum:
            _warn(f"{name}={number} exceeds the maximum {maximum}; using {maximum}")
            return maximum
        return number

    return parse


def _float_parser(name: str, *, default: float, minimum: float) -> Callable[[Any], float]:
    def parse(value: Any) -> float:
        if value is None or (isinstance(value, str) and value.strip() == ""):
            return default
        try:
            number = float(str(value).strip())
        except ValueError:
            _warn(f"{name}={value!r} is not a number; using {default}")
            return default
        if number < minimum:
            _warn(f"{name}={number} is below the minimum {minimum}; using {default}")
            return default
        return number

    return parse


def _org_id(value: Any) -> int | None:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return None
    try:
        number = int(str(value).strip())
    except ValueError:
        _warn(f"SOAR_ORG_ID={value!r} is not an integer; connection disabled")
        return None
    if number <= 0:
        _warn(f"SOAR_ORG_ID={number} is not positive; connection disabled")
        return None
    return number


def _verify_ssl(value: Any) -> bool | Path:
    """``true`` | ``false`` | (deprecated) the path of an existing CA bundle.

    Never guesses: an unrecognised value refuses to start instead of picking a
    side. The value is not echoed, because it may be a filesystem path.
    """
    if isinstance(value, bool):
        return value
    raw = str(value)
    if raw.lower() in TRUE_VALUES:
        return True
    if raw.lower() in FALSE_VALUES:
        return False
    path = Path(raw)
    if raw.strip() and path.is_file():
        return path  # the Phase-1 bool-or-path form; see Settings._tls_rules
    raise ValueError(
        "SOAR_VERIFY_SSL must be true or false (a CA bundle belongs in SOAR_CA_BUNDLE; "
        "the path of an existing bundle is still accepted here); refusing to guess"
    )


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def _transport(value: Any) -> str:
    raw = str(value).strip().lower()
    if raw in {"stdio", ""}:
        return "stdio"
    if raw in {"streamable-http", "http", "streamable_http"}:
        return "streamable-http"
    _warn(f"SOAR_MCP_TRANSPORT={value!r} is not stdio or streamable-http; using stdio")
    return "stdio"


def _approval_mode(value: Any) -> str:
    raw = str(value).strip().lower()
    if raw in {"out_of_band", "in_band", "disabled"}:
        return raw
    _warn(f"SOAR_APPROVAL_MODE={value!r} is not recognised; using out_of_band")
    return "out_of_band"


def _catalog_source(value: Any) -> str:
    """``collections`` | ``export``. Anything else resolves to ``collections``, the
    read-only source, and never to the export, which needs a more privileged key (08 §25)."""
    raw = str(value).strip().lower()
    if raw in {"export", "collections"}:
        return raw
    _warn(f"SOAR_CATALOG_SOURCE={value!r} is not recognised; using collections")
    return "collections"


def _log_level(value: Any) -> str:
    raw = str(value).strip().upper()
    if raw in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        return raw
    _warn(f"SOAR_LOG_LEVEL={value!r} is not a log level; using INFO")
    return "INFO"


def _optional_path(value: Any) -> Path | None:
    if value is None:
        return None
    raw = str(value).strip()
    return Path(raw) if raw else None


def _path(default: str) -> Callable[[Any], Path]:
    def parse(value: Any) -> Path:
        raw = str(value).strip() if value is not None else ""
        return Path(raw) if raw else Path(default)

    return parse


def _secret(value: Any) -> SecretStr:
    if isinstance(value, SecretStr):
        return value
    return SecretStr("" if value is None else str(value).strip())


def is_loopback_host(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _env_name(info: ValidationInfo) -> str:
    return f"SOAR_{(info.field_name or 'unknown').upper()}"


def _parse_capability(value: Any, info: ValidationInfo) -> bool:
    return _bool_parser(_env_name(info), safe=False)(value)


def _parse_safety(value: Any, info: ValidationInfo) -> bool:
    return _bool_parser(_env_name(info), safe=True)(value)


# A capability flag: unparseable ⇒ false. A safety switch: unparseable ⇒ true.
Cap = Annotated[bool, BeforeValidator(_parse_capability)]
Safety = Annotated[bool, BeforeValidator(_parse_safety)]


# ------------------------------------------------------------------ source
class _MappingEnvSource(EnvSettingsSource):
    """The env source, reading from a supplied mapping instead of os.environ."""

    def __init__(self, settings_cls: type[BaseSettings], mapping: Mapping[str, str]) -> None:
        self._mapping = dict(mapping)  # must exist before super().__init__ loads env vars
        super().__init__(settings_cls)

    def _load_env_vars(self) -> Mapping[str, str | None]:
        return parse_env_vars(
            self._mapping, self.case_sensitive, self.env_ignore_empty, self.env_parse_none_str
        )


# ---------------------------------------------------------------- settings
class Settings(BaseSettings):
    """Every flag from 02 §2 and every variable from env.example (08 §5 rename applied)."""

    model_config = SettingsConfigDict(
        env_prefix="SOAR_",
        frozen=True,
        extra="ignore",
        case_sensitive=False,
        validate_default=False,
    )

    # ── connection ─────────────────────────────────────────────────────
    base_url: str = ""
    org_id: Annotated[int | None, BeforeValidator(_org_id)] = None
    api_key_id: str = ""
    api_key_secret: Annotated[SecretStr, BeforeValidator(_secret)] = SecretStr("")
    # TLS trust (08 §22). Verification is on by default against Python's default TLS
    # trust configuration; ``ca_bundle``, when supplied, is used instead of it.
    verify_ssl: Annotated[bool | Path, BeforeValidator(_verify_ssl)] = True
    ca_bundle: Annotated[Path | None, BeforeValidator(_optional_path)] = None
    timeout: Annotated[
        float, BeforeValidator(_float_parser("SOAR_TIMEOUT", default=30.0, minimum=1.0))
    ] = 30.0
    max_results: Annotated[
        int, BeforeValidator(_int_parser("SOAR_MAX_RESULTS", default=50, minimum=1, maximum=500))
    ] = 50

    # ── Tier 1 ─────────────────────────────────────────────────────────
    allow_comments: Cap = False
    allow_artifacts: Cap = False

    # ── Tier 2 ─────────────────────────────────────────────────────────
    allow_incident_writes: Cap = False
    allow_task_writes: Cap = False
    allow_incident_close: Cap = False

    # ── Tier 3 ─────────────────────────────────────────────────────────
    allow_actions: Cap = False
    allow_destructive_actions: Cap = False
    action_policy_file: Annotated[Path | None, BeforeValidator(_optional_path)] = None

    # ── Tier 4 (parsed and held; no Phase-1 consumer) ─────────────────
    allow_playbook_draft: Cap = False
    allow_playbook_export: Cap = False
    allow_playbook_create: Cap = False
    allow_playbook_modify: Cap = False
    allow_playbook_deploy: Cap = False
    allow_playbook_enable: Cap = False
    playbook_export_dir: Annotated[Path, BeforeValidator(_path("out/playbooks"))] = Path(
        "out/playbooks"
    )
    # Reserved; must stay false (02 §2, 05 U4). True refuses to start.
    allow_script_writes: Cap = False

    # ── approval ───────────────────────────────────────────────────────
    approval_mode: Annotated[str, BeforeValidator(_approval_mode)] = "out_of_band"
    require_action_confirmation: Safety = True
    require_playbook_confirmation: Safety = True
    approval_broker_path: Annotated[Path, BeforeValidator(_path("approvals"))] = Path("approvals")
    approval_public_key_file: Annotated[Path | None, BeforeValidator(_optional_path)] = None
    approval_ttl_seconds: Annotated[
        int, BeforeValidator(_int_parser("SOAR_APPROVAL_TTL_SECONDS", default=900, minimum=10))
    ] = 900

    # ── blast-radius caps ──────────────────────────────────────────────
    max_mutations_per_call: Annotated[
        int,
        BeforeValidator(
            _int_parser("SOAR_MAX_MUTATIONS_PER_CALL", default=1, minimum=1, maximum=1)
        ),
    ] = 1
    max_tier2_per_hour: Annotated[
        int, BeforeValidator(_int_parser("SOAR_MAX_TIER2_PER_HOUR", default=25, minimum=0))
    ] = 25
    max_tier3_per_hour: Annotated[
        int, BeforeValidator(_int_parser("SOAR_MAX_TIER3_PER_HOUR", default=5, minimum=0))
    ] = 5
    sim_max_incidents: Annotated[
        int, BeforeValidator(_int_parser("SOAR_SIM_MAX_INCIDENTS", default=25, minimum=1))
    ] = 25

    # ── audit & safety ─────────────────────────────────────────────────
    audit_log_path: Annotated[Path, BeforeValidator(_path("audit.jsonl"))] = Path("audit.jsonl")
    audit_required: Safety = True
    snapshot_dir: Annotated[Path, BeforeValidator(_path("snapshots"))] = Path("snapshots")
    kill_switch_file: Annotated[Path, BeforeValidator(_path("HALT"))] = Path("HALT")
    log_level: Annotated[str, BeforeValidator(_log_level)] = "INFO"

    # ── catalog (P2-01; 08 §25) ────────────────────────────────────────
    catalog_source: Annotated[str, BeforeValidator(_catalog_source)] = "collections"
    # 0 reloads on every read; a day is the ceiling (a larger value is clamped to it).
    catalog_ttl_seconds: Annotated[
        int,
        BeforeValidator(
            _int_parser("SOAR_CATALOG_TTL_SECONDS", default=300, minimum=0, maximum=86_400)
        ),
    ] = 300

    # ── transport ──────────────────────────────────────────────────────
    mcp_transport: Annotated[str, BeforeValidator(_transport)] = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: Annotated[
        int, BeforeValidator(_int_parser("SOAR_MCP_PORT", default=8090, minimum=1, maximum=65535))
    ] = 8090
    http_auth_token: Annotated[SecretStr, BeforeValidator(_secret)] = SecretStr("")
    http_acknowledge_exposure: Cap = False

    # ── lab only ───────────────────────────────────────────────────────
    lab_mode: Cap = False

    # ── deprecated ─────────────────────────────────────────────────────
    allow_writes: Cap = False

    # Warnings produced while parsing this instance (for `--check`).
    warnings: tuple[str, ...] = ()

    # ------------------------------------------------------------ sources
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        override = _ENV_OVERRIDE.get()
        if override is not None:
            return (init_settings, _MappingEnvSource(settings_cls, override))
        return (init_settings, env_settings)

    # --------------------------------------------------------- validators
    @model_validator(mode="before")
    @classmethod
    def _apply_legacy_writes(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = data.get("allow_writes")
        # Parsed silently here; the field validator reports any garbage once.
        if raw is None or str(raw).lower() not in TRUE_VALUES:
            return data
        data = dict(data)
        for env_name in LEGACY_WRITES_TARGETS:
            data[env_name.removeprefix("SOAR_").lower()] = True
        _warn(
            "SOAR_ALLOW_WRITES is deprecated and will be removed in the next minor version. "
            "It has been mapped to " + ", ".join(LEGACY_WRITES_TARGETS) + ". "
            "It deliberately does NOT enable SOAR_ALLOW_ACTIONS (endpoint isolation, "
            "IP blocking); set that flag explicitly if you mean it."
        )
        return data

    @model_validator(mode="after")
    def _cross_field_rules(self) -> Settings:
        if self.allow_script_writes:
            raise ValueError(
                "SOAR_ALLOW_SCRIPT_WRITES=true is refused: script writes are an architectural "
                "non-goal (02 §1.2, 05 U4) and have no supported configuration"
            )
        if self.base_url:
            parts = urlsplit(self.base_url)
            if parts.scheme not in {"https", "http"} or not parts.hostname:
                raise ValueError("SOAR_BASE_URL must be an absolute http(s) URL")
            if parts.scheme == "http" and not is_loopback_host(parts.hostname):
                raise ValueError("SOAR_BASE_URL must use https unless it points at loopback")
            if parts.query or parts.fragment or parts.username or parts.password:
                raise ValueError("SOAR_BASE_URL must not carry credentials, a query or a fragment")
        self._tls_rules()
        if self.allow_actions:
            if self.action_policy_file is None:
                raise ValueError("SOAR_ALLOW_ACTIONS=true requires SOAR_ACTION_POLICY_FILE (02 §2)")
            if not self.action_policy_file.is_file():
                raise ValueError(
                    f"SOAR_ACTION_POLICY_FILE={self.action_policy_file} does not exist; "
                    "SOAR_ALLOW_ACTIONS=true requires a policy file"
                )
            if self.approval_mode != "out_of_band" and not self.lab_mode:
                raise ValueError(
                    f"SOAR_APPROVAL_MODE={self.approval_mode} with SOAR_ALLOW_ACTIONS=true "
                    "requires SOAR_LAB_MODE=true; out_of_band approval is mandatory for "
                    "Tier 3 outside a lab (02 §4.1)"
                )
        return self

    def _tls_rules(self) -> None:
        """The TLS trust model (08 §22). Messages name variables, never paths."""
        legacy = self.verify_ssl if isinstance(self.verify_ssl, Path) else None
        if legacy is not None:
            if self.ca_bundle is not None and not _same_file(legacy, self.ca_bundle):
                raise ValueError(
                    "SOAR_VERIFY_SSL and SOAR_CA_BUNDLE name different CA bundles; set "
                    "SOAR_VERIFY_SSL=true and keep only SOAR_CA_BUNDLE"
                )
            _warn(
                "SOAR_VERIFY_SSL=<path> is deprecated; it still selects that CA bundle, but "
                "set SOAR_VERIFY_SSL=true and SOAR_CA_BUNDLE=<path> instead"
            )
        if self.ca_bundle is not None and not self.ca_bundle.is_file():
            raise ValueError(
                "SOAR_CA_BUNDLE does not name an existing file; it must be a PEM CA bundle. "
                "Refusing to start rather than fall back to another trust source"
            )
        if self.verify_ssl is False:
            if self.ca_bundle is not None:
                raise ValueError(
                    "SOAR_CA_BUNDLE is set but SOAR_VERIFY_SSL=false disables verification; "
                    "remove one of them (keep SOAR_CA_BUNDLE to stay verified)"
                )
            if not self.lab_mode:
                raise ValueError(
                    "SOAR_VERIFY_SSL=false is refused: disabling TLS certificate verification "
                    "exposes the API key to interception and is lab-only, so it also requires "
                    "SOAR_LAB_MODE=true. For a private or self-signed CA set SOAR_CA_BUNDLE "
                    "instead"
                )
            _warn(TLS_INSECURE_WARNING)

    # ----------------------------------------------------------- loading
    @classmethod
    def load(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``env`` (default: the process environment).

        Raises:
            ConfigError: for any configuration that must not start. The message
                names the variable and never echoes a secret.
        """
        warnings: list[str] = []
        token_w = _WARNINGS.set(warnings)
        token_e = _ENV_OVERRIDE.set(env if env is not None else None)
        try:
            try:
                settings = cls()
            except ValidationError as exc:
                problems = "; ".join(
                    f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}"
                    for err in exc.errors(include_input=False, include_url=False)
                )
                raise ConfigError(problems) from None
            return settings.model_copy(update={"warnings": tuple(warnings)})
        finally:
            _WARNINGS.reset(token_w)
            _ENV_OVERRIDE.reset(token_e)

    # ---------------------------------------------------------- reporting
    @property
    def connection_ready(self) -> bool:
        return bool(
            self.base_url
            and self.org_id
            and self.api_key_id
            and self.api_key_secret.get_secret_value()
        )

    @property
    def base_url_clean(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def tls_verify(self) -> bool:
        """False only for ``SOAR_VERIFY_SSL=false``, which needs ``SOAR_LAB_MODE=true``."""
        return self.verify_ssl is not False

    @property
    def tls_ca_bundle(self) -> Path | None:
        """The user-supplied CA bundle, from ``SOAR_CA_BUNDLE`` or the deprecated path form."""
        return self.verify_ssl if isinstance(self.verify_ssl, Path) else self.ca_bundle

    @property
    def tls_trust(self) -> str:
        if not self.tls_verify:
            return "insecure"
        return "ca_bundle" if self.tls_ca_bundle is not None else "python_default"

    def capability_enabled(self, env_name: str) -> bool:
        attr = env_name.removeprefix("SOAR_").lower()
        value = getattr(self, attr, False)
        return bool(value) if isinstance(value, bool) else False

    def enabled_capabilities(self) -> list[str]:
        return [name for name in CAPABILITY_FLAGS if self.capability_enabled(name)]

    def startup_summary(self) -> str:
        """The single INFO line emitted at startup (P1-02 AC)."""
        enabled = self.enabled_capabilities()
        listing = ", ".join(enabled) if enabled else "none (read-only)"
        return (
            f"capabilities enabled: {listing}; approval_mode={self.approval_mode}; "
            f"transport={self.mcp_transport}; lab_mode={str(self.lab_mode).lower()}; "
            f"tls={self.tls_trust}"
        )

    def secret_values(self) -> list[str]:
        return [
            s
            for s in (
                self.api_key_secret.get_secret_value(),
                self.http_auth_token.get_secret_value(),
            )
            if s
        ]

    def safe_dump(self) -> dict[str, Any]:
        """JSON-safe view with every secret masked."""
        data = self.model_dump(mode="json")
        data["api_key_secret"] = "***" if self.api_key_secret.get_secret_value() else ""
        data["http_auth_token"] = "***" if self.http_auth_token.get_secret_value() else ""
        return data

    def assert_secrets_hidden(self) -> None:
        """Startup self-test (02 §7): no secret may appear in the rendered configuration.

        Raises:
            ConfigError: if any configured secret is visible in ``repr``, ``str``,
                ``model_dump`` or ``safe_dump``. The message names nothing sensitive.
        """
        import json

        rendered = "\n".join(
            (
                repr(self),
                str(self),
                repr(self.model_dump()),
                json.dumps(self.model_dump(mode="json"), default=str),
                json.dumps(self.safe_dump(), default=str),
                self.startup_summary(),
            )
        )
        for secret in self.secret_values():
            if secret in rendered:
                raise ConfigError(
                    "startup self-test failed: a configured secret is visible in the rendered "
                    "configuration; refusing to start"
                )


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Module-level convenience; ``env=None`` reads ``os.environ``."""
    return Settings.load(dict(os.environ) if env is None else env)
