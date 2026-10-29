"""LAB-01: opt-in guards for the live lab tiers (07 §2, §7; plan: docs/lab-validation-plan.md).

Nothing in this module sends a request. It decides, from an explicit mapping of
``SOAR_TEST_*`` variables, whether a lab tier may run and against what, and it
provides the transport filter that keeps T4 read-only on the wire.

Outcomes, never a third one:

- the tier is not enabled ⇒ :class:`LabNotEnabledError` (the test is **skipped**);
- the tier is enabled but its target is missing, ambiguous or unsafe ⇒
  :class:`LabRefusedError` (the test **fails**). An enabled tier never falls back to
  another target, to the server's own ``SOAR_*`` configuration, to a default host or
  from a mock to a real system.

Error messages name variables, never their values, and never a secret.
"""

from __future__ import annotations

import dataclasses
import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ENABLE_VAR = "SOAR_TEST_ENABLE"
LAB_PREFIX = "SOAR_TEST_"


class LabTier(enum.StrEnum):
    """The three live tiers of 07 §2, by their pytest marker."""

    READ_ONLY = "lab"  # T4: real SOAR, read-only key, org 201
    WRITE = "lab_write"  # T5: real SOAR, disposable org 301
    DESTRUCTIVE = "lab_destructive"  # T6: real SOAR + mock AppHost, never in CI


TIER_NAMES = {LabTier.READ_ONLY: "T4", LabTier.WRITE: "T5", LabTier.DESTRUCTIVE: "T6"}


class LabNotEnabledError(Exception):
    """The tier was not opted into: skip."""


class LabRefusedError(Exception):
    """The tier was opted into but cannot run safely: fail, never skip or fall back."""


@dataclass(frozen=True, slots=True)
class LabTarget:
    tier: LabTier
    base_url: str
    host: str
    org_id: int
    api_key_id: str
    api_key_secret: str = field(repr=False)
    ca_bundle: str | None = None
    mock_apphost_url: str | None = None

    def runtime_env(self, state_dir: Path) -> dict[str, str]:
        """The complete server environment for a lab run.

        Built only from this target: no ``SOAR_*`` value of the calling process is
        read. Every capability flag is absent (deny by default), the audit log is
        required and lives under ``state_dir`` so the run can be verified.
        """
        env = {
            "SOAR_BASE_URL": self.base_url,
            "SOAR_ORG_ID": str(self.org_id),
            "SOAR_API_KEY_ID": self.api_key_id,
            "SOAR_API_KEY_SECRET": self.api_key_secret,
            "SOAR_VERIFY_SSL": "true",
            "SOAR_AUDIT_REQUIRED": "true",
            "SOAR_AUDIT_LOG_PATH": str(state_dir / "audit.jsonl"),
            "SOAR_APPROVAL_BROKER_PATH": str(state_dir / "approvals"),
            "SOAR_KILL_SWITCH_FILE": str(state_dir / "HALT"),
            "SOAR_SNAPSHOT_DIR": str(state_dir / "snapshots"),
        }
        if self.ca_bundle:
            env["SOAR_CA_BUNDLE"] = self.ca_bundle
        return env


# ----------------------------------------------------------------- parsing
def _host_of(url: str, var: str, *, allow_http: bool = False) -> str:
    parts = urlsplit(url)
    schemes = {"https", "http"} if allow_http else {"https"}
    if parts.scheme not in schemes:
        raise LabRefusedError(f"{var} must be an {' or '.join(sorted(schemes))} URL")
    if parts.username or parts.password:
        raise LabRefusedError(f"{var} must not carry credentials")
    if parts.query or parts.fragment:
        raise LabRefusedError(f"{var} must not carry a query or fragment")
    if not parts.hostname:
        raise LabRefusedError(f"{var} has no host")
    return parts.hostname.lower().rstrip(".")


def _required(env: Mapping[str, str], var: str, tier: LabTier) -> str:
    value = (env.get(var) or "").strip()
    if not value:
        raise LabRefusedError(f"{TIER_NAMES[tier]} is enabled but {var} is not set")
    return value


def _org(env: Mapping[str, str], var: str, tier: LabTier) -> int:
    raw = _required(env, var, tier)
    if not raw.isdigit() or int(raw) <= 0:
        raise LabRefusedError(f"{var} must be a positive integer organisation id")
    return int(raw)


def _hosts(env: Mapping[str, str], var: str) -> set[str]:
    return {h.strip().lower().rstrip(".") for h in (env.get(var) or "").split(",") if h.strip()}


def enabled_tiers(env: Mapping[str, str]) -> set[LabTier]:
    """Parse ``SOAR_TEST_ENABLE``. An unknown token refuses: a typo must not skip silently."""
    tokens = {t.strip() for t in (env.get(ENABLE_VAR) or "").split(",") if t.strip()}
    known = {t.value: t for t in LabTier}
    unknown = sorted(tokens - set(known))
    if unknown:
        raise LabRefusedError(
            f"{ENABLE_VAR} has unknown tier name(s) {unknown}; use lab, lab_write, lab_destructive"
        )
    return {known[t] for t in tokens}


def resolve(
    env: Mapping[str, str], tier: LabTier, *, runtime_env: Mapping[str, str] | None = None
) -> LabTarget:
    """The target ``tier`` may use, or an exception (see the module docstring).

    ``env`` holds the ``SOAR_TEST_*`` variables. ``runtime_env`` holds the server's
    own ``SOAR_*`` variables as they were before the suite scrubbed them: a lab run
    refuses to target the host the server itself is configured for, because on an
    operator's machine that is the production appliance.
    """
    if tier not in enabled_tiers(env):
        raise LabNotEnabledError(
            f"{TIER_NAMES[tier]} not enabled (set {ENABLE_VAR} to include {tier})"
        )

    base_url = _required(env, "SOAR_TEST_BASE_URL", tier).rstrip("/")
    host = _host_of(base_url, "SOAR_TEST_BASE_URL")
    if urlsplit(base_url).path not in ("", "/"):
        raise LabRefusedError("SOAR_TEST_BASE_URL must be the appliance root, without a path")
    ack = _required(env, "SOAR_TEST_TARGET_ACK", tier).lower().rstrip(".")
    if ack != host:
        raise LabRefusedError(
            "SOAR_TEST_TARGET_ACK must repeat the host of SOAR_TEST_BASE_URL exactly"
        )
    if host in _hosts(env, "SOAR_TEST_FORBIDDEN_HOSTS"):
        raise LabRefusedError("SOAR_TEST_BASE_URL names a host listed in SOAR_TEST_FORBIDDEN_HOSTS")
    runtime_url = (runtime_env or {}).get("SOAR_BASE_URL", "").strip()
    if runtime_url:
        try:
            runtime_host = _host_of(runtime_url, "SOAR_BASE_URL", allow_http=True)
        except LabRefusedError:
            runtime_host = ""
        if runtime_host == host:
            raise LabRefusedError(
                "SOAR_TEST_BASE_URL is the host the server's own SOAR_BASE_URL names; unset "
                "SOAR_* in the shell that runs the lab suite and use SOAR_TEST_* only"
            )
    ca_bundle = (env.get("SOAR_TEST_CA_BUNDLE") or "").strip() or None
    if ca_bundle and not Path(ca_bundle).is_file():
        raise LabRefusedError("SOAR_TEST_CA_BUNDLE does not name an existing file")

    read_org = _org(env, "SOAR_TEST_ORG_ID", tier)
    read_key = _required(env, "SOAR_TEST_API_KEY_ID", tier)
    if tier is LabTier.READ_ONLY:
        return LabTarget(
            tier=tier,
            base_url=base_url,
            host=host,
            org_id=read_org,
            api_key_id=read_key,
            api_key_secret=_required(env, "SOAR_TEST_API_KEY_SECRET", tier),
            ca_bundle=ca_bundle,
        )

    # T5 and T6 mutate: only a disposable organisation with its own key (07 §7.2).
    write_org = _org(env, "SOAR_TEST_WRITE_ORG_ID", tier)
    if write_org == read_org:
        raise LabRefusedError(
            "SOAR_TEST_WRITE_ORG_ID must differ from SOAR_TEST_ORG_ID (the read-only data org)"
        )
    if _required(env, "SOAR_TEST_DISPOSABLE_ORG_ACK", tier) != str(write_org):
        raise LabRefusedError(
            "SOAR_TEST_DISPOSABLE_ORG_ACK must repeat SOAR_TEST_WRITE_ORG_ID, confirming the "
            "organisation is disposable"
        )
    write_key = _required(env, "SOAR_TEST_WRITE_API_KEY_ID", tier)
    if write_key == read_key:
        raise LabRefusedError("the write key must differ from the read-only key")
    target = LabTarget(
        tier=tier,
        base_url=base_url,
        host=host,
        org_id=write_org,
        api_key_id=write_key,
        api_key_secret=_required(env, "SOAR_TEST_WRITE_API_KEY_SECRET", tier),
        ca_bundle=ca_bundle,
    )
    if tier is LabTier.WRITE:
        return target

    # T6: a mock AppHost only (07 §7.1, §7.4). Never derived, never defaulted.
    mock_url = _required(env, "SOAR_TEST_MOCK_APPHOST_URL", tier).rstrip("/")
    mock_host = _host_of(mock_url, "SOAR_TEST_MOCK_APPHOST_URL")
    real = _hosts(env, "SOAR_TEST_REAL_APPHOST_HOSTS")
    if not real:
        raise LabRefusedError(
            "T6 is enabled but SOAR_TEST_REAL_APPHOST_HOSTS is not set; the guard must know "
            "the real AppHost to prove the mock is not it"
        )
    if mock_host in real or mock_host == host:
        raise LabRefusedError(
            "SOAR_TEST_MOCK_APPHOST_URL names the SOAR appliance or a real AppHost, not a mock"
        )
    if mock_host in _hosts(env, "SOAR_TEST_FORBIDDEN_HOSTS"):
        raise LabRefusedError(
            "SOAR_TEST_MOCK_APPHOST_URL names a host in SOAR_TEST_FORBIDDEN_HOSTS"
        )
    if (env.get("SOAR_TEST_MOCK_APPHOST_ACK") or "").strip().lower() != mock_host:
        raise LabRefusedError(
            "SOAR_TEST_MOCK_APPHOST_ACK must repeat the host of SOAR_TEST_MOCK_APPHOST_URL"
        )
    return dataclasses.replace(target, mock_apphost_url=mock_url)


# --------------------------------------------------------- read-only wire
_READ_POSTS = re.compile(r"^/rest/orgs/(\d+)/(incidents|playbooks)/query_paged$")


class LabWriteBlocked(httpx.TransportError):
    """Raised by :class:`ReadOnlyTransport` instead of sending a request."""


class ReadOnlyTransport(httpx.AsyncBaseTransport):
    """T4's wire-level guard: anything but a read to the one lab host never leaves.

    Allowed: ``GET``/``HEAD`` under ``/rest/`` on ``host``, and ``POST`` to the two
    verified search endpoints (``incidents``/``playbooks`` ``query_paged``) of
    ``org_id``. Everything else raises :class:`LabWriteBlocked` **before** the inner
    transport sees it, and is recorded in ``blocked``.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport, *, host: str, org_id: int) -> None:
        self._inner = inner
        self._host = host
        self._org = str(org_id)
        self.sent: list[tuple[str, str]] = []
        self.blocked: list[tuple[str, str]] = []

    def allows(self, request: httpx.Request) -> bool:
        if (request.url.host or "").lower() != self._host:
            return False
        path = request.url.path
        if not path.startswith("/rest/"):
            return False
        if request.method in ("GET", "HEAD"):
            org = re.match(r"^/rest/orgs/(\d+)/", path)
            return org is None or org.group(1) == self._org
        match = _READ_POSTS.match(path)
        return request.method == "POST" and match is not None and match.group(1) == self._org

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        entry = (request.method, request.url.path)
        if not self.allows(request):
            self.blocked.append(entry)
            raise LabWriteBlocked(
                f"lab read-only guard blocked {request.method} {request.url.path}"
            )
        self.sent.append(entry)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def capture_env(environ: Mapping[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """Split the process environment into (``SOAR_TEST_*``, other ``SOAR_*``).

    Called once at collection, before the suite's autouse fixture scrubs ``SOAR_*``.
    """
    lab = {k: v for k, v in environ.items() if k.startswith(LAB_PREFIX)}
    runtime = {
        k: v for k, v in environ.items() if k.startswith("SOAR_") and not k.startswith(LAB_PREFIX)
    }
    return lab, runtime
