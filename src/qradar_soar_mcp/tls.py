"""TLS trust for the connection to SOAR (P2-TLS; 08 §22).

One decision, made once, before any request is sent:

============== =========================== ======================================
trust          configuration               what verifies the appliance
============== =========================== ======================================
python_default (default: no bundle)        Python's default TLS trust
                                           configuration: whatever
                                           ``ssl.create_default_context()``
                                           exposes on the current platform and
                                           Python distribution
ca_bundle      ``SOAR_CA_BUNDLE=<pem>``    only the explicitly supplied bundle
                                           (private or self-signed CA)
insecure       ``SOAR_VERIFY_SSL=false``   nothing. Lab only
               + ``SOAR_LAB_MODE=true``
============== =========================== ======================================

The default is often, but not always, the operating system's trust store: the
exact behaviour varies by platform and Python build, and this module does not
paper over that. It reports at start-up if the default exposes no CA
certificates at all, and it never substitutes another trust source.

In both verifying modes the certificate chain **and the host name** are checked;
a user-supplied bundle changes whom we trust, never what we check. Nothing here
retries, downgrades or falls back: a bundle that cannot be loaded refuses to
start, and a handshake that fails verification surfaces as a sanitised ``tls``
error (``errors.from_httpx``). No certificate is bundled with the package, none
is fetched from the appliance, nothing is pinned or trusted on first use, and
the operating-system trust store is never modified.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.errors import SoarConfigError

TrustMode = Literal["python_default", "ca_bundle", "insecure"]

NO_DEFAULT_TRUST_WARNING = (
    "Python's default TLS trust configuration exposes no CA certificates on this platform "
    "and Python build, so certificate verification will fail for every host until "
    "SOAR_CA_BUNDLE names a PEM CA bundle. Verification stays enabled"
)


@dataclass(frozen=True, slots=True)
class TlsTrust:
    """The outcome: which trust source is in force and what the HTTP client is given."""

    mode: TrustMode
    context: ssl.SSLContext | None  # None only in insecure mode
    warnings: tuple[str, ...] = ()

    @property
    def verifies(self) -> bool:
        return self.context is not None

    @property
    def httpx_verify(self) -> ssl.SSLContext | bool:
        """The ``verify=`` argument for httpx: a verifying context, or (insecure) ``False``."""
        return self.context if self.context is not None else False


def build_trust(settings: Settings) -> TlsTrust:
    """Resolve the TLS trust configuration. Performs no network I/O.

    Raises:
        SoarConfigError: the configuration cannot be honoured. The message names
            variables and never a filesystem path; the cause is log-only.
    """
    if not settings.tls_verify:
        # config.py already refuses this combination; never rely on a single check.
        if not settings.lab_mode:
            raise SoarConfigError(
                "SOAR_VERIFY_SSL=false requires SOAR_LAB_MODE=true; refusing to connect "
                "without certificate verification"
            )
        # config.py has already logged TLS_INSECURE_WARNING for these settings.
        return TlsTrust("insecure", None)

    bundle = settings.tls_ca_bundle
    context, failure = _verifying_context(bundle)
    if context is None:
        # Raised outside the except block: the ssl/OS error text can carry the path.
        source = "SOAR_CA_BUNDLE could not be loaded as a PEM CA bundle"
        if bundle is None:
            source = "Python's default TLS trust configuration could not be loaded"
        raise SoarConfigError(
            f"{source}; refusing to connect rather than fall back to another trust source",
            detail=failure,
        )
    if not context.check_hostname or context.verify_mode is not ssl.CERT_REQUIRED:
        raise SoarConfigError(
            "the TLS context does not verify certificates and host names; refusing to connect"
        )
    if bundle is not None:
        return TlsTrust("ca_bundle", context)
    warnings = () if _default_trust_visible(context) else (NO_DEFAULT_TRUST_WARNING,)
    return TlsTrust("python_default", context, warnings)


def _verifying_context(bundle: Path | None) -> tuple[ssl.SSLContext | None, str | None]:
    """A context that checks the chain and the host name, or ``(None, error class)``."""
    try:
        if bundle is None:
            return ssl.create_default_context(), None
        # With cafile given, Python's default trust is NOT loaded: the bundle is the trust.
        return ssl.create_default_context(cafile=str(bundle)), None
    except (ssl.SSLError, OSError, ValueError) as exc:
        return None, type(exc).__name__


def _default_trust_visible(context: ssl.SSLContext) -> bool:
    """Best-effort diagnosis only; it never changes what is trusted."""
    if context.cert_store_stats().get("x509", 0) > 0:
        return True
    paths = ssl.get_default_verify_paths()
    if paths.cafile and Path(paths.cafile).is_file():
        return True
    # A hashed directory is read lazily, so its certificates are not counted above.
    return bool(paths.capath) and _has_entries(Path(paths.capath))


def _has_entries(directory: Path) -> bool:
    try:
        return directory.is_dir() and any(directory.iterdir())
    except OSError:
        return False
