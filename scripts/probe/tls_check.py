"""TLS inspection for the P2-00 probe. Runs before any API request.

It answers, without ever printing a certificate subject, a SAN value, a host
name or an address:

* does verification succeed with the trust the *package* uses today (httpx's
  default, the certifi bundle)? with the operating-system trust store? with a
  supplied CA bundle?
* is the leaf certificate self-signed, or issued by another CA?
* does the certificate's SAN cover the host we connect to?
* does a private CA appear to be required?

Everything reported is a boolean, a count or a fixed category string.

Trust order used by the probe (first that verifies wins):

1. ``system``        normal trust (certifi, then the OS store)
2. ``ca-bundle``     ``P2_PROBE_CA_BUNDLE`` or a path in ``SOAR_VERIFY_SSL``
3. ``san-hostname``  trust is fine but the name is not: verify against a SAN
                     DNS name that resolves to the same endpoint
4. ``lab-pinned``    LAB ONLY, opt-in. Verification against public or private
                     trust is OFF. The leaf seen by this check is pinned in
                     memory for the rest of the run (trust on first use), so a
                     mid-run interception fails, but the first connection is
                     unauthenticated. Never a package default.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

LAB_WARNING = (
    "LAB-ONLY: TLS verification against public/private trust is DISABLED for this probe run. "
    "The leaf certificate is pinned in memory (trust on first use). Never use this mode outside "
    "a lab, and never make it a package default."
)

# OpenSSL X509_V_ERR_* codes -> fixed categories. Messages are never shown: they
# can contain the host name.
VERIFY_CATEGORIES = {
    10: "certificate expired",
    9: "certificate not yet valid",
    18: "self-signed certificate",
    19: "self-signed certificate in chain",
    20: "issuer not trusted (unknown CA)",
    21: "issuer not trusted (unknown CA)",
    62: "host name mismatch",
    64: "host name mismatch (ip address)",
}


def categorise(exc: BaseException) -> str:
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ssl.SSLCertVerificationError):
            return VERIFY_CATEGORIES.get(
                cur.verify_code, f"verification failed (code {cur.verify_code})"
            )
        cur = cur.__cause__ or cur.__context__
    if isinstance(exc, TimeoutError | socket.timeout):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls protocol error"
    if isinstance(exc, OSError):
        return "connection failed"
    return type(exc).__name__


@dataclass(slots=True)
class TlsReport:
    reachable: bool = False
    connect_error: str | None = None
    verifies_with_certifi: bool | None = None
    certifi_failure: str | None = None
    verifies_with_os_store: bool | None = None
    os_store_failure: str | None = None
    ca_bundle_supplied: bool = False
    verifies_with_ca_bundle: bool | None = None
    ca_bundle_failure: str | None = None
    self_signed: bool | None = None
    leaf_is_ca: bool | None = None
    issuer_type: str = "unknown"
    host_is_ip_literal: bool = False
    san_dns_entries: int = 0
    san_ip_entries: int = 0
    san_covers_host: bool | None = None
    san_names_resolving_to_endpoint: int = 0
    verifies_with_san_hostname: bool | None = None
    currently_valid: bool | None = None
    key_type: str = "unknown"
    signature_hash: str = "unknown"
    tls_version: str = "unknown"
    private_ca_appears_required: bool | None = None
    recommended_mode: str = "unknown"
    leaf_pem: bytes = field(default=b"", repr=False)
    san_hostname: str = field(default="", repr=False)
    san_trust: str = field(default="", repr=False)

    def lines(self) -> list[str]:
        skip = {"leaf_pem", "san_hostname", "san_trust"}
        return [f"{name}: {getattr(self, name)}" for name in self.__slots__ if name not in skip]


def _handshake(
    host: str, port: int, ctx: ssl.SSLContext, server_hostname: str, timeout: float
) -> str:
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=server_hostname) as tls,
    ):
        return tls.version() or "unknown"


def _try(
    host: str, port: int, ctx: ssl.SSLContext, name: str, timeout: float
) -> tuple[bool, str | None]:
    try:
        _handshake(host, port, ctx, name, timeout)
    except Exception as exc:
        return False, categorise(exc)
    return True, None


def _certifi_context() -> ssl.SSLContext:
    import certifi  # httpx's default trust; this is what the package uses today

    return ssl.create_default_context(cafile=certifi.where())


def _san_matches(host: str, dns: list[str], ips: list[str]) -> bool:
    try:
        return str(ipaddress.ip_address(host)) in ips
    except ValueError:
        pass
    wanted = host.lower().rstrip(".")
    for name in dns:
        pattern = name.lower().rstrip(".")
        if pattern == wanted:
            return True
        if pattern.startswith("*.") and "." in wanted and wanted.split(".", 1)[1] == pattern[2:]:
            return True
    return False


def _endpoint_addresses(host: str, port: int) -> set[str]:
    with contextlib.suppress(OSError):
        return {str(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    return set()


def pinned_context(leaf_pem: bytes) -> ssl.SSLContext:
    """LAB ONLY: trust exactly this leaf; no CA, no host name check."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=leaf_pem.decode("ascii"))
    return ctx


def inspect(host: str, port: int, *, ca_bundle: str = "", timeout: float = 15.0) -> TlsReport:
    report = TlsReport()
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(host)
        report.host_is_ip_literal = True

    # The certificate itself, fetched without verification so it can be described.
    blind = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    blind.check_hostname = False
    blind.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            blind.wrap_socket(raw, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
            report.tls_version = tls.version() or "unknown"
    except Exception as exc:
        report.connect_error = categorise(exc)
        return report
    report.reachable = True
    if not der:
        report.connect_error = "no certificate presented"
        return report

    cert = x509.load_der_x509_certificate(der)
    report.leaf_pem = cert.public_bytes(serialization.Encoding.PEM)
    report.self_signed = cert.issuer == cert.subject
    with contextlib.suppress(x509.ExtensionNotFound):
        report.leaf_is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    dns: list[str] = []
    ips: list[str] = []
    with contextlib.suppress(x509.ExtensionNotFound):
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = list(san.get_values_for_type(x509.DNSName))
        ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    report.san_dns_entries, report.san_ip_entries = len(dns), len(ips)
    report.san_covers_host = _san_matches(host, dns, ips)
    now = datetime.now(UTC)
    report.currently_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        report.key_type = f"RSA-{key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        report.key_type = f"EC-{key.curve.name}"
    else:
        report.key_type = type(key).__name__
    if isinstance(cert.signature_hash_algorithm, hashes.HashAlgorithm):
        report.signature_hash = cert.signature_hash_algorithm.name

    # 1. normal trust, both flavours.
    report.verifies_with_certifi, report.certifi_failure = _try(
        host, port, _certifi_context(), host, timeout
    )
    report.verifies_with_os_store, report.os_store_failure = _try(
        host, port, ssl.create_default_context(), host, timeout
    )
    # 2. a supplied CA bundle.
    bundle_ctx: ssl.SSLContext | None = None
    if ca_bundle and Path(ca_bundle).is_file():
        report.ca_bundle_supplied = True
        try:
            bundle_ctx = ssl.create_default_context(cafile=ca_bundle)
        except (ssl.SSLError, OSError):
            report.verifies_with_ca_bundle, report.ca_bundle_failure = False, "bundle unreadable"
        else:
            report.verifies_with_ca_bundle, report.ca_bundle_failure = _try(
                host, port, bundle_ctx, host, timeout
            )
    # 3. a SAN DNS name that reaches the same endpoint (fixes a name mismatch only).
    endpoint = _endpoint_addresses(host, port)
    trusts = [("certifi", _certifi_context()), ("os", ssl.create_default_context())]
    if bundle_ctx is not None:
        trusts.append(("bundle", bundle_ctx))
    for name in dns[:8]:
        if name.startswith("*.") or not (_endpoint_addresses(name, port) & endpoint):
            continue
        report.san_names_resolving_to_endpoint += 1
        if report.verifies_with_san_hostname:
            continue
        report.verifies_with_san_hostname = False
        for label, ctx in trusts:
            if _try(host, port, ctx, name, timeout)[0]:
                report.verifies_with_san_hostname = True
                report.san_hostname, report.san_trust = name, label
                break

    failures = {report.certifi_failure, report.os_store_failure}
    report.issuer_type = (
        "self-signed leaf"
        if report.self_signed
        else "publicly trusted CA"
        if report.verifies_with_certifi
        or "host name mismatch" in " ".join(f or "" for f in failures)
        else "CA not in public or OS trust (private CA)"
    )
    report.private_ca_appears_required = (
        not report.self_signed
        and not report.verifies_with_certifi
        and not report.verifies_with_os_store
        and any(f and "unknown CA" in f for f in failures)
    )
    if report.verifies_with_certifi or report.verifies_with_os_store:
        report.recommended_mode = "system"
    elif report.verifies_with_ca_bundle:
        report.recommended_mode = "ca-bundle"
    elif report.verifies_with_san_hostname:
        report.recommended_mode = "san-hostname"
    else:
        report.recommended_mode = "lab-pinned (explicit opt-in required)"
    return report


def main() -> int:
    from probe_env import ProbeEnvError, load_env

    try:
        env = load_env()
    except ProbeEnvError as exc:
        print(f"cannot run: {exc}")
        return 2
    if env.scheme != "https":
        print("SOAR_BASE_URL is not https; there is no TLS to inspect")
        return 2
    bundle = env.ca_bundle or (
        env.verify_ssl if env.verify_ssl.lower() not in ("true", "false", "") else ""
    )
    report = inspect(env.host, env.port, ca_bundle=bundle, timeout=env.timeout)
    print("TLS inspection (no certificate subject, SAN value, host name or address is shown)")
    for line in report.lines():
        print("  " + line)
    return 0 if report.reachable else 1


if __name__ == "__main__":
    sys.exit(main())
