"""Throwaway PKI and a loopback TLS server for the P2-TLS tests (08 §22).

Nothing here is a fixture file: every key and certificate is generated at test
time into pytest's ``tmp_path`` and thrown away, so the repository never carries
certificate material. The server listens on the loopback interface only; no test
reaches a real host.

The certificates follow RFC 5280 closely enough for ``ssl.VERIFY_X509_STRICT``,
which ``ssl.create_default_context()`` enables by default from Python 3.13.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LOOPBACK = "127.0.0.1"
_KEY_USAGE = dict(
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    encipher_only=False,
    decipher_only=False,
)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass(frozen=True)
class Leaf:
    cert: Path
    key: Path


class TestCA:
    """A self-signed test CA that issues server certificates."""

    __test__ = False  # not a pytest class

    def __init__(self, directory: Path, name: str = "Generated Test CA") -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self._key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(_name(name))
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True, **_KEY_USAGE
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        self.bundle = directory / f"{name.replace(' ', '-').lower()}.pem"
        self.bundle.write_bytes(self._cert.public_bytes(serialization.Encoding.PEM))

    def issue(
        self,
        label: str,
        *,
        dns: tuple[str, ...] = (),
        ips: tuple[str, ...] = (),
        expired: bool = False,
    ) -> Leaf:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        start, end = now - dt.timedelta(minutes=5), now + dt.timedelta(days=1)
        if expired:
            start, end = now - dt.timedelta(days=2), now - dt.timedelta(days=1)
        names: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
        names += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(label))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=False, crl_sign=False, **_KEY_USAGE
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        leaf = Leaf(self.directory / f"{label}.cert.pem", self.directory / f"{label}.key.pem")
        leaf.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        leaf.key.write_bytes(_pem_key(key))
        return leaf


class LoopbackTlsServer:
    """A one-thread HTTPS server on 127.0.0.1 that answers every request with ``{"ok": true}``.

    ``attempts`` counts TCP connections, whether or not the handshake completed;
    ``requests`` counts HTTP requests that arrived over a completed handshake. A
    client that refuses the certificate therefore shows up as an attempt without
    a request, and a silent retry of any kind would show up as a second attempt.
    """

    def __init__(self, leaf: Leaf) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile=str(leaf.cert), keyfile=str(leaf.key))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((LOOPBACK, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.1)
        self.port: int = self._sock.getsockname()[1]
        self.attempts = 0
        self.requests = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="loopback-tls", daemon=True)

    def url(self, host: str = LOOPBACK) -> str:
        return f"https://{host}:{self.port}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            self.attempts += 1
            try:
                conn.settimeout(5)
                with self._context.wrap_socket(conn, server_side=True) as tls:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    if data:
                        self.requests += 1
                        body = json.dumps({"ok": True}).encode()
                        tls.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Connection: close\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\n\r\n"
                            + body
                        )
            except (ssl.SSLError, OSError):
                pass  # the client refused our certificate, or went away
            finally:
                conn.close()
