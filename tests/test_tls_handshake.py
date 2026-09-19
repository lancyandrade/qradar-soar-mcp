"""P2-TLS (08 §22): real TLS handshakes, on the loopback interface only.

A throwaway CA and a one-thread HTTPS server (``tests/tls_harness.py``) let the
actual client negotiate actual TLS, so these tests prove what mocks cannot:

* a user-supplied CA bundle verifies a private CA, **with** the host name checked;
* Python's default trust rejects an unknown CA, and a wrong bundle is rejected;
* a host-name mismatch is never bypassed, even when the CA is trusted;
* after a verification failure there is exactly one connection attempt and no
  request ever arrives: nothing retried, with or without verification;
* only the explicit lab opt-in gets past verification.

No test leaves 127.0.0.1, and no key or certificate is stored in the repository.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.config import ConfigError, Settings
from qradar_soar_mcp.errors import SoarTLSError
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from tests.conftest import connection_env
from tests.tls_harness import LOOPBACK, Leaf, LoopbackTlsServer, TestCA
from tests.tool_harness import base_env

PATH = "/rest/orgs/201/incidents/42"
LAB_INSECURE = {"SOAR_VERIFY_SSL": "false", "SOAR_LAB_MODE": "true"}


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's proxy settings must not carry loopback traffic anywhere."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> TestCA:
    return TestCA(tmp_path_factory.mktemp("pki"))


@pytest.fixture(scope="module")
def other_ca(tmp_path_factory: pytest.TempPathFactory) -> TestCA:
    return TestCA(tmp_path_factory.mktemp("other-pki"), "Other Generated CA")


@pytest.fixture(scope="module")
def good_leaf(ca: TestCA) -> Leaf:
    return ca.issue("loopback", dns=("localhost",), ips=(LOOPBACK,))


@pytest.fixture(scope="module")
def elsewhere_leaf(ca: TestCA) -> Leaf:
    """Issued by the trusted CA, but for a different host."""
    return ca.issue("elsewhere", dns=("soar.example.internal",))


@pytest.fixture
def server(good_leaf: Leaf) -> Iterator[LoopbackTlsServer]:
    with LoopbackTlsServer(good_leaf) as running:
        yield running


def _settings(url: str, **env: str) -> Settings:
    return Settings.load(connection_env(SOAR_BASE_URL=url, SOAR_TIMEOUT="10", **env))


def _public(err: SoarTLSError) -> str:
    return str(err) + repr(err) + json.dumps(err.to_dict())


async def _expect_tls_failure(settings: Settings) -> SoarTLSError:
    async with SoarClient(settings) as client:
        with pytest.raises(SoarTLSError) as info:
            await client.get(PATH)
        assert client.tls.verifies  # the failure did not loosen anything
    err = info.value
    assert err.code == "tls" and err.__cause__ is None and err.__context__ is None
    return err


# ------------------------------------------------------------ the harness


def test_generated_certificates_pass_strict_x509_verification(
    ca: TestCA, server: LoopbackTlsServer
):
    """Python 3.13+ verifies with VERIFY_X509_STRICT by default; hold the harness to it."""
    context = ssl.create_default_context(cafile=str(ca.bundle))
    context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    with (
        socket.create_connection((LOOPBACK, server.port), timeout=10) as raw,
        context.wrap_socket(raw, server_hostname=LOOPBACK) as tls,
    ):
        assert tls.version() in {"TLSv1.2", "TLSv1.3"}


# ------------------------------------------------------------- verified


async def test_a_ca_bundle_verifies_a_private_ca(ca: TestCA, server: LoopbackTlsServer):
    async with SoarClient(_settings(server.url(), SOAR_CA_BUNDLE=str(ca.bundle))) as client:
        assert client.tls.mode == "ca_bundle"
        assert await client.get(PATH) == {"ok": True}
    assert (server.attempts, server.requests) == (1, 1)


async def test_the_deprecated_path_form_verifies_the_same_way(
    ca: TestCA, server: LoopbackTlsServer
):
    async with SoarClient(_settings(server.url(), SOAR_VERIFY_SSL=str(ca.bundle))) as client:
        assert client.tls.mode == "ca_bundle"
        assert await client.get(PATH) == {"ok": True}
    assert server.requests == 1


# ------------------------------------------------------------- rejected


async def test_default_trust_rejects_an_unknown_ca_and_nothing_is_retried(
    server: LoopbackTlsServer, caplog: pytest.LogCaptureFixture
):
    with caplog.at_level(logging.WARNING):
        err = await _expect_tls_failure(_settings(server.url()))
    assert "issuer is not trusted" in str(err) and "SOAR_CA_BUNDLE" in str(err)
    assert "category=untrusted issuer" in (err.detail or "")
    # One TCP connection, no completed handshake, no request: no retry, verified or not.
    assert (server.attempts, server.requests) == (1, 0)
    public = _public(err)
    assert LOOPBACK not in public and str(server.port) not in public
    assert "SOAR_VERIFY_SSL" not in public and "verify_code" not in public
    logged = [r.getMessage() for r in caplog.records if "tls failure" in r.getMessage()]
    assert len(logged) == 1 and "untrusted issuer" in logged[0]


async def test_a_bundle_for_another_ca_is_rejected(
    other_ca: TestCA, server: LoopbackTlsServer, tmp_path: Path
):
    err = await _expect_tls_failure(_settings(server.url(), SOAR_CA_BUNDLE=str(other_ca.bundle)))
    assert "issuer is not trusted" in str(err)
    assert (server.attempts, server.requests) == (1, 0)
    assert str(other_ca.bundle) not in _public(err) and other_ca.bundle.name not in _public(err)


@pytest.mark.parametrize("host", [LOOPBACK, "localhost"])
async def test_a_host_name_mismatch_is_never_bypassed(ca: TestCA, elsewhere_leaf: Leaf, host: str):
    """The CA is trusted and the certificate is valid, just not for this host."""
    with LoopbackTlsServer(elsewhere_leaf) as server:
        err = await _expect_tls_failure(_settings(server.url(host), SOAR_CA_BUNDLE=str(ca.bundle)))
        assert server.requests == 0 and server.attempts == 1
    assert "not valid for the host in SOAR_BASE_URL" in str(err)
    assert "never bypassed automatically" in str(err)
    assert "category=host name mismatch" in (err.detail or "")
    assert "soar.example.internal" not in _public(err) and host not in _public(err)


async def test_an_expired_certificate_is_rejected(ca: TestCA):
    expired = ca.issue("expired", dns=("localhost",), ips=(LOOPBACK,), expired=True)
    with LoopbackTlsServer(expired) as server:
        err = await _expect_tls_failure(_settings(server.url(), SOAR_CA_BUNDLE=str(ca.bundle)))
        assert server.requests == 0
    assert "expired or not yet valid" in str(err)
    assert "category=validity period" in (err.detail or "")


# ------------------------------------------------------ the lab override


async def test_only_the_explicit_lab_opt_in_gets_past_verification(server: LoopbackTlsServer):
    with pytest.raises(ConfigError, match="SOAR_LAB_MODE=true"):
        _settings(server.url(), SOAR_VERIFY_SSL="false")
    assert server.attempts == 0  # refused before any connection
    async with SoarClient(_settings(server.url(), **LAB_INSECURE)) as client:
        assert client.tls.mode == "insecure"
        assert await client.get(PATH) == {"ok": True}
    assert (server.attempts, server.requests) == (1, 1)


# ------------------------------------------------------ through the pipeline


async def test_a_tls_failure_reaches_the_model_sanitised(
    tmp_path: Path, server: LoopbackTlsServer, capsys: pytest.CaptureFixture[str]
):
    rt = Runtime.build(base_env(tmp_path, SOAR_BASE_URL=server.url(), SOAR_TIMEOUT="10"))
    assert rt.usable and rt.describe()["tls"] == {"verify": True, "trust": "python_default"}
    first = await run_pipeline(TOOL_REGISTRY["soar_get_incident"], rt, {"incident_id": 42})
    second = await run_pipeline(TOOL_REGISTRY["soar_get_incident"], rt, {"incident_id": 42})
    await rt.aclose()
    assert first["ok"] is False and first["error"]["code"] == "tls"
    assert first["error"] == second["error"]  # deterministic
    assert "SOAR_CA_BUNDLE" in first["error"]["message"]
    rendered = json.dumps(first)
    assert LOOPBACK not in rendered and str(server.port) not in rendered
    assert str(tmp_path) not in rendered and "verify_code" not in rendered
    assert (server.attempts, server.requests) == (2, 0)  # one attempt per call, none succeeded
    assert capsys.readouterr().out == ""
