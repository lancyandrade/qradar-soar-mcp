"""P2-TLS (08 §22): the public TLS trust model, offline.

Verification is on by default against Python's default TLS trust configuration
(whatever ``ssl.create_default_context()`` exposes on the platform and Python
build); ``SOAR_CA_BUNDLE``, when supplied, is used instead of it for a private or
self-signed CA; ``SOAR_VERIFY_SSL=false`` is lab-only. Whatever the trust source,
the chain *and the host name* are checked, nothing falls back, and every refusal
happens before a request is sent. Real handshakes are in ``test_tls_handshake.py``.
"""

from __future__ import annotations

import ast
import io
import json
import logging
import ssl
import sys
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import qradar_soar_mcp
from qradar_soar_mcp import tls as tls_module
from qradar_soar_mcp.client import base as client_base
from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.config import TLS_INSECURE_WARNING, ConfigError, Settings
from qradar_soar_mcp.errors import SoarConfigError, SoarTLSError, from_httpx
from qradar_soar_mcp.logging import configure_logging
from qradar_soar_mcp.security.transport import check_transport_config
from qradar_soar_mcp.tls import NO_DEFAULT_TRUST_WARNING, build_trust
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from tests.conftest import SENTINEL, connection_env
from tests.tls_harness import TestCA
from tests.tool_harness import base_env

ROOT = Path(__file__).resolve().parent.parent
PKG = Path(qradar_soar_mcp.__file__).parent
LAB_INSECURE = {"SOAR_VERIFY_SSL": "false", "SOAR_LAB_MODE": "true"}
PATH = "/rest/orgs/201/incidents/42"


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> TestCA:
    return TestCA(tmp_path_factory.mktemp("pki"))


def _refused(env: dict[str, str]) -> str:
    with pytest.raises(ConfigError) as info:
        Settings.load(env)
    return str(info.value)


# ------------------------------------------------------------------ config


def test_verification_is_on_by_default_against_pythons_default_trust():
    s = Settings.load({})
    assert s.verify_ssl is True and s.ca_bundle is None
    assert s.tls_verify is True and s.tls_ca_bundle is None and s.tls_trust == "python_default"
    assert s.startup_summary().endswith("tls=python_default") and s.warnings == ()
    for empty in ("", "   "):
        assert Settings.load({"SOAR_CA_BUNDLE": empty}).tls_trust == "python_default"


def test_a_ca_bundle_keeps_verification_on(ca: TestCA):
    s = Settings.load({"SOAR_VERIFY_SSL": "true", "SOAR_CA_BUNDLE": str(ca.bundle)})
    assert s.tls_verify is True and s.tls_ca_bundle == ca.bundle and s.tls_trust == "ca_bundle"
    assert s.warnings == ()
    assert Settings.load({"SOAR_CA_BUNDLE": str(ca.bundle)}).tls_trust == "ca_bundle"


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_an_unusable_ca_bundle_refuses_to_start_without_echoing_the_path(tmp_path: Path, kind: str):
    target = tmp_path / "private-dir-name" / "ca.pem"
    if kind == "directory":
        target.mkdir(parents=True)
    message = _refused({"SOAR_CA_BUNDLE": str(target)})
    assert "SOAR_CA_BUNDLE" in message and "fall back" in message
    assert "private-dir-name" not in message and str(tmp_path) not in message


@pytest.mark.parametrize("value", ["nope", "", " ", "TRUE ", "2", "verify", "none"])
def test_a_malformed_verify_setting_refuses_to_start(value: str):
    message = _refused({"SOAR_VERIFY_SSL": value})
    assert "SOAR_VERIFY_SSL" in message and "refusing to guess" in message


@pytest.mark.parametrize("lab", [None, "false", "", "TRUE ", "maybe"])
def test_disabling_verification_needs_the_explicit_lab_opt_in(lab: str | None):
    env = {"SOAR_VERIFY_SSL": "false"}
    if lab is not None:
        env["SOAR_LAB_MODE"] = lab
    message = _refused(env)
    assert "SOAR_LAB_MODE=true" in message and "SOAR_CA_BUNDLE" in message
    assert "lab-only" in message


def test_the_lab_opt_in_is_loud(caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING):
        s = Settings.load(LAB_INSECURE)
    assert s.tls_verify is False and s.tls_trust == "insecure"
    assert TLS_INSECURE_WARNING in s.warnings
    assert "DISABLED" in TLS_INSECURE_WARNING and "intercepted" in TLS_INSECURE_WARNING
    assert any(TLS_INSECURE_WARNING in r.getMessage() for r in caplog.records)
    assert s.startup_summary().endswith("tls=insecure")
    # Lab mode alone changes nothing about TLS.
    assert Settings.load({"SOAR_LAB_MODE": "true"}).tls_trust == "python_default"


def test_a_bundle_with_verification_disabled_is_contradictory(ca: TestCA):
    message = _refused({**LAB_INSECURE, "SOAR_CA_BUNDLE": str(ca.bundle)})
    assert "SOAR_CA_BUNDLE is set but SOAR_VERIFY_SSL=false" in message


def test_the_phase_one_path_form_still_works_and_is_deprecated(ca: TestCA, tmp_path: Path):
    s = Settings.load({"SOAR_VERIFY_SSL": str(ca.bundle)})
    assert s.tls_verify is True and s.tls_ca_bundle == ca.bundle and s.tls_trust == "ca_bundle"
    assert len(s.warnings) == 1 and "deprecated" in s.warnings[0]
    assert "SOAR_CA_BUNDLE=<path>" in s.warnings[0] and str(ca.bundle) not in s.warnings[0]
    # Naming the same file twice is fine; two different bundles is ambiguous.
    both = Settings.load({"SOAR_VERIFY_SSL": str(ca.bundle), "SOAR_CA_BUNDLE": str(ca.bundle)})
    assert both.tls_ca_bundle == ca.bundle
    other = TestCA(tmp_path / "other", "Other Generated CA")
    message = _refused({"SOAR_VERIFY_SSL": str(ca.bundle), "SOAR_CA_BUNDLE": str(other.bundle)})
    assert "different CA bundles" in message and str(tmp_path) not in message
    # A path that does not exist was never accepted, and still is not.
    assert "SOAR_VERIFY_SSL" in _refused({"SOAR_VERIFY_SSL": str(tmp_path / "missing.pem")})


def test_two_bundles_that_cannot_be_compared_are_treated_as_different(
    ca: TestCA, monkeypatch: pytest.MonkeyPatch
):
    def unresolvable(_self: Path, *_a: Any, **_k: Any) -> Path:
        raise OSError("loop")

    monkeypatch.setattr(Path, "resolve", unresolvable)
    message = _refused({"SOAR_VERIFY_SSL": str(ca.bundle), "SOAR_CA_BUNDLE": str(ca.bundle)})
    assert "different CA bundles" in message  # ambiguity fails closed


# ------------------------------------------------------------- build_trust


def _spy_on_default_context(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real = ssl.create_default_context

    def spy(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        calls.append({"args": args, "kwargs": kwargs})
        return real(*args, **kwargs)

    monkeypatch.setattr(tls_module.ssl, "create_default_context", spy)
    return calls


def _assert_verifying(context: ssl.SSLContext | None) -> None:
    """What this project guarantees about a verifying context: certificate-chain
    verification and host-name verification. Nothing else is asserted here.

    The protocol floor is deliberately not asserted. That policy is inherited from
    Python/OpenSSL and may vary by build (08 §22): most Python builds set TLS 1.2
    themselves, while some distribution builds report no floor of their own
    (``minimum_version == MINIMUM_SUPPORTED``) and defer to the OpenSSL system
    configuration. This project uses the context as Python provides it, and sets no
    floor of its own; nothing in src/ may touch ``minimum_version`` at all (see
    ``test_no_code_path_weakens_verification``).
    """
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True and context.verify_mode is ssl.CERT_REQUIRED


def test_default_trust_is_pythons_default_context(monkeypatch: pytest.MonkeyPatch):
    calls = _spy_on_default_context(monkeypatch)
    trust = build_trust(Settings.load(connection_env()))
    # No cafile, no capath: exactly what Python exposes by default on this platform/build.
    assert calls == [{"args": (), "kwargs": {}}]
    assert trust.mode == "python_default" and trust.verifies
    assert trust.httpx_verify is trust.context
    _assert_verifying(trust.context)


def test_a_ca_bundle_is_the_only_trust_when_supplied(monkeypatch: pytest.MonkeyPatch, ca: TestCA):
    calls = _spy_on_default_context(monkeypatch)
    trust = build_trust(Settings.load(connection_env(SOAR_CA_BUNDLE=str(ca.bundle))))
    assert calls == [{"args": (), "kwargs": {"cafile": str(ca.bundle)}}]
    assert trust.mode == "ca_bundle" and trust.warnings == ()
    _assert_verifying(trust.context)
    assert trust.context is not None
    # Exactly the supplied CA: Python's default trust was not loaded alongside it.
    assert trust.context.cert_store_stats()["x509"] == 1
    subjects = [dict(item[0] for item in c["subject"]) for c in trust.context.get_ca_certs()]
    assert subjects == [{"commonName": "Generated Test CA"}]


@pytest.mark.parametrize("content", [b"this is not a certificate\n", b""])
def test_a_bundle_that_is_not_pem_fails_closed_before_any_request(tmp_path: Path, content: bytes):
    bogus = tmp_path / "private-dir-name" / "bogus.pem"
    bogus.parent.mkdir()
    bogus.write_bytes(content)
    settings = Settings.load(connection_env(SOAR_CA_BUNDLE=str(bogus)))
    with pytest.raises(SoarConfigError) as info:
        build_trust(settings)
    err = info.value
    assert "SOAR_CA_BUNDLE could not be loaded" in str(err) and "fall back" in str(err)
    rendered = str(err) + repr(err) + json.dumps(err.to_dict()) + (err.detail or "")
    assert "private-dir-name" not in rendered and str(tmp_path) not in rendered
    assert err.__cause__ is None and err.__context__ is None  # the ssl error is not chained
    assert err.detail in {"SSLError", "OSError"}


def test_insecure_trust_needs_lab_mode_at_this_layer_too():
    lab = Settings.load(connection_env(**LAB_INSECURE))
    trust = build_trust(lab)
    assert trust.mode == "insecure" and trust.context is None
    assert trust.httpx_verify is False and trust.verifies is False
    # Settings cannot be loaded in this state; prove the second check independently.
    smuggled = lab.model_copy(update={"lab_mode": False})
    with pytest.raises(SoarConfigError, match="requires SOAR_LAB_MODE=true"):
        build_trust(smuggled)


def test_a_context_that_does_not_check_host_names_is_refused(monkeypatch: pytest.MonkeyPatch):
    def weakened(*_a: Any, **_k: Any) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        return context

    monkeypatch.setattr(tls_module.ssl, "create_default_context", weakened)
    with pytest.raises(SoarConfigError, match="does not verify certificates and host names"):
        build_trust(Settings.load(connection_env()))


def test_unloadable_default_trust_fails_closed(monkeypatch: pytest.MonkeyPatch):
    def broken(*_a: Any, **_k: Any) -> ssl.SSLContext:
        raise ssl.SSLError("store unavailable")

    monkeypatch.setattr(tls_module.ssl, "create_default_context", broken)
    with pytest.raises(
        SoarConfigError, match="default TLS trust configuration could not be loaded"
    ):
        build_trust(Settings.load(connection_env()))


def test_default_trust_without_ca_certificates_warns_and_stays_verified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setattr(tls_module, "_default_trust_visible", lambda _context: False)
    trust = build_trust(Settings.load(connection_env()))
    assert trust.mode == "python_default" and trust.warnings == (NO_DEFAULT_TRUST_WARNING,)
    assert "platform" in NO_DEFAULT_TRUST_WARNING and "Python build" in NO_DEFAULT_TRUST_WARNING
    assert "SOAR_CA_BUNDLE" in NO_DEFAULT_TRUST_WARNING
    _assert_verifying(trust.context)  # a warning, never a downgrade

    class Empty:
        def cert_store_stats(self) -> dict[str, int]:
            return {"x509": 0, "x509_ca": 0, "crl": 0}

    def paths(cafile: str | None, capath: str | None) -> Any:
        return lambda: type("P", (), {"cafile": cafile, "capath": capath})()

    probe: Any = Empty()
    hashed = tmp_path / "certs"
    hashed.mkdir()
    monkeypatch.undo()
    monkeypatch.setattr(tls_module.ssl, "get_default_verify_paths", paths(None, None))
    assert tls_module._default_trust_visible(probe) is False
    monkeypatch.setattr(tls_module.ssl, "get_default_verify_paths", paths(None, str(hashed)))
    assert tls_module._default_trust_visible(probe) is False  # an empty directory
    (hashed / "0a1b2c3d.0").write_text("x", encoding="utf-8")
    assert tls_module._default_trust_visible(probe) is True
    monkeypatch.setattr(
        tls_module.ssl, "get_default_verify_paths", paths(str(hashed / "0a1b2c3d.0"), None)
    )
    assert tls_module._default_trust_visible(probe) is True
    assert tls_module._has_entries(tmp_path / "absent") is False


# ------------------------------------------------------------------ client


class _RecordingClient(httpx.AsyncClient):
    seen: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, **kwargs: Any) -> None:
        type(self).seen.append(kwargs)
        super().__init__(**kwargs)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    _RecordingClient.seen = []
    monkeypatch.setattr(client_base.httpx, "AsyncClient", _RecordingClient)
    return _RecordingClient.seen


async def test_the_http_client_is_given_the_verifying_context(
    recorded: list[dict[str, Any]], ca: TestCA
):
    async with SoarClient(Settings.load(connection_env())) as system:
        assert system.tls.mode == "python_default"
    async with SoarClient(Settings.load(connection_env(SOAR_CA_BUNDLE=str(ca.bundle)))) as own:
        assert own.tls.mode == "ca_bundle"
    assert [kw["verify"] for kw in recorded] == [system.tls.context, own.tls.context]
    for kwargs in recorded:
        _assert_verifying(kwargs["verify"])
        assert kwargs["follow_redirects"] is False
    assert recorded[1]["verify"].cert_store_stats()["x509"] == 1  # the bundle, nothing else


async def test_only_the_lab_opt_in_hands_the_http_client_no_verification(
    recorded: list[dict[str, Any]],
):
    async with SoarClient(Settings.load(connection_env(**LAB_INSECURE))) as c:
        assert c.tls.mode == "insecure"
    assert [kw["verify"] for kw in recorded] == [False]


# ----------------------------------------------------------------- runtime


class _CountingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={})


@pytest.mark.parametrize("kind", ["missing", "not_pem"])
async def test_an_unusable_bundle_stops_the_server_before_any_request(tmp_path: Path, kind: str):
    target = tmp_path / "private-dir-name" / "ca.pem"
    if kind == "not_pem":
        target.parent.mkdir()
        target.write_text("not a certificate", encoding="utf-8")
    transport = _CountingTransport()
    rt = Runtime.build(base_env(tmp_path, SOAR_CA_BUNDLE=str(target)), http_transport=transport)
    assert not rt.usable and rt.client is None
    assert "SOAR_CA_BUNDLE" in (rt.config_error or "")
    out = await run_pipeline(TOOL_REGISTRY["soar_get_incident"], rt, {"incident_id": 42})
    assert out["ok"] is False and out["error"]["code"] == "DENY_CONFIG"
    assert "SOAR_CA_BUNDLE" in out["error"]["message"]
    assert "private-dir-name" not in json.dumps(out) and str(tmp_path) not in json.dumps(out)
    assert transport.calls == 0


async def test_the_check_report_names_the_trust_source(tmp_path: Path, ca: TestCA):
    transport = _CountingTransport()
    rt = Runtime.build(base_env(tmp_path), http_transport=transport)
    assert rt.describe()["tls"] == {"verify": True, "trust": "python_default"}
    await rt.aclose()
    own = Runtime.build(base_env(tmp_path, SOAR_CA_BUNDLE=str(ca.bundle)), http_transport=transport)
    assert own.describe()["tls"] == {"verify": True, "trust": "ca_bundle"}
    assert str(ca.bundle) not in json.dumps(own.describe()["tls"])
    await own.aclose()
    lab = Runtime.build(base_env(tmp_path, **LAB_INSECURE), http_transport=transport)
    assert lab.describe()["tls"] == {"verify": False, "trust": "insecure"}
    assert TLS_INSECURE_WARNING in lab.warnings
    await lab.aclose()


async def test_default_trust_without_ca_certificates_is_reported_at_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(tls_module, "_default_trust_visible", lambda _context: False)
    rt = Runtime.build(base_env(tmp_path), http_transport=_CountingTransport())
    assert rt.usable and NO_DEFAULT_TRUST_WARNING in rt.warnings
    assert rt.client is not None and rt.client.tls.verifies
    await rt.aclose()


async def test_any_other_client_failure_still_stops_the_server_by_class_name_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from qradar_soar_mcp.tools import runtime as runtime_module

    def explode(*_a: Any, **_k: Any) -> SoarClient:
        raise RuntimeError(f"boom {SENTINEL} {tmp_path}")

    monkeypatch.setattr(runtime_module, "SoarClient", explode)
    rt = Runtime.build(base_env(tmp_path))
    assert not rt.usable
    assert rt.config_error == "SOAR client could not be created (RuntimeError)"


def test_the_trust_store_diagnosis_survives_an_unreadable_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def denied(_self: Path) -> Any:
        raise PermissionError("no")

    monkeypatch.setattr(Path, "iterdir", denied)
    assert tls_module._has_entries(tmp_path) is False


def test_tls_settings_do_not_touch_the_http_transport_rules(tmp_path: Path):
    """Lab mode unlocks the TLS override only; the MCP HTTP transport rules are unchanged."""
    env = base_env(tmp_path, **LAB_INSECURE)
    rt = Runtime.build(env, transport="streamable-http")
    assert not rt.usable and "SOAR_HTTP_AUTH_TOKEN" in (rt.config_error or "")
    with pytest.raises(ConfigError, match="SOAR_HTTP_AUTH_TOKEN"):
        check_transport_config(
            Settings.load(env).model_copy(update={"mcp_transport": "streamable-http"})
        )


# ------------------------------------------------------------------ errors


def _verification_failure(code: int | None, message: str) -> httpx.ConnectError:
    exc = httpx.ConnectError(
        f"handshake {SENTINEL}", request=httpx.Request("GET", "https://soar.example.internal")
    )
    cause = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] {message}")
    if code is not None:
        cause.verify_code = code
        cause.verify_message = message
    exc.__cause__ = cause
    return exc


@pytest.mark.parametrize(
    ("code", "category", "advice"),
    [
        (62, "host name mismatch", "SOAR_BASE_URL"),
        (64, "host name mismatch", "never bypassed automatically"),
        (18, "untrusted issuer", "SOAR_CA_BUNDLE"),
        (19, "untrusted issuer", "SOAR_CA_BUNDLE"),
        (20, "untrusted issuer", "SOAR_CA_BUNDLE"),
        (21, "untrusted issuer", "SOAR_CA_BUNDLE"),
        (2, "untrusted issuer", "SOAR_CA_BUNDLE"),
        (10, "validity period", "expired or not yet valid"),
        (9, "validity period", "expired or not yet valid"),
        (26, "verification failed", "SOAR_CA_BUNDLE"),
        (None, "verification failed", "SOAR_CA_BUNDLE"),
    ],
)
def test_verification_failures_are_categorised_and_sanitised(
    code: int | None, category: str, advice: str
):
    leak = f"certificate is not valid for 'leak-canary.example.internal' {SENTINEL}"
    err = from_httpx(_verification_failure(code, leak), "GET", PATH)
    assert isinstance(err, SoarTLSError) and err.code == "tls"
    public = str(err) + repr(err) + json.dumps(err.to_dict())
    assert f"TLS certificate verification failed for GET {PATH}" in public and advice in public
    # The public text is ours alone: nothing from OpenSSL, the host or the request.
    assert "leak-canary" not in public and SENTINEL not in public and "handshake" not in public
    assert "verify_code" not in public
    # The way out is never "turn verification off".
    assert "SOAR_VERIFY_SSL" not in public and "false" not in public.lower()
    assert err.detail == (
        f"ConnectError; cause=SSLCertVerificationError; verify_code={code}; category={category}"
    )
    assert err.__cause__ is None and err.__context__ is None


def test_other_tls_failures_stay_generic():
    exc = httpx.ConnectError("x", request=httpx.Request("GET", "https://soar.example.internal"))
    exc.__context__ = ssl.SSLError(1, f"[SSL: WRONG_VERSION_NUMBER] {SENTINEL}")
    err = from_httpx(exc, "POST", PATH)
    assert isinstance(err, SoarTLSError)
    assert str(err) == (
        f"TLS failure connecting to SOAR for POST {PATH} "
        "(check SOAR_CA_BUNDLE, or the certificate on the appliance)"
    )
    assert err.detail == "ConnectError; cause=SSLError"
    odd = _verification_failure(None, "x")
    assert odd.__cause__ is not None
    odd.__cause__.verify_code = True  # type: ignore[attr-defined]  # not an int code
    assert "verify_code=None" in (from_httpx(odd, "GET", PATH).detail or "")


async def test_a_tls_failure_is_attempted_once_and_its_cause_is_log_only(
    caplog: pytest.LogCaptureFixture,
):
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise _verification_failure(62, f"not valid for 'leak-canary.example.internal' {SENTINEL}")

    settings = Settings.load(connection_env())
    with caplog.at_level(logging.DEBUG):
        async with SoarClient(settings, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(SoarTLSError) as info:
                await client.get(PATH)
            assert client.tls.verifies and client.tls.mode == "python_default"  # unchanged
    assert attempts == 1  # no retry of any kind, let alone an unverified one
    assert "SOAR_BASE_URL" in str(info.value) and "leak-canary" not in str(info.value)
    logged = [r.getMessage() for r in caplog.records if "tls failure" in r.getMessage()]
    assert len(logged) == 1 and "verify_code=62" in logged[0] and "host name mismatch" in logged[0]
    assert "leak-canary" not in logged[0] and SENTINEL not in logged[0]


# --------------------------------------------------------- no bypass, by AST


def _sources() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text(encoding="utf-8"))) for p in sorted(PKG.rglob("*.py"))]


def test_no_code_path_weakens_verification():
    """Contexts come from ``ssl.create_default_context()`` only, and are never loosened."""
    forbidden = {"CERT_NONE", "CERT_OPTIONAL", "_create_unverified_context", "wrap_socket"}
    forbidden |= {"_create_stdlib_context"}
    never_assigned = {"check_hostname", "verify_mode", "verify_flags", "minimum_version"}
    for path, tree in _sources():
        for node in ast.walk(tree):
            where = f"{path.name}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Attribute):
                assert node.attr not in forbidden, f"{where} uses {node.attr}"
                if node.attr in never_assigned:
                    assert isinstance(node.ctx, ast.Load), f"{where} assigns {node.attr}"
            if isinstance(node, ast.Name):
                assert node.id not in forbidden, f"{where} uses {node.id}"
            if isinstance(node, ast.Call):
                func = node.func
                called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                # ssl.SSLContext is a type annotation in tls.py; it is never constructed.
                assert called != "SSLContext", f"{where} builds a bare SSLContext"


def test_verification_is_decided_in_exactly_one_place():
    verify_keywords: list[str] = []
    build_calls: list[str] = []
    for path, tree in _sources():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "verify":
                    verify_keywords.append(f"{path.name}: {ast.unparse(kw.value)}")
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "build_trust":
                build_calls.append(path.name)
    # One HTTP client, fed by one decision; no second client with other settings.
    assert verify_keywords == ["base.py: self.tls.httpx_verify"]
    assert build_calls == ["base.py"]
    text = (PKG / "client" / "base.py").read_text(encoding="utf-8")
    assert text.count("httpx.AsyncClient(") == 1 and "retry" not in text.lower().replace(
        "no retry", ""
    )


# ------------------------------------------------------------------ stdout


async def test_tls_warnings_and_failures_never_reach_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    handler = configure_logging("DEBUG")

    def failing(request: httpx.Request) -> httpx.Response:
        raise _verification_failure(20, "unable to get local issuer certificate")

    try:
        rt = Runtime.build(
            base_env(tmp_path, SOAR_LOG_LEVEL="DEBUG", **LAB_INSECURE),
            http_transport=httpx.MockTransport(failing),
        )
        result = await run_pipeline(TOOL_REGISTRY["soar_get_incident"], rt, {"incident_id": 42})
        await rt.aclose()
    finally:
        logging.getLogger().removeHandler(handler)
    assert result["error"]["code"] == "tls" and "SOAR_CA_BUNDLE" in result["error"]["message"]
    assert out.getvalue() == ""
    assert "TLS certificate verification is DISABLED" in err.getvalue()
    assert "tls failure" in err.getvalue() and "verify_code=20" in err.getvalue()


async def test_real_stdio_server_stays_protocol_only_with_the_lab_tls_override(tmp_path: Path):
    errlog_path = tmp_path / "server-stderr.log"
    env = {
        "SOAR_AUDIT_LOG_PATH": str(tmp_path / "state" / "audit.jsonl"),
        "SOAR_APPROVAL_BROKER_PATH": str(tmp_path / "state" / "approvals"),
        "SOAR_KILL_SWITCH_FILE": str(tmp_path / "state" / "HALT"),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        **LAB_INSECURE,  # the loudest TLS state; no SOAR connection, so nothing is contacted
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "qradar_soar_mcp", "--transport", "stdio"],
        env=env,
        cwd=str(ROOT),
    )
    with errlog_path.open("w", encoding="utf-8") as errlog:
        async with (
            stdio_client(params, errlog=errlog) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()  # any stray byte on stdout breaks this handshake
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == set(TOOL_REGISTRY)
    stderr_text = errlog_path.read_text(encoding="utf-8")
    assert "TLS certificate verification is DISABLED" in stderr_text
    assert "tls=insecure" in stderr_text
