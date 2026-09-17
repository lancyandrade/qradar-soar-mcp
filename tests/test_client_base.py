"""P1-04: the transport layer — sanitised, capped, and pinned to the Phase-1 surface."""

from __future__ import annotations

import base64
import json
import ssl

import httpx
import pytest

from qradar_soar_mcp.client.base import DEFAULT_PARAMS, MAX_RESPONSE_BYTES, SoarClient
from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.errors import (
    SoarAuthError,
    SoarConfigError,
    SoarConflictError,
    SoarConnectionError,
    SoarError,
    SoarForbiddenError,
    SoarMalformedResponseError,
    SoarNotFoundError,
    SoarPatchRejectedError,
    SoarRateLimitedError,
    SoarResponseTooLargeError,
    SoarServerError,
    SoarTimeoutError,
    SoarTLSError,
    SoarValidationError,
)
from tests.conftest import SENTINEL, connection_env
from tests.fake_soar import API_KEY_ID, FakeSoar

pytestmark = pytest.mark.contract

INC = "/rest/orgs/201/incidents/42"


@pytest.fixture
async def client(fake: FakeSoar):
    async with SoarClient(Settings.load(connection_env())) as c:
        yield c


async def test_requires_connection_settings():
    with pytest.raises(SoarConfigError):
        SoarClient(Settings.load({}))
    with pytest.raises(SoarConfigError):
        SoarClient(Settings.load(connection_env(SOAR_API_KEY_SECRET="")))


async def test_basic_auth_and_default_params_on_every_request(client: SoarClient, fake: FakeSoar):
    await client.get(INC)
    await client.post(
        "/rest/orgs/201/incidents/query_paged",
        json_body={"filters": []},
        params={"return_level": "normal"},
    )
    assert len(fake.requests) == 2
    expected = "Basic " + base64.b64encode(f"{API_KEY_ID}:{SENTINEL}".encode()).decode()
    for rec in fake.requests:
        assert rec.headers["authorization"] == expected
        for k, v in DEFAULT_PARAMS.items():
            assert rec.params[k] == v
        assert rec.headers["accept"] == "application/json"
        assert rec.headers["user-agent"].startswith("qradar-soar-mcp/")


async def test_only_get_post_patch_exist(client: SoarClient):
    assert not hasattr(client, "put") and not hasattr(client, "delete")
    with pytest.raises(SoarValidationError, match="not part of the Phase-1 contract"):
        await client.request("PUT", INC, json_body={})
    with pytest.raises(SoarValidationError, match="not part of the Phase-1 contract"):
        await client.request("DELETE", INC)


async def test_query_string_in_path_is_rejected(client: SoarClient):
    with pytest.raises(SoarValidationError, match="params="):
        await client.get(INC + "?x=1")


async def test_org_path(client: SoarClient):
    assert client.org_path("incidents/42") == "/rest/orgs/201/incidents/42"
    assert client.org_path("/incidents/42") == "/rest/orgs/201/incidents/42"


async def test_wrong_secret_is_auth_error_without_leak(fake: FakeSoar):
    s = Settings.load(connection_env(SOAR_API_KEY_SECRET="WRONG-SECRET-VALUE-0000"))
    async with SoarClient(s) as c:
        with pytest.raises(SoarAuthError) as info:
            await c.get(INC)
    err = info.value
    assert "WRONG-SECRET" not in str(err) + repr(err) + (err.detail or "")
    assert err.__cause__ is None and err.__context__ is None


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, SoarValidationError),
        (401, SoarAuthError),
        (403, SoarForbiddenError),
        (404, SoarNotFoundError),
        (409, SoarConflictError),
        (422, SoarValidationError),
        (429, SoarRateLimitedError),
        (500, SoarServerError),
        (503, SoarServerError),
        (418, SoarError),
    ],
)
async def test_status_codes_map_to_sanitised_errors(
    client: SoarClient, fake: FakeSoar, status, cls
):
    basic = base64.b64encode(f"{API_KEY_ID}:{SENTINEL}".encode()).decode()
    fake.fault(
        "GET", r"/incidents/42$", status=status, body={"message": f"nope {SENTINEL} {basic}"}
    )
    with pytest.raises(cls) as info:
        await client.get(INC)
    err = info.value
    assert err.status == status
    assert err.__cause__ is None and err.__context__ is None
    rendered = str(err) + repr(err) + json.dumps(err.to_dict()) + (err.detail or "")
    assert SENTINEL not in rendered and basic not in rendered
    assert "GET /rest/orgs/201/incidents/42" in str(err)
    assert "handle_format" not in str(err)
    if status not in (401, 429):
        assert "nope [REDACTED] [REDACTED]" in str(err)


async def test_error_with_non_json_body_is_still_mapped(client: SoarClient, fake: FakeSoar):
    fake.fault("GET", r"/incidents/42$", status=502, raw_body=b"<html>Bad Gateway</html>")
    with pytest.raises(SoarServerError) as info:
        await client.get(INC)
    assert info.value.detail is None and "html" not in str(info.value)


@pytest.mark.parametrize(
    ("exc", "cls"),
    [
        (httpx.ConnectTimeout, SoarTimeoutError),
        (httpx.ReadTimeout, SoarTimeoutError),
        (httpx.PoolTimeout, SoarTimeoutError),
        (httpx.ConnectError, SoarConnectionError),
        (httpx.ReadError, SoarConnectionError),
        (httpx.RemoteProtocolError, SoarConnectionError),
        (httpx.DecodingError, SoarMalformedResponseError),
    ],
)
async def test_transport_failures_never_chain_httpx(client: SoarClient, fake: FakeSoar, exc, cls):
    fake.fault("GET", r"/incidents/42$", exc=exc)
    with pytest.raises(cls) as info:
        await client.get(INC)
    err = info.value
    assert err.__cause__ is None and err.__context__ is None
    assert "injected" not in str(err) and SENTINEL not in str(err)


async def test_tls_failure_is_reported_as_tls():
    """respx rewrites __cause__ on side-effect exceptions, so this one uses a bare transport."""

    def handler(request: httpx.Request) -> httpx.Response:
        exc = httpx.ConnectError("tls handshake", request=request)
        exc.__cause__ = ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED")
        raise exc

    s = Settings.load(connection_env())
    async with SoarClient(s, transport=httpx.MockTransport(handler)) as c:
        with pytest.raises(SoarTLSError) as info:
            await c.get(INC)
    err = info.value
    assert err.__cause__ is None and err.__context__ is None
    assert "SOAR_VERIFY_SSL" in str(err) and "handshake" not in str(err)


async def test_malformed_json_and_empty_body(client: SoarClient, fake: FakeSoar):
    fake.fault("GET", r"/incidents/42$", status=200, raw_body=b"{not json")
    with pytest.raises(SoarMalformedResponseError):
        await client.get(INC)
    fake.fault("GET", r"/incidents/42$", status=200, raw_body=b"  \n")
    assert await client.get(INC) is None


async def test_response_size_cap_declared_and_streamed(client: SoarClient, fake: FakeSoar):
    client.max_response_bytes = 2048
    fake.fault(
        "GET", r"/incidents/42$", status=200, raw_body=b"{}", headers={"Content-Length": "999999"}
    )
    with pytest.raises(SoarResponseTooLargeError, match="declares 999999"):
        await client.get(INC)
    fake.fault(
        "GET",
        r"/incidents/42$",
        status=200,
        raw_body=b'{"pad": "' + b"x" * 5000 + b'"}',
        chunked=True,
    )
    with pytest.raises(SoarResponseTooLargeError, match="exceeded"):
        await client.get(INC)
    fake.fault("GET", r"/incidents/42$", status=200, raw_body=b'{"ok": 1}', chunked=True)
    assert await client.get(INC) == {"ok": 1}
    assert MAX_RESPONSE_BYTES == 5_000_000


# ----------------------------------------------------------------- patch


async def test_patch_object_builds_patchdto_and_raises_on_success_false(
    client: SoarClient, fake: FakeSoar
):
    current = await client.get(INC)
    result = await client.patch_object(
        INC,
        current,
        {"severity_code": "High", "triage_summary": "ok"},
        custom_fields={"triage_summary"},
    )
    sent = fake.requests[-1].json
    assert sent == {
        "version": 3,
        "changes": [
            {
                "field": {"name": "severity_code"},
                "old_value": {"object": "Medium"},
                "new_value": {"object": "High"},
            },
            {
                "field": {"name": "triage_summary"},
                "old_value": {"object": None},
                "new_value": {"object": "ok"},
            },
        ],
    }
    assert result == {
        "version": 3,
        "changes": {"severity_code": ("Medium", "High"), "triage_summary": (None, "ok")},
    }
    # Stale now: the fake bumped the version.
    with pytest.raises(SoarPatchRejectedError) as info:
        await client.patch_object(INC, current, {"description": "x"})
    assert info.value.status == 200 and "modified by another user" in str(info.value)
    assert info.value.to_dict()["code"] == "patch_rejected"


async def test_patch_object_refuses_without_integer_version(client: SoarClient):
    with pytest.raises(SoarValidationError, match="no integer 'vers'"):
        await client.patch_object(INC, {"id": 42}, {"description": "x"})
    with pytest.raises(SoarValidationError):
        await client.patch_object(INC, {"id": 42, "vers": True}, {"description": "x"})


async def test_patch_rejection_scrubs_server_text_and_lists_fields(
    client: SoarClient, fake: FakeSoar
):
    fake.fault(
        "PATCH",
        r"/incidents/42$",
        status=200,
        body={
            "success": False,
            "message": f"drift {SENTINEL}",
            "field_failures": [
                {
                    "field": "description",
                    "your_original_value": SENTINEL,
                    "actual_current_value": "z",
                }
            ],
        },
    )
    with pytest.raises(SoarPatchRejectedError) as info:
        await client.patch_object(INC, {"vers": 3, "description": "d"}, {"description": "x"})
    err = info.value
    assert SENTINEL not in str(err) + json.dumps(err.to_dict()) + (err.detail or "")
    assert err.to_dict()["fields"] == ["description"]


async def test_patch_non_dict_response_is_rejected(client: SoarClient, fake: FakeSoar):
    fake.fault("PATCH", r"/incidents/42$", status=200, body=[])
    with pytest.raises(SoarPatchRejectedError, match="success=false"):
        await client.patch_object(INC, {"vers": 3, "description": "d"}, {"description": "x"})


# ------------------------------------------------------------------ ping


async def test_ping_uses_query_paged_and_degrades_on_session_403(
    client: SoarClient, fake: FakeSoar
):
    result = await client.ping()
    assert result == {
        "reachable": True,
        "org_id": 201,
        "incidents_visible": 1,
        "identity": None,
        "session": "unavailable (403)",
    }
    first = fake.requests[0]
    assert first.method == "POST" and first.path.endswith("/incidents/query_paged")
    assert first.params["return_level"] == "normal" and first.json["length"] == 1


async def test_ping_identity_when_session_permitted():
    import respx

    from tests.fake_soar import BASE_URL

    engine = FakeSoar(session_status=200)
    with respx.mock(base_url=BASE_URL, assert_all_mocked=True) as router:
        router.route().mock(side_effect=engine.handler)
        async with SoarClient(Settings.load(connection_env())) as c:
            result = await c.ping()
    assert result["identity"] == "MCP API key" and result["session"] == "ok"


async def test_ping_fails_when_search_fails(client: SoarClient, fake: FakeSoar):
    fake.fault("POST", r"/query_paged$", status=403)
    with pytest.raises(SoarForbiddenError):
        await client.ping()
    fake.fault("POST", r"/query_paged$", status=200, body={"nope": 1})
    with pytest.raises(SoarMalformedResponseError):
        await client.ping()


# ------------------------------------------------------------------- TLS


async def test_verify_ssl_settings_are_applied(fake: FakeSoar, tmp_path, caplog):
    bogus = tmp_path / "ca.pem"
    bogus.write_text("not really a cert")
    with pytest.raises(Exception):  # noqa: B017 - ssl raises SSLError; never a silent fallback
        SoarClient(Settings.load(connection_env(SOAR_VERIFY_SSL=str(bogus))))
    with caplog.at_level("WARNING"):
        c = SoarClient(Settings.load(connection_env(SOAR_VERIFY_SSL="false")))
    await c.aclose()
    assert any("TLS verification is DISABLED" in r.getMessage() for r in caplog.records)


async def test_accessors_are_cached(client: SoarClient):
    assert client.incidents is client.incidents
    assert client.tasks is client.tasks and client.org is client.org
    assert client.artifacts is client.artifacts and client.comments is client.comments
    assert client.attachments is client.attachments and client.actions is client.actions
