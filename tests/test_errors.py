"""P1-03: every error that crosses a layer boundary is sanitised (08 §8)."""

from __future__ import annotations

import json
import ssl

import httpx
import pytest

from qradar_soar_mcp import errors
from qradar_soar_mcp.errors import (
    SoarAuthError,
    SoarConflictError,
    SoarConnectionError,
    SoarError,
    SoarForbiddenError,
    SoarMalformedResponseError,
    SoarNotFoundError,
    SoarPatchRejectedError,
    SoarRateLimitedError,
    SoarServerError,
    SoarTimeoutError,
    SoarTLSError,
    SoarValidationError,
    from_httpx,
    from_status,
)
from tests.conftest import SENTINEL

PATH = "/rest/orgs/201/incidents/42"


def scrub(text: str) -> str:
    return text.replace(SENTINEL, "[REDACTED]")


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (401, SoarAuthError),
        (403, SoarForbiddenError),
        (404, SoarNotFoundError),
        (409, SoarConflictError),
        (400, SoarValidationError),
        (422, SoarValidationError),
        (429, SoarRateLimitedError),
        (500, SoarServerError),
        (502, SoarServerError),
        (503, SoarServerError),
        (418, SoarError),
    ],
)
def test_status_mapping_and_safe_message_shape(status: int, cls: type[SoarError]):
    err = from_status(status, "get", PATH, {"message": "soar says no"}, scrub=scrub)
    assert type(err) is cls
    assert err.status == status
    assert str(err).startswith(f"{cls.failure_class} ({status}) on GET {PATH}")
    if status not in (401, 429):
        assert str(err).endswith(": soar says no")  # useful: status class + SOAR message
    assert err.to_dict() == {"code": cls.code, "message": str(err), "http_status": status}


def test_detail_goes_to_logs_only():
    err = from_status(500, "GET", PATH, {"message": "m", "stack": "deep internals"}, scrub=scrub)
    assert err.detail is not None and "deep internals" in err.detail
    assert "deep internals" not in str(err)
    assert "deep internals" not in repr(err)
    assert "deep internals" not in json.dumps(err.to_dict())
    assert err.log_fields()["detail"] == err.detail


def test_401_keeps_the_body_out_of_output_entirely():
    err = from_status(401, "GET", PATH, {"message": f"bad key {SENTINEL}"}, scrub=scrub)
    assert SENTINEL not in str(err) and "bad key" not in str(err)
    assert SENTINEL not in (err.detail or "")  # scrubbed even in the log copy


def test_scrub_is_applied_to_message_and_detail():
    err = from_status(403, "GET", PATH, {"message": f"denied for {SENTINEL}"}, scrub=scrub)
    assert "[REDACTED]" in str(err) and SENTINEL not in str(err)
    assert SENTINEL not in (err.detail or "")


def test_query_string_and_whitespace_are_normalised():
    err = from_status(404, "GET", f"{PATH}?api_key={SENTINEL}", {"message": "a\n  b\t c"})
    assert SENTINEL not in str(err)
    assert str(err).endswith(": a b c")


def test_safe_message_is_truncated_and_detail_capped():
    err = from_status(500, "GET", PATH, {"message": "x" * 1000})
    assert len(str(err)) < 300
    err = from_status(500, "GET", PATH, {"blob": "y" * 5000})
    assert err.detail is not None and len(err.detail) == 2000


def test_message_taken_from_message_title_or_error_only_when_string():
    assert str(from_status(500, "GET", PATH, {"title": "t"})).endswith(": t")
    assert str(from_status(500, "GET", PATH, {"error": "e"})).endswith(": e")
    assert str(from_status(500, "GET", PATH, {"message": "  "})).endswith(PATH)
    assert str(from_status(500, "GET", PATH, ["list"])).endswith(PATH)
    assert str(from_status(500, "GET", PATH, "text")).endswith(PATH)
    assert from_status(500, "GET", PATH, None).detail is None


def test_unserialisable_body_still_yields_detail():
    err = from_status(500, "GET", PATH, {"obj": object()})
    assert err.detail is not None and "object" in err.detail


def _request() -> httpx.Request:
    # A request that *does* carry the secret; from_httpx must never look at it.
    return httpx.Request(
        "GET", f"https://soar.example.internal{PATH}", headers={"Authorization": SENTINEL}
    )


@pytest.mark.parametrize(
    ("exc", "cls"),
    [
        (httpx.ConnectTimeout(SENTINEL, request=_request()), SoarTimeoutError),
        (httpx.ReadTimeout(SENTINEL, request=_request()), SoarTimeoutError),
        (httpx.WriteTimeout(SENTINEL, request=_request()), SoarTimeoutError),
        (httpx.PoolTimeout(SENTINEL, request=_request()), SoarTimeoutError),
        (httpx.ConnectError(SENTINEL, request=_request()), SoarConnectionError),
        (httpx.ReadError(SENTINEL, request=_request()), SoarConnectionError),
        (httpx.WriteError(SENTINEL, request=_request()), SoarConnectionError),
        (httpx.RemoteProtocolError(SENTINEL, request=_request()), SoarConnectionError),
        (httpx.DecodingError(SENTINEL, request=_request()), SoarMalformedResponseError),
        (httpx.TooManyRedirects(SENTINEL, request=_request()), SoarConnectionError),
        (httpx.ProxyError(SENTINEL, request=_request()), SoarConnectionError),
    ],
)
def test_httpx_mapping_uses_type_only(exc: httpx.HTTPError, cls: type[SoarError]):
    err = from_httpx(exc, "GET", PATH)
    assert type(err) is cls
    assert SENTINEL not in str(err) and SENTINEL not in repr(err)
    assert err.detail == type(exc).__name__
    assert err.__cause__ is None and err.__context__ is None


def test_tls_failure_detected_through_cause_and_context_chains():
    exc = httpx.ConnectError("tls", request=_request())
    exc.__cause__ = ssl.SSLCertVerificationError(1, "CERTIFICATE_VERIFY_FAILED")
    err = from_httpx(exc, "GET", PATH)
    assert isinstance(err, SoarTLSError) and "SOAR_VERIFY_SSL" in str(err)
    exc2 = httpx.ConnectError("tls", request=_request())
    exc2.__context__ = ssl.SSLError("handshake")
    assert isinstance(from_httpx(exc2, "GET", PATH), SoarTLSError)


def test_tls_detection_survives_cyclic_chains():
    a = httpx.ConnectError("a", request=_request())
    b = RuntimeError("b")
    a.__cause__ = b
    b.__cause__ = a
    assert errors._is_tls_failure(a) is False


def test_patch_rejected_carries_field_names_only():
    err = SoarPatchRejectedError(
        "Patch rejected on PATCH /x: values changed",
        field_failures=[
            {
                "field": "severity_code",
                "your_original_value": SENTINEL,
                "actual_current_value": "High",
            },
            "junk",
        ],
        detail=f"raw {SENTINEL}",
    )
    assert isinstance(err, SoarConflictError)
    assert err.to_dict() == {
        "code": "patch_rejected",
        "message": "Patch rejected on PATCH /x: values changed",
        "http_status": 200,
        "fields": ["severity_code"],
    }
    assert SENTINEL not in json.dumps(err.to_dict())


def test_repr_and_str_without_status():
    err = SoarError("plain")
    assert str(err) == "plain"
    assert repr(err) == "SoarError(code='soar_error', status=None, message='plain')"
    assert err.to_dict() == {"code": "soar_error", "message": "plain"}
