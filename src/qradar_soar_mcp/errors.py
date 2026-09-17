"""The only exceptions that cross layer boundaries (P1-03; 02 §7; 08 §8).

Every :class:`SoarError` carries two texts:

* ``safe_message`` — goes to MCP output. Failure class, HTTP status, the
  request method and *path* (never host, query or headers), and a redacted,
  truncated copy of SOAR's own ``message`` where one is useful.
* ``detail`` — goes to logs only. It never appears in ``str()``, ``repr()``
  or :meth:`to_dict`.

``httpx`` exceptions carry the ``Request``, which carries the ``Authorization``
header. :func:`from_httpx` reads the exception's *type* and nothing else, and
callers raise the result outside their ``except`` block so no ``httpx``
exception is ever chained (``__cause__`` and ``__context__`` stay ``None``).
"""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from typing import Any

import httpx

_MAX_SAFE_MESSAGE = 200
_MAX_DETAIL = 2000


def _identity(text: str) -> str:
    return text


class SoarError(Exception):
    """Base class. ``code`` is stable and safe to return to the MCP client."""

    code: str = "soar_error"
    failure_class: str = "SOAR error"

    def __init__(
        self,
        safe_message: str,
        *,
        status: int | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.status = status
        self.detail = detail[:_MAX_DETAIL] if detail else None

    def __str__(self) -> str:
        return self.safe_message

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code!r}, status={self.status!r}, "
            f"message={self.safe_message!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        """The MCP-facing shape. Never includes ``detail``."""
        out: dict[str, Any] = {"code": self.code, "message": self.safe_message}
        if self.status is not None:
            out["http_status"] = self.status
        return out

    def log_fields(self) -> dict[str, Any]:
        """For the (redacting) logger only."""
        return {"code": self.code, "status": self.status, "detail": self.detail}


class SoarConfigError(SoarError):
    code = "not_configured"
    failure_class = "Not configured"


class SoarAuthError(SoarError):
    code = "auth_failed"
    failure_class = "Authentication failed"


class SoarForbiddenError(SoarError):
    code = "forbidden"
    failure_class = "Forbidden"


class SoarNotFoundError(SoarError):
    code = "not_found"
    failure_class = "Not found"


class SoarConflictError(SoarError):
    """Optimistic-concurrency failure: the object changed under us."""

    code = "conflict"
    failure_class = "Conflict"


class SoarPatchRejectedError(SoarConflictError):
    """SOAR answered a PATCH with HTTP 200 and ``success: false``.

    That is how SOAR reports a stale ``version``, a drifted ``old_value`` or a
    validation rule such as close-required fields (05 §1.1). Never swallowed.
    """

    code = "patch_rejected"
    failure_class = "Patch rejected"

    def __init__(
        self,
        safe_message: str,
        *,
        field_failures: list[dict[str, Any]] | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(safe_message, status=200, detail=detail)
        self.field_failures = field_failures or []

    def to_dict(self) -> dict[str, Any]:
        out = super().to_dict()
        if self.field_failures:
            out["fields"] = [
                str(f.get("field")) for f in self.field_failures if isinstance(f, dict)
            ]
        return out


class SoarValidationError(SoarError):
    """SOAR rejected the request (400/422), or the client refused to send it."""

    code = "validation"
    failure_class = "Validation failed"


class SoarRateLimitedError(SoarError):
    code = "soar_rate_limited"
    failure_class = "Rate limited by SOAR"


class SoarServerError(SoarError):
    code = "server_error"
    failure_class = "SOAR server error"


class SoarTimeoutError(SoarError):
    code = "timeout"
    failure_class = "Timeout"


class SoarTLSError(SoarError):
    code = "tls"
    failure_class = "TLS failure"


class SoarConnectionError(SoarError):
    code = "connection"
    failure_class = "Connection failure"


class SoarMalformedResponseError(SoarError):
    code = "malformed_response"
    failure_class = "Malformed response"


class SoarResponseTooLargeError(SoarError):
    code = "response_too_large"
    failure_class = "Response too large"


# ----------------------------------------------------------------- factories
def _where(method: str, path: str) -> str:
    # Defensive: strip anything after '?' even though callers pass a bare path.
    return f"{method.upper()} {path.split('?', 1)[0]}"


def _soar_message(body: Any) -> str | None:
    if isinstance(body, dict):
        for key in ("message", "title", "error"):
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return " ".join(value.split())
    return None


def from_status(
    status: int,
    method: str,
    path: str,
    body: Any = None,
    *,
    scrub: Callable[[str], str] = _identity,
) -> SoarError:
    """Map an HTTP status to a sanitised error.

    ``scrub`` removes the caller's credential from any server-supplied text
    (the client passes its own scrubber). SOAR's ``message`` is included in
    ``safe_message`` (redacted, truncated) except for 401, where the body is
    about the credential and is kept out of MCP output entirely.
    """
    where = _where(method, path)
    message = _soar_message(body)
    detail: str | None = None
    if body is not None:
        try:
            detail = scrub(json.dumps(body, default=str))
        except (TypeError, ValueError):
            detail = scrub(str(body))

    def build(cls: type[SoarError], *, include_message: bool = True) -> SoarError:
        text = f"{cls.failure_class} ({status}) on {where}"
        if include_message and message:
            text += ": " + scrub(message)[:_MAX_SAFE_MESSAGE]
        return cls(text, status=status, detail=detail)

    if status == 401:
        return build(SoarAuthError, include_message=False)
    if status == 403:
        return build(SoarForbiddenError)
    if status == 404:
        return build(SoarNotFoundError)
    if status == 409:
        return build(SoarConflictError)
    if status in (400, 422):
        return build(SoarValidationError)
    if status == 429:
        return build(SoarRateLimitedError, include_message=False)
    if status >= 500:
        return build(SoarServerError)
    return build(SoarError)


def from_httpx(exc: httpx.HTTPError, method: str, path: str) -> SoarError:
    """Map a transport-level ``httpx`` failure by *type only*.

    The exception's message is deliberately not used: it can include the URL
    and, for some error types, fragments of request state. ``detail`` records
    only the exception class name.
    """
    where = _where(method, path)
    detail = type(exc).__name__
    if isinstance(exc, httpx.TimeoutException):
        return SoarTimeoutError(f"Timeout waiting for SOAR on {where}", detail=detail)
    if isinstance(exc, httpx.ConnectError):
        if _is_tls_failure(exc):
            return SoarTLSError(
                f"TLS failure connecting to SOAR for {where} "
                "(check SOAR_VERIFY_SSL, or the certificate on the appliance)",
                detail=detail,
            )
        return SoarConnectionError(f"Could not connect to SOAR for {where}", detail=detail)
    if isinstance(exc, httpx.RemoteProtocolError | httpx.ReadError | httpx.WriteError):
        return SoarConnectionError(f"Connection to SOAR dropped during {where}", detail=detail)
    if isinstance(exc, httpx.DecodingError):
        return SoarMalformedResponseError(
            f"SOAR returned an undecodable body for {where}", detail=detail
        )
    if isinstance(exc, httpx.TooManyRedirects):
        return SoarConnectionError(f"Too many redirects on {where}", detail=detail)
    return SoarConnectionError(f"Transport failure on {where}", detail=detail)


def _is_tls_failure(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return True
        # httpx wraps the underlying error in ``__cause__`` / ``__context__``.
        current = current.__cause__ or current.__context__
    return False
