"""``SoarClient``: request, ``patch_object``, ``ping``, common params (P1-04; 01 §3; 08 §4).

Everything the client package sends to SOAR goes through :meth:`SoarClient.request`,
which owns:

* HTTP Basic auth with the API key id/secret;
* ``handle_format=names`` and ``text_content_output_format=always_text`` on every call;
* TLS verification from ``SOAR_VERIFY_SSL`` (bool or CA bundle) and the timeout;
* a streamed response-size cap (08 §13);
* the mapping of every failure to a sanitised :class:`SoarError`, raised *outside*
  the ``except`` block so no ``httpx`` exception is ever chained;
* scrubbing of the credential (secret and ``Basic`` value) from any server-echoed text.

Only GET, POST and PATCH exist. There is no PUT and no DELETE (05 U7; 08 §4).
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

import httpx

from qradar_soar_mcp import __version__
from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.errors import (
    SoarConfigError,
    SoarError,
    SoarForbiddenError,
    SoarMalformedResponseError,
    SoarNotFoundError,
    SoarPatchRejectedError,
    SoarResponseTooLargeError,
    SoarValidationError,
    from_httpx,
    from_status,
)

if TYPE_CHECKING:
    from qradar_soar_mcp.client.actions import ActionsClient
    from qradar_soar_mcp.client.artifacts import ArtifactsClient
    from qradar_soar_mcp.client.attachments import AttachmentsClient
    from qradar_soar_mcp.client.comments import CommentsClient
    from qradar_soar_mcp.client.incidents import IncidentsClient
    from qradar_soar_mcp.client.org import OrgClient
    from qradar_soar_mcp.client.tasks import TasksClient

logger = logging.getLogger(__name__)

DEFAULT_PARAMS: dict[str, str] = {
    "handle_format": "names",
    "text_content_output_format": "always_text",
}
QUERY_PAGED_PARAMS: dict[str, str] = {"return_level": "normal"}
# Internal cap, not a flag (08 §14): a SOAR response larger than this is an error.
MAX_RESPONSE_BYTES = 5_000_000

JSON = Any


@dataclass(frozen=True, slots=True)
class PatchOutcome:
    """What a PATCH did: the audit pre-/post-images and the applied changes."""

    path: str
    version_before: int
    pre_image: dict[str, Any]
    post_image: dict[str, Any] | None
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)


class SoarClient:
    """Async client bound to one org. Use as an async context manager."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        org_id = settings.org_id
        if not settings.connection_ready or org_id is None:
            raise SoarConfigError(
                "SOAR connection is not configured: set SOAR_BASE_URL, SOAR_ORG_ID, "
                "SOAR_API_KEY_ID and SOAR_API_KEY_SECRET"
            )
        self.settings = settings
        self.org_id: int = org_id
        self.max_response_bytes = MAX_RESPONSE_BYTES
        secret = settings.api_key_secret.get_secret_value()
        basic = base64.b64encode(f"{settings.api_key_id}:{secret}".encode()).decode()
        # Anything the server (or a proxy) could echo that identifies the credential.
        self._sensitive: tuple[str, ...] = (secret, basic)
        verify: bool | ssl.SSLContext
        if isinstance(settings.verify_ssl, bool):
            verify = settings.verify_ssl
            if not verify:
                logger.warning("TLS verification is DISABLED (SOAR_VERIFY_SSL=false)")
        else:
            # Raises at startup if the bundle is unreadable; never falls back silently.
            verify = ssl.create_default_context(cafile=str(settings.verify_ssl))
        self._http = httpx.AsyncClient(
            base_url=settings.base_url_clean,
            auth=(settings.api_key_id, secret),
            verify=verify,
            timeout=settings.timeout,
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "User-Agent": f"qradar-soar-mcp/{__version__}",
            },
            transport=transport,
        )
        self._accessors: dict[str, Any] = {}

    # ---------------------------------------------------------------- scrub
    def scrub(self, text: str | None) -> str | None:
        """Remove the credential from server-supplied text before it goes anywhere."""
        if not text:
            return text
        for value in self._sensitive:
            if value and value in text:
                text = text.replace(value, "[REDACTED]")
        return text

    def _scrub_str(self, text: str) -> str:
        return self.scrub(text) or ""

    # ---------------------------------------------------------------- paths
    def org_path(self, suffix: str) -> str:
        suffix = suffix.lstrip("/")
        return f"/rest/orgs/{self.org_id}/{suffix}"

    # -------------------------------------------------------------- request
    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: JSON | None = None,
    ) -> JSON:
        """Perform a request and return the parsed JSON body (``None`` if empty).

        Raises:
            SoarError: for any HTTP status >= 400, any transport failure, an
                undecodable body, or a body larger than the cap.
        """
        method = method.upper()
        if method not in {"GET", "POST", "PATCH"}:
            raise SoarValidationError(f"HTTP method {method} is not part of the Phase-1 contract")
        if "?" in path:
            raise SoarValidationError("pass query parameters via params=, not in the path")
        merged: dict[str, Any] = {**DEFAULT_PARAMS, **(params or {})}
        failure: SoarError | None = None
        status = 0
        raw = b""
        try:
            async with self._http.stream(method, path, params=merged, json=json_body) as response:
                status = response.status_code
                declared = response.headers.get("Content-Length")
                if (
                    declared is not None
                    and declared.isdigit()
                    and int(declared) > self.max_response_bytes
                ):
                    failure = SoarResponseTooLargeError(
                        f"Response too large on {method} {path}: declares {declared} bytes; "
                        f"cap is {self.max_response_bytes}"
                    )
                else:
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > self.max_response_bytes:
                            failure = SoarResponseTooLargeError(
                                f"Response too large on {method} {path}: exceeded the "
                                f"{self.max_response_bytes}-byte cap"
                            )
                            break
                        chunks.append(chunk)
                    raw = b"".join(chunks)
        except httpx.HTTPError as exc:
            # Map by type only; the exception is dropped here and never chained.
            failure = from_httpx(exc, method, path)
        if failure is not None:
            logger.debug("soar %s %s -> %s", method, path, failure.code)
            raise failure

        body: JSON = None
        decode_error = False
        if raw.strip():
            try:
                body = json.loads(raw)
            except ValueError:
                decode_error = True

        if status >= 400:
            failure = from_status(
                status, method, path, None if decode_error else body, scrub=self._scrub_str
            )
            logger.debug("soar %s %s -> HTTP %s (%s)", method, path, status, failure.code)
            raise failure
        if decode_error:
            raise SoarMalformedResponseError(
                f"Malformed response on {method} {path} (HTTP {status}): not JSON", status=status
            )
        logger.debug("soar %s %s -> HTTP %s", method, path, status)
        return body

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> JSON:
        return await self.request("GET", path, params=params)

    async def post(
        self, path: str, *, json_body: JSON | None = None, params: Mapping[str, Any] | None = None
    ) -> JSON:
        return await self.request("POST", path, params=params, json_body=json_body)

    async def patch(self, path: str, *, json_body: JSON) -> JSON:
        return await self.request("PATCH", path, json_body=json_body)

    # ---------------------------------------------------------------- patch
    async def patch_object(
        self,
        path: str,
        current: Mapping[str, Any],
        changes: Mapping[str, Any],
        *,
        custom_fields: frozenset[str] | set[str] = frozenset(),
        version_key: str = "vers",
    ) -> dict[str, Any]:
        """Build a PatchDTO from ``current`` and PATCH it; raise on ``success: false``.

        ``changes`` maps a bare field name to its new value. Names in
        ``custom_fields`` are read from ``current["properties"]`` for the old value.
        SOAR wants the bare name in ``field.name`` either way (05 §1.1).
        """
        version = current.get(version_key)
        if not isinstance(version, int) or isinstance(version, bool):
            raise SoarValidationError(
                f"object at {path} carries no integer {version_key!r}; cannot PATCH safely"
            )
        dto_changes: list[dict[str, Any]] = []
        applied: dict[str, tuple[Any, Any]] = {}
        for name, new_value in changes.items():
            if name in custom_fields:
                props = current.get("properties")
                old_value = props.get(name) if isinstance(props, Mapping) else None
            else:
                old_value = current.get(name)
            dto_changes.append(
                {
                    "field": {"name": name},
                    "old_value": {"object": old_value},
                    "new_value": {"object": new_value},
                }
            )
            applied[name] = (old_value, new_value)
        response = await self.patch(path, json_body={"version": version, "changes": dto_changes})
        if not isinstance(response, dict) or response.get("success") is not True:
            message = response.get("message") if isinstance(response, dict) else None
            failures = response.get("field_failures") if isinstance(response, dict) else None
            text = self._scrub_str(" ".join(str(message).split())) if message else "success=false"
            raise SoarPatchRejectedError(
                f"Patch rejected on PATCH {path}: {text[:200]}",
                field_failures=failures if isinstance(failures, list) else [],
                detail=self.scrub(json.dumps(response, default=str)),
            )
        return {"version": version, "changes": applied}

    # ----------------------------------------------------------------- ping
    async def ping(self) -> dict[str, Any]:
        """Reachability via the same ``query_paged`` endpoint search uses (00 §1.2).

        A green result means search actually works. ``/rest/session`` is
        optional and commonly 403 for API keys; that is reported, not raised.
        """
        body = await self.post(
            self.org_path("incidents/query_paged"),
            json_body={"filters": [], "start": 0, "length": 1},
            params=QUERY_PAGED_PARAMS,
        )
        if not isinstance(body, dict) or "data" not in body:
            raise SoarMalformedResponseError("query_paged did not return a paged result")
        result: dict[str, Any] = {
            "reachable": True,
            "org_id": self.org_id,
            "incidents_visible": body.get("recordsTotal"),
            "identity": None,
            "session": "ok",
        }
        try:
            session = await self.get("/rest/session")
        except (SoarForbiddenError, SoarNotFoundError) as exc:
            result["session"] = f"unavailable ({exc.status})"
        else:
            if isinstance(session, dict):
                result["identity"] = session.get("user_display_name") or session.get("user_email")
        return result

    # ------------------------------------------------------------ accessors
    def _accessor(self, name: str, factory: Any) -> Any:
        if name not in self._accessors:
            self._accessors[name] = factory(self)
        return self._accessors[name]

    @property
    def org(self) -> OrgClient:
        from qradar_soar_mcp.client.org import OrgClient

        return self._accessor("org", OrgClient)  # type: ignore[no-any-return]

    @property
    def incidents(self) -> IncidentsClient:
        from qradar_soar_mcp.client.incidents import IncidentsClient

        return self._accessor("incidents", IncidentsClient)  # type: ignore[no-any-return]

    @property
    def tasks(self) -> TasksClient:
        from qradar_soar_mcp.client.tasks import TasksClient

        return self._accessor("tasks", TasksClient)  # type: ignore[no-any-return]

    @property
    def artifacts(self) -> ArtifactsClient:
        from qradar_soar_mcp.client.artifacts import ArtifactsClient

        return self._accessor("artifacts", ArtifactsClient)  # type: ignore[no-any-return]

    @property
    def comments(self) -> CommentsClient:
        from qradar_soar_mcp.client.comments import CommentsClient

        return self._accessor("comments", CommentsClient)  # type: ignore[no-any-return]

    @property
    def attachments(self) -> AttachmentsClient:
        from qradar_soar_mcp.client.attachments import AttachmentsClient

        return self._accessor("attachments", AttachmentsClient)  # type: ignore[no-any-return]

    @property
    def actions(self) -> ActionsClient:
        from qradar_soar_mcp.client.actions import ActionsClient

        return self._accessor("actions", ActionsClient)  # type: ignore[no-any-return]

    # ------------------------------------------------------------ lifecycle
    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


def text_content(text: str) -> dict[str, str]:
    """A TextContentDTO for comment/description bodies."""
    return {"format": "text", "content": text}
