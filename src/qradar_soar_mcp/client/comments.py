"""Incident comments (notes): list and add."""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import SoarClient, text_content
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarValidationError

MAX_COMMENT_LENGTH = 20_000


class CommentsClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/comments"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /comments did not return a list")
        return [c for c in body if isinstance(c, dict)]

    async def add(
        self, incident_id: int, text: str, *, parent_id: int | None = None
    ) -> dict[str, Any]:
        if not text.strip():
            raise SoarValidationError("comment text is empty")
        if len(text) > MAX_COMMENT_LENGTH:
            raise SoarValidationError(f"comment text exceeds {MAX_COMMENT_LENGTH} characters")
        body: dict[str, Any] = {"text": text_content(text)}
        if parent_id is not None:
            body["parent_id"] = int(parent_id)
        resp = await self._c.post(
            self._c.org_path(f"incidents/{int(incident_id)}/comments"), json_body=body
        )
        if not isinstance(resp, dict) or "id" not in resp:
            raise SoarMalformedResponseError("POST /comments did not return a comment")
        return resp
