"""Attachment *metadata* only. Contents are ⚠️ (05 §1.2) and deferred to P2-00 (08 §9)."""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.errors import SoarMalformedResponseError


class AttachmentsClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list(self, incident_id: int) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}/attachments"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /attachments did not return a list")
        return [
            {
                "id": a.get("id"),
                "name": a.get("name"),
                "size": a.get("size"),
                "content_type": a.get("content_type"),
                "created": a.get("created"),
            }
            for a in body
            if isinstance(a, dict)
        ]
