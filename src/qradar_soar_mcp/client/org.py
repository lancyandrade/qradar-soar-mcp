"""Org-level reads: incident field definitions and users (Phase-1 subset of 01 §3 ``org.py``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.errors import SoarMalformedResponseError

PROPERTIES_PREFIX = "properties"


@dataclass(frozen=True, slots=True)
class FieldDef:
    name: str
    text: str
    input_type: str
    prefix: str | None
    required: str | None  # None | "always" | "close"
    read_only: bool
    internal: bool
    values: tuple[tuple[Any, str], ...]  # (value, label) for select-type fields

    @property
    def in_properties(self) -> bool:
        return self.prefix == PROPERTIES_PREFIX

    @property
    def api_name(self) -> str:
        """The name a caller uses: ``properties.<name>`` for custom fields."""
        return f"{PROPERTIES_PREFIX}.{self.name}" if self.in_properties else self.name

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(label for _, label in self.values)

    @property
    def close_required(self) -> bool:
        return self.required == "close"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "api_name": self.api_name,
            "label": self.text,
            "input_type": self.input_type,
            "custom": self.in_properties,
            "required": self.required,
            "close_required": self.close_required,
            "read_only": self.read_only,
        }
        if self.values:
            out["values"] = list(self.labels)
        return out

    @classmethod
    def from_dto(cls, dto: dict[str, Any]) -> FieldDef:
        values: list[tuple[Any, str]] = []
        for v in dto.get("values") or []:
            if isinstance(v, dict) and v.get("enabled", True) and "label" in v:
                values.append((v.get("value"), str(v["label"])))
        return cls(
            name=str(dto["name"]),
            text=str(dto.get("text") or dto["name"]),
            input_type=str(dto.get("input_type") or "unknown"),
            prefix=dto.get("prefix"),
            required=dto.get("required"),
            read_only=bool(dto.get("read_only", False)),
            internal=bool(dto.get("internal", False)),
            values=tuple(values),
        )


def resolve_field(fields: list[FieldDef], api_name: str) -> FieldDef | None:
    """Find a field by ``name`` or ``properties.name``; a wrong prefix never resolves."""
    wants_custom = api_name.startswith(PROPERTIES_PREFIX + ".")
    bare = api_name.split(".", 1)[1] if wants_custom else api_name
    for f in fields:
        if f.name == bare and f.in_properties == wants_custom:
            return f
    if not wants_custom:
        # Be forgiving about a custom field given without its prefix, never the reverse.
        for f in fields:
            if f.name == bare and f.in_properties:
                return f
    return None


class OrgClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def incident_fields(self) -> list[FieldDef]:
        body = await self._c.get(self._c.org_path("types/incident/fields"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /types/incident/fields did not return a list")
        return [FieldDef.from_dto(dto) for dto in body if isinstance(dto, dict) and "name" in dto]

    async def users(self) -> list[dict[str, Any]]:
        body = await self._c.get(self._c.org_path("users"))
        if not isinstance(body, list):
            raise SoarMalformedResponseError("GET /users did not return a list")
        return [
            {
                "id": u.get("id"),
                "display_name": u.get("display_name")
                or " ".join(str(p) for p in (u.get("fname"), u.get("lname")) if p),
                "email": u.get("email"),
                "status": u.get("status"),
            }
            for u in body
            if isinstance(u, dict)
        ]
