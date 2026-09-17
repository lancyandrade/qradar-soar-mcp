"""Incidents: get, search, create, and ``apply_patch`` with optimistic concurrency.

``apply_patch`` is the helper 00 §1.2 describes: GET → build PatchDTO →
PATCH → raise on ``success: false``. Closing (05 §1.1) sends ``plan_status``,
``resolution_id`` and ``resolution_summary`` together; SOAR itself rejects the
close if a close-required custom field is empty and that rejection is raised,
never swallowed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from qradar_soar_mcp.client.base import QUERY_PAGED_PARAMS, PatchOutcome, SoarClient, text_content
from qradar_soar_mcp.client.org import FieldDef, resolve_field
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarValidationError

SEARCH_METHODS = frozenset(
    {
        "equals",
        "not_equals",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "gte",
        "gt",
        "lte",
        "lt",
        "has_a_value",
        "does_not_have_a_value",
    }
)
Condition = Mapping[str, Any]


class IncidentsClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    # ------------------------------------------------------------------ read
    async def get(self, incident_id: int) -> dict[str, Any]:
        body = await self._c.get(self._c.org_path(f"incidents/{int(incident_id)}"))
        if not isinstance(body, dict):
            raise SoarMalformedResponseError("GET /incidents/{id} did not return an object")
        return body

    async def search(
        self,
        *,
        filters: list[list[Condition]] | None = None,
        sorts: list[Mapping[str, Any]] | None = None,
        start: int = 0,
        length: int | None = None,
    ) -> dict[str, Any]:
        """``POST /incidents/query_paged?return_level=normal``.

        ``filters`` is a list of filter groups; conditions inside a group are
        ANDed, groups are ORed (05 §1.1). ``length`` is capped by
        ``SOAR_MAX_RESULTS``.
        """
        groups: list[dict[str, Any]] = []
        for group in filters or []:
            conditions: list[dict[str, Any]] = []
            for cond in group:
                method = cond.get("method")
                if method not in SEARCH_METHODS:
                    raise SoarValidationError(f"unsupported search method {method!r}")
                name = cond.get("field_name")
                if not isinstance(name, str) or not name:
                    raise SoarValidationError("search condition needs a field_name")
                item: dict[str, Any] = {"field_name": name, "method": method}
                if "value" in cond:
                    item["value"] = cond["value"]
                conditions.append(item)
            if conditions:
                groups.append({"conditions": conditions})
        for sort in sorts or []:
            if sort.get("type") not in {"asc", "desc"} or not sort.get("field_name"):
                raise SoarValidationError("sort needs field_name and type asc|desc")
        cap = self._c.settings.max_results
        start = max(0, int(start))
        length = cap if length is None else max(1, min(int(length), cap))
        body = {
            "filters": groups,
            "sorts": [dict(s) for s in sorts or []],
            "start": start,
            "length": length,
        }
        resp = await self._c.post(
            self._c.org_path("incidents/query_paged"), json_body=body, params=QUERY_PAGED_PARAMS
        )
        if not isinstance(resp, dict) or not isinstance(resp.get("data"), list):
            raise SoarMalformedResponseError("query_paged did not return data")
        return {
            "total": resp.get("recordsTotal"),
            "filtered": resp.get("recordsFiltered"),
            "start": start,
            "length": length,
            "items": resp["data"],
        }

    # ---------------------------------------------------------------- create
    async def create(
        self,
        *,
        name: str,
        discovered_date_ms: int,
        description: str | None = None,
        incident_type_ids: list[str] | None = None,
        severity_code: str | None = None,
        owner_id: str | None = None,
        properties: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not name.strip():
            raise SoarValidationError("incident name is required")
        body: dict[str, Any] = {"name": name, "discovered_date": int(discovered_date_ms)}
        if description is not None:
            body["description"] = text_content(description)
        if incident_type_ids:
            body["incident_type_ids"] = list(incident_type_ids)
        if severity_code is not None:
            body["severity_code"] = severity_code
        if owner_id is not None:
            body["owner_id"] = owner_id
        if properties:
            body["properties"] = dict(properties)
        resp = await self._c.post(self._c.org_path("incidents"), json_body=body)
        if not isinstance(resp, dict) or "id" not in resp:
            raise SoarMalformedResponseError("POST /incidents did not return an incident")
        return resp

    # ----------------------------------------------------------------- patch
    async def apply_patch(self, incident_id: int, changes: Mapping[str, Any]) -> PatchOutcome:
        """Change fields on one incident under optimistic concurrency.

        Field names may be bare or ``properties.<name>``. Every field is checked
        against the org's definitions (exists, writable, select values valid)
        before anything is sent. Returns pre- and post-images for the audit log.
        """
        if not changes:
            raise SoarValidationError("no changes given")
        fields = await self._c.org.incident_fields()
        normalised, custom = self._normalise(fields, changes)
        current = await self.get(incident_id)
        path = self._c.org_path(f"incidents/{int(incident_id)}")
        result = await self._c.patch_object(path, current, normalised, custom_fields=custom)
        post = await self.get(incident_id)
        return PatchOutcome(
            path=path,
            version_before=int(result["version"]),
            pre_image=current,
            post_image=post,
            changes=dict(result["changes"]),
        )

    @staticmethod
    def _normalise(
        fields: list[FieldDef], changes: Mapping[str, Any]
    ) -> tuple[dict[str, Any], set[str]]:
        normalised: dict[str, Any] = {}
        custom: set[str] = set()
        for api_name, value in changes.items():
            fdef = resolve_field(fields, api_name)
            if fdef is None:
                raise SoarValidationError(f"unknown incident field {api_name!r}")
            if fdef.read_only or fdef.internal:
                raise SoarValidationError(f"field {fdef.api_name!r} is read-only")
            if fdef.values and value is not None:
                # With handle_format=names most selects carry labels, but some carry
                # their raw codes (plan_status is "A"/"C", 05 §1.1): accept either.
                raw_values = {v for v, _ in fdef.values}
                candidates = value if isinstance(value, list) else [value]
                for candidate in candidates:
                    if candidate not in fdef.labels and candidate not in raw_values:
                        raise SoarValidationError(
                            f"{candidate!r} is not a valid value for {fdef.api_name!r}; "
                            f"choose one of {list(fdef.labels)}"
                        )
            if fdef.name in normalised:
                raise SoarValidationError(f"field {fdef.api_name!r} given twice")
            normalised[fdef.name] = value
            if fdef.in_properties:
                custom.add(fdef.name)
        return normalised, custom

    async def assign(self, incident_id: int, owner: str) -> PatchOutcome:
        if not owner.strip():
            raise SoarValidationError("owner is required")
        return await self.apply_patch(incident_id, {"owner_id": owner})

    async def close(
        self,
        incident_id: int,
        *,
        resolution: str,
        summary: str,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> PatchOutcome:
        """Close with ``plan_status`` + ``resolution_id`` + ``resolution_summary`` together.

        ``extra_fields`` carries any close-required custom fields the operator
        must fill; SOAR rejects the close otherwise and that is surfaced.
        """
        if not resolution.strip() or not summary.strip():
            raise SoarValidationError(
                "closing requires a resolution and a resolution summary (05 §1.1)"
            )
        changes: dict[str, Any] = dict(extra_fields or {})
        for key in ("plan_status", "resolution_id", "resolution_summary"):
            if key in changes:
                raise SoarValidationError(
                    f"{key} is set by close(); do not pass it in extra_fields"
                )
        changes.update(
            {"plan_status": "C", "resolution_id": resolution, "resolution_summary": summary}
        )
        return await self.apply_patch(incident_id, changes)
