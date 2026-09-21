"""Read-only configuration discovery for the catalog (P2-01; 08 §25).

Every call here was verified on QRadar SOAR 51.0.9.0.20848 with a read-only API key
(``docs/soar-api-verified.md`` §1 Q1, Q4, Q5 and §2), and each method checks the one
thing it relies on: the wrapper that call was seen to answer with. The wrappers differ,
so there is no generic one: ``entities`` for functions, rules, scripts, workflows,
message destinations and phases; a bare list for groups and field definitions; a
name-keyed map for types and incident types; ``data`` with paging totals for the
playbook query.

Nothing here writes. The one POST is the playbook query, which is how this version
lists playbooks (a GET on the collection answers 500): its body is built here, from two
integers, in the criteria-only form that was verified (``filters`` empty, ``start``,
``length``; sent live from start 0 with lengths 1 and 10). No caller supplies a filter, a
path or a method. The configuration export is not among these calls.
"""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.client.base import QUERY_PAGED_PARAMS, SoarClient
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarValidationError

# Field definitions are read for exactly these types (the ledger of the verified record).
FIELD_TYPES: tuple[str, ...] = ("incident", "task", "artifact")
MAX_PLAYBOOK_PAGE = 100

Row = dict[str, Any]


def _rows(items: Any, where: str) -> list[Row]:
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise SoarMalformedResponseError(f"{where} did not return a list of objects")
    return items


def _entities(body: Any, where: str) -> list[Row]:
    if not isinstance(body, dict) or "entities" not in body:
        raise SoarMalformedResponseError(f"{where} did not return an entities wrapper")
    return _rows(body["entities"], where)


def _named_map(body: Any, where: str) -> dict[str, Row]:
    if not isinstance(body, dict) or not all(isinstance(v, dict) for v in body.values()):
        raise SoarMalformedResponseError(f"{where} did not return a name-keyed map")
    return body


class DiscoveryClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def server_version(self) -> str:
        """The version string the server reports about itself."""
        body = await self._c.get("/rest/const")
        version = body.get("server_version") if isinstance(body, dict) else None
        text = version.get("version") if isinstance(version, dict) else None
        if not isinstance(text, str) or not text:
            raise SoarMalformedResponseError("GET /rest/const did not report a server version")
        return text

    # ------------------------------------------------------ entities wrappers
    async def functions(self) -> list[Row]:
        """List rows. Their ``view_items`` is empty; :meth:`function` has the real one."""
        body = await self._c.get(self._c.org_path("functions"))
        return _entities(body, "GET /functions")

    async def function(self, function_id: int) -> Row:
        body = await self._c.get(self._c.org_path(f"functions/{int(function_id)}"))
        if not isinstance(body, dict):
            raise SoarMalformedResponseError("GET /functions/{id} did not return an object")
        return body

    async def rules(self) -> list[Row]:
        """Rules are ``actions`` in the API (05 §2)."""
        body = await self._c.get(self._c.org_path("actions"))
        return _entities(body, "the rule collection (GET actions)")

    async def scripts(self) -> list[Row]:
        """List rows: no script body."""
        return _entities(await self._c.get(self._c.org_path("scripts")), "GET /scripts")

    async def workflows(self) -> list[Row]:
        return _entities(await self._c.get(self._c.org_path("workflows")), "GET /workflows")

    async def message_destinations(self) -> list[Row]:
        body = await self._c.get(self._c.org_path("message_destinations"))
        return _entities(body, "GET /message_destinations")

    async def phases(self) -> list[Row]:
        return _entities(await self._c.get(self._c.org_path("phases")), "GET /phases")

    # ------------------------------------------------------------- bare lists
    async def groups(self) -> list[Row]:
        return _rows(await self._c.get(self._c.org_path("groups")), "GET /groups")

    async def function_fields(self) -> list[Row]:
        """The ``__function`` field definitions a function's ``view_items`` point at."""
        body = await self._c.get(self._c.org_path("types/__function/fields"))
        return _rows(body, "GET /types/__function/fields")

    async def type_fields(self, type_name: str) -> list[Row]:
        if type_name == "incident":
            body = await self._c.get(self._c.org_path("types/incident/fields"))
        elif type_name == "task":
            body = await self._c.get(self._c.org_path("types/task/fields"))
        elif type_name == "artifact":
            body = await self._c.get(self._c.org_path("types/artifact/fields"))
        else:
            raise SoarValidationError(
                f"field definitions are read for {', '.join(FIELD_TYPES)} only", not_sent=True
            )
        return _rows(body, f"GET /types/{type_name}/fields")

    # ------------------------------------------------------- name-keyed maps
    async def types(self) -> dict[str, Row]:
        """Every type, data tables included (``type_id == 8``), keyed by type name."""
        return _named_map(await self._c.get(self._c.org_path("types")), "GET /types")

    async def incident_types(self) -> dict[str, Row]:
        body = await self._c.get(self._c.org_path("incident_types"))
        return _named_map(body, "GET /incident_types")

    # ------------------------------------------------------------ paged query
    async def playbooks_page(self, *, start: int, length: int) -> dict[str, Any]:
        """One page of ``POST /playbooks/query_paged?return_level=normal``."""
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (start, length)):
            raise SoarValidationError("playbook paging takes integers", not_sent=True)
        if start < 0:
            raise SoarValidationError("playbook paging starts at 0 or later", not_sent=True)
        if not 1 <= length <= MAX_PLAYBOOK_PAGE:
            raise SoarValidationError(
                f"a playbook page holds 1 to {MAX_PLAYBOOK_PAGE} rows", not_sent=True
            )
        body = await self._c.post(
            self._c.org_path("playbooks/query_paged"),
            json_body={"filters": [], "start": int(start), "length": int(length)},
            params=QUERY_PAGED_PARAMS,
        )
        if not isinstance(body, dict) or "data" not in body:
            raise SoarMalformedResponseError(
                "POST /playbooks/query_paged did not return a paged result"
            )
        total = body.get("recordsTotal")
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise SoarMalformedResponseError(
                "POST /playbooks/query_paged did not return recordsTotal"
            )
        return {"items": _rows(body["data"], "POST /playbooks/query_paged"), "total": total}
