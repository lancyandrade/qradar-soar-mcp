"""Manual actions available on an incident: the list the incident object carries.

On QRadar SOAR 51.0.9.0.20848 (docs/soar-api-verified.md §3, D3/D4; 08 §21):

* ``GET /incidents/{id}/actions`` is undocumented and answers 500, so it is not
  used. The incident, task and artifact objects each carry an ``actions`` list;
  the incident's own list, from the verified ``GET /incidents/{id}``, is the
  source here.
* That list was empty on the verified appliance, so the shape of its elements is
  unverified. Only ``id`` (a positive integer) and ``name`` (a non-empty string)
  are relied on and passed on. A missing list, a list that is not one, or an
  element without both fails closed as a malformed response; no other route is
  tried.
* How an action is *invoked* is unverified: the Phase-1
  ``POST /incidents/{id}/action_invocations`` is undocumented. This client
  therefore cannot invoke anything, and ``soar_invoke_action`` refuses.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.errors import SoarMalformedResponseError


def _carried_actions(obj: Mapping[str, Any], where: str) -> list[dict[str, Any]]:
    """``{id, name}`` for every entry of ``obj["actions"]``; anything unexpected raises."""
    raw = obj.get("actions")
    if not isinstance(raw, list):
        raise SoarMalformedResponseError(f"{where} carries no 'actions' list")
    out: list[dict[str, Any]] = []
    for item in raw:
        action_id = item.get("id") if isinstance(item, dict) else None
        name = item.get("name") if isinstance(item, dict) else None
        if (
            not isinstance(action_id, int)
            or isinstance(action_id, bool)
            or action_id <= 0
            or not isinstance(name, str)
            or not name.strip()
        ):
            raise SoarMalformedResponseError(
                f"{where} carries an 'actions' entry without a positive integer id and a name"
            )
        out.append({"id": action_id, "name": name})
    return out


class ActionsClient:
    def __init__(self, client: SoarClient) -> None:
        self._c = client

    async def list_for_incident(self, incident_id: int) -> list[dict[str, Any]]:
        incident = await self._c.incidents.get(incident_id)
        return _carried_actions(incident, "GET /incidents/{id}")
