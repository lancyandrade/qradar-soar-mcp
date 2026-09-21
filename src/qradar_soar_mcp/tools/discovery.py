"""Discovery tools (P2-01; 08 §25). This ticket adds the catalog and one tool over it;
the listing tools of P2-02 to P2-05 are not here."""

from __future__ import annotations

from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools.registry import ToolResult, soar_tool
from qradar_soar_mcp.tools.runtime import Runtime


@soar_tool(name="soar_refresh_catalog", tier=Tier.READ)
async def soar_refresh_catalog(rt: Runtime) -> ToolResult:
    """Reload the server's cached catalog of SOAR configuration (functions, scripts,
    message destinations, incident types, phases, fields, data tables, playbooks, rules,
    groups) now, instead of waiting for the cache to expire; use it after an app or a
    playbook was installed or changed. Read-only. Returns the source, the fetch time, the
    SOAR version and a count per section, never the objects themselves. A section under
    ``not_loaded`` could not be established on this SOAR version: treat it as unknown,
    not as empty."""
    service = rt.require_catalog()
    catalog = await service.refresh()
    return ToolResult(data={**catalog.summary(), "ttl_seconds": service.ttl_seconds})
