"""MCP tools. Importing this package populates ``TOOL_REGISTRY`` (08 §3)."""

from qradar_soar_mcp.tools import actions, incidents, investigation  # noqa: F401  (registration)
from qradar_soar_mcp.tools.registry import (
    TOOL_REGISTRY,
    ToolResult,
    ToolSpec,
    register_all,
    run_pipeline,
    soar_tool,
)
from qradar_soar_mcp.tools.runtime import Runtime

__all__ = [
    "TOOL_REGISTRY",
    "Runtime",
    "ToolResult",
    "ToolSpec",
    "register_all",
    "run_pipeline",
    "soar_tool",
]
