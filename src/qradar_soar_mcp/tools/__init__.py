"""MCP tools. Importing this package populates ``TOOL_REGISTRY`` (P1-14)."""

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
