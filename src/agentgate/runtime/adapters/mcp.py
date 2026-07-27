from __future__ import annotations

from typing import Any

from agentgate.models import ToolSpec


class McpToolAdapter:
    """Convert MCP list_tools entries into AgentGate's protocol-neutral ToolSpec."""

    @staticmethod
    def to_tool_spec(tool: dict[str, Any], server_name: str, trusted: bool = False) -> ToolSpec:
        return ToolSpec(
            name=f"{server_name}.{tool['name']}",
            description=str(tool.get("description", "")),
            input_schema=dict(tool.get("inputSchema", {"type": "object"})),
            output_schema=dict(tool.get("outputSchema", {})),
            namespace=server_name,
            source=f"mcp://{server_name}",
            publisher=server_name,
            version=str(tool.get("version", "unknown")),
            trusted=trusted,
        )

    @staticmethod
    def call_payload(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"method": "tools/call", "params": {"name": tool_name, "arguments": arguments}}
