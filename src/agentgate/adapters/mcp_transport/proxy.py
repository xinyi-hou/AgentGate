from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

from agentgate.capabilities.inference import CapabilityInferer
from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import RawToolCall
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.gateway import AgentGateRuntime

from .upstream import JsonObject, McpJsonRpcUpstream

ContextProvider = Callable[[JsonObject, dict[str, str]], RuntimeContext]


class McpProtocolProxy:
    """Transparent MCP method proxy with mediation at tools/call."""

    def __init__(
        self,
        runtime: AgentGateRuntime,
        upstream: McpJsonRpcUpstream,
        *,
        context_provider: ContextProvider,
        inferer: CapabilityInferer | None = None,
        explicit_capabilities: dict[str, ToolCapability] | None = None,
    ):
        self.runtime = runtime
        self.upstream = upstream
        self.context_provider = context_provider
        self.inferer = inferer or CapabilityInferer()
        self.explicit_capabilities = explicit_capabilities or {}

    async def handle(
        self,
        message: JsonObject,
        headers: dict[str, str] | None = None,
    ) -> JsonObject | None:
        method = message.get("method")
        if method == "tools/list":
            response = await self.upstream.forward(message)
            if response is not None and "result" in response:
                try:
                    await self._register_tools(response)
                except ValueError as exc:
                    return _error(message.get("id"), -32602, str(exc))
            return response
        if method == "tools/call":
            return await self._call_tool(message, headers or {})
        return await self.upstream.forward(message)

    async def refresh_tools(self) -> list[ToolCapability]:
        capabilities: list[ToolCapability] = []
        for tool in await self.upstream.list_tools():
            capabilities.append(await self._register_tool(tool))
        return capabilities

    async def _register_tools(self, response: JsonObject) -> None:
        tools = response.get("result", {}).get("tools", [])
        for tool in tools:
            if isinstance(tool, dict):
                await self._register_tool(tool)

    async def _register_tool(self, tool: JsonObject) -> ToolCapability:
        name = str(tool["name"])
        capability = self.explicit_capabilities.get(name)
        if capability is None:
            capability = await self.inferer.infer(
                name=name,
                description=str(tool.get("description", "")),
                input_schema=dict(tool.get("inputSchema", {"type": "object"})),
                output_schema=dict(tool.get("outputSchema", {})),
                annotations=dict(tool.get("annotations", {})),
            )
        if capability.tool_name != name:
            capability = ToolCapability.model_validate(
                {**capability.model_dump(), "tool_name": name}
            )

        async def execute(arguments: dict[str, Any], tool_name: str = name) -> Any:
            return await self.upstream.call_tool(tool_name, arguments)

        self.runtime.registry.register(capability, execute, replace=name in self.runtime.registry)
        return capability

    async def _call_tool(
        self,
        message: JsonObject,
        headers: dict[str, str],
    ) -> JsonObject:
        request_id = message.get("id")
        params = message.get("params") or {}
        name = str(params.get("name", ""))
        if name not in self.runtime.registry:
            try:
                await self.refresh_tools()
            except ValueError as exc:
                return _error(request_id, -32602, str(exc))
        context = self.context_provider(message, headers)
        call = RawToolCall(
            tool_name=name,
            arguments=dict(params.get("arguments", {})),
            principal=context.principal,
            session_id=context.session_id,
            call_id=str(request_id) if request_id is not None else str(uuid4()),
            agent_id=context.agent_id,
            task_id=context.task_id,
            parent_call_id=context.parent_call_id,
        )
        try:
            outcome = await self.runtime.execute(call, context)
        except (KeyError, ValueError, RuntimeError) as exc:
            return _error(request_id, -32000, str(exc))
        if outcome.execution is not None:
            return {"jsonrpc": "2.0", "id": request_id, "result": outcome.execution.output}
        decision = outcome.decision
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"AgentGate {decision.action.value}: {'; '.join(decision.reasons)}",
                    }
                ],
                "isError": True,
                "structuredContent": {
                    "agentgate": decision.model_dump(mode="json"),
                },
            },
        }


def static_context_provider(context: RuntimeContext) -> ContextProvider:
    def provide(_: JsonObject, __: dict[str, str]) -> RuntimeContext:
        return context.model_copy(deep=True)

    return provide


def _error(request_id: Any, code: int, message: str) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
