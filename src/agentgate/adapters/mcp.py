from __future__ import annotations

from typing import Any, Protocol
from uuid import uuid4

from agentgate.capabilities.inference import CapabilityInferer
from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import RawToolCall, ToolExecutionResult
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.runtime.models import RuntimeOutcome


class McpUpstream(Protocol):
    async def list_tools(self) -> list[dict[str, Any]]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


class McpGateway:
    def __init__(
        self,
        runtime: AgentGateRuntime,
        upstream: McpUpstream,
        *,
        server_name: str,
        inferer: CapabilityInferer | None = None,
    ):
        self.runtime = runtime
        self.upstream = upstream
        self.server_name = server_name
        self.inferer = inferer or CapabilityInferer()
        self._catalog: dict[str, dict[str, Any]] = {}

    async def initialize(
        self,
        explicit_capabilities: dict[str, ToolCapability] | None = None,
    ) -> list[ToolCapability]:
        capabilities: list[ToolCapability] = []
        explicit_capabilities = explicit_capabilities or {}
        for tool in await self.upstream.list_tools():
            upstream_name = str(tool["name"])
            gateway_name = f"{self.server_name}.{upstream_name}"
            explicit = explicit_capabilities.get(upstream_name)
            capability = explicit or await self.inferer.infer(
                name=gateway_name,
                description=str(tool.get("description", "")),
                input_schema=dict(tool.get("inputSchema", {"type": "object"})),
                output_schema=dict(tool.get("outputSchema", {})),
                annotations=dict(tool.get("annotations", {})),
            )
            if capability.tool_name != gateway_name:
                capability = ToolCapability.model_validate(
                    {**capability.model_dump(), "tool_name": gateway_name}
                )

            async def execute(arguments: dict[str, Any], name: str = upstream_name) -> Any:
                return await self.upstream.call_tool(name, arguments)

            self.runtime.registry.register(capability, execute)
            self._catalog[gateway_name] = tool
            capabilities.append(capability)
        return capabilities

    async def intercept_request(
        self,
        raw_call: Any,
        context: RuntimeContext,
    ) -> RawToolCall:
        if not isinstance(raw_call, dict) or raw_call.get("method") != "tools/call":
            raise ValueError("expected an MCP tools/call request")
        params = raw_call.get("params") or {}
        name = str(params["name"])
        gateway_name = (
            name if name.startswith(f"{self.server_name}.") else f"{self.server_name}.{name}"
        )
        return RawToolCall(
            tool_name=gateway_name,
            arguments=dict(params.get("arguments", {})),
            call_id=str(raw_call.get("id")) if raw_call.get("id") is not None else str(uuid4()),
            principal=context.principal,
            session_id=context.session_id,
            agent_id=context.agent_id,
            task_id=context.task_id,
            parent_call_id=context.parent_call_id,
            trusted_context=context.trusted_context,
            untrusted_context=context.untrusted_context,
            task_contract=context.task_contract,
        )

    async def execute(self, raw_call: RawToolCall) -> RuntimeOutcome:
        return await self.runtime.execute(raw_call)

    async def normalize_result(self, raw_result: Any) -> ToolExecutionResult:
        return ToolExecutionResult(output=raw_result)

    async def call(self, request: dict[str, Any], context: RuntimeContext) -> RuntimeOutcome:
        call = await self.intercept_request(request, context)
        return await self.execute(call)

    async def list_tools(self) -> list[dict[str, Any]]:
        return [{**tool, "name": gateway_name} for gateway_name, tool in self._catalog.items()]
