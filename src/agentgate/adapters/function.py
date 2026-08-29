from __future__ import annotations

from typing import Any

from agentgate.adapters.canonical import canonicalize_call
from agentgate.capabilities.inference import CapabilityInferer
from agentgate.capabilities.models import ToolCapability
from agentgate.capabilities.registry import ToolExecutor
from agentgate.events.models import RawToolCall, ToolExecutionResult
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.runtime.models import RuntimeOutcome
from agentgate.semantics import CanonicalToolCall


class FunctionToolAdapter:
    def __init__(
        self,
        runtime: AgentGateRuntime,
        inferer: CapabilityInferer | None = None,
    ):
        self.runtime = runtime
        self.inferer = inferer or CapabilityInferer()

    async def register(
        self,
        *,
        name: str,
        executor: ToolExecutor,
        capability: ToolCapability | None = None,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        replace: bool = False,
    ) -> ToolCapability:
        resolved = capability or await self.inferer.infer(
            name=name,
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
        )
        if resolved.tool_name != name:
            raise ValueError("capability tool_name does not match the registered function")
        self.runtime.registry.register(resolved, executor, replace=replace)
        return resolved

    async def intercept_request(
        self,
        raw_call: Any,
        context: RuntimeContext,
    ) -> CanonicalToolCall:
        return canonicalize_call(
            raw_call,
            context,
            source_framework="function",
            source_transport="in_process",
        )

    async def execute(
        self,
        raw_call: RawToolCall | CanonicalToolCall,
        context: RuntimeContext | None = None,
    ) -> RuntimeOutcome:
        return await self.runtime.execute(raw_call, context)

    async def normalize_result(self, raw_result: Any) -> ToolExecutionResult:
        if isinstance(raw_result, ToolExecutionResult):
            return raw_result
        return ToolExecutionResult(
            output=raw_result,
            affected_count=len(raw_result) if isinstance(raw_result, list) else 1,
        )

    async def invoke(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        context: RuntimeContext,
        call_id: str | None = None,
        approval_token: str | None = None,
        source_framework: str = "function",
        source_transport: str = "in_process",
    ) -> RuntimeOutcome:
        payload: dict[str, Any] = {
            "tool_name": tool_name,
            "arguments": arguments,
            "approval_token": approval_token,
        }
        if call_id is not None:
            payload["call_id"] = call_id
        call = canonicalize_call(
            payload,
            context,
            source_framework=source_framework,
            source_transport=source_transport,
        )
        return await self.execute(call, context)
