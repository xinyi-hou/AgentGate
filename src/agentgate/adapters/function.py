from __future__ import annotations

from typing import Any
from uuid import uuid4

from agentgate.capabilities.inference import CapabilityInferer
from agentgate.capabilities.models import ToolCapability
from agentgate.capabilities.registry import ToolExecutor
from agentgate.events.models import RawToolCall, ToolExecutionResult
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.runtime.models import RuntimeOutcome


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
    ) -> RawToolCall:
        if isinstance(raw_call, RawToolCall):
            return raw_call.model_copy(
                update={
                    "principal": context.principal,
                    "session_id": context.session_id,
                    "agent_id": context.agent_id,
                    "task_id": context.task_id,
                    "parent_call_id": context.parent_call_id,
                    "trusted_context": context.trusted_context,
                    "untrusted_context": context.untrusted_context,
                    "task_contract": context.task_contract,
                }
            )
        if not isinstance(raw_call, dict):
            raise TypeError("function tool call must be a mapping or RawToolCall")
        return RawToolCall(
            tool_name=str(raw_call["tool_name"]),
            arguments=dict(raw_call.get("arguments", {})),
            call_id=raw_call.get("call_id") or str(uuid4()),
            approval_token=raw_call.get("approval_token"),
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
    ) -> RuntimeOutcome:
        payload: dict[str, Any] = {
            "tool_name": tool_name,
            "arguments": arguments,
            "approval_token": approval_token,
        }
        if call_id is not None:
            payload["call_id"] = call_id
        call = await self.intercept_request(payload, context)
        return await self.execute(call)
