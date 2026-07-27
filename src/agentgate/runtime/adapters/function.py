from __future__ import annotations

from typing import Any

from agentgate.models import GatewayOutcome, TaskContract, ToolCall
from agentgate.runtime.gateway import AgentGate


class FunctionToolAdapter:
    """Framework-neutral wrapper for local function tool calls."""

    def __init__(self, gateway: AgentGate):
        self.gateway = gateway

    async def invoke(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        principal: str,
        session_id: str,
        contract: TaskContract,
        approval_token: str | None = None,
    ) -> GatewayOutcome:
        call = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            principal=principal,
            session_id=session_id,
            approval_token=approval_token,
        )
        return await self.gateway.execute(call, contract)
