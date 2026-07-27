from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from agentgate.models import GatewayOutcome, TaskContract
from agentgate.runtime.adapters.function import FunctionToolAdapter


class LangGraphAdapter:
    """Minimal middleware callable usable from LangGraph tool nodes without importing LangGraph."""

    def __init__(
        self, adapter: FunctionToolAdapter, contract_provider: Callable[[Any], TaskContract]
    ):
        self.adapter = adapter
        self.contract_provider = contract_provider

    async def before_tool(
        self, state: Any, tool_name: str, arguments: dict[str, Any]
    ) -> GatewayOutcome:
        contract = self.contract_provider(state)
        return await self.adapter.invoke(
            tool_name=tool_name,
            arguments=arguments,
            principal=contract.principal,
            session_id=str(getattr(state, "session_id", "langgraph-session")),
            contract=contract,
        )


class OpenAIAgentsAdapter:
    """Adapter callable for OpenAI Agents SDK function-tool wrappers."""

    def __init__(self, adapter: FunctionToolAdapter):
        self.adapter = adapter

    def wrap(
        self,
        tool_name: str,
        contract_provider: Callable[[Any], TaskContract],
    ) -> Callable[[Any, dict[str, Any]], Awaitable[GatewayOutcome]]:
        async def guarded(context: Any, arguments: dict[str, Any]) -> GatewayOutcome:
            contract = contract_provider(context)
            session_id = str(getattr(context, "session_id", "openai-agents-session"))
            return await self.adapter.invoke(
                tool_name=tool_name,
                arguments=arguments,
                principal=contract.principal,
                session_id=session_id,
                contract=contract,
            )

        return guarded
