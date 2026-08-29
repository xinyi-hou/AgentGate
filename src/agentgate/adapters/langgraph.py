from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentgate.adapters.function import FunctionToolAdapter
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.models import RuntimeOutcome


class LangGraphAdapter:
    def __init__(
        self,
        functions: FunctionToolAdapter,
        context_provider: Callable[[Any], RuntimeContext],
    ):
        self.functions = functions
        self.context_provider = context_provider

    def wrap(self, tool_name: str) -> Callable[[dict[str, Any], Any], Any]:
        async def guarded(arguments: dict[str, Any], state: Any) -> RuntimeOutcome:
            return await self.functions.invoke(
                tool_name=tool_name,
                arguments=arguments,
                context=self.context_provider(state),
                source_framework="langgraph",
            )

        return guarded
