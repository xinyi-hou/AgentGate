from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentgate.adapters.function import FunctionToolAdapter
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.models import RuntimeOutcome


class OpenAIAgentsAdapter:
    def __init__(
        self,
        functions: FunctionToolAdapter,
        context_provider: Callable[[Any], RuntimeContext],
    ):
        self.functions = functions
        self.context_provider = context_provider

    def wrap(self, tool_name: str) -> Callable[[Any, dict[str, Any]], Any]:
        async def guarded(context: Any, arguments: dict[str, Any]) -> RuntimeOutcome:
            return await self.functions.invoke(
                tool_name=tool_name,
                arguments=arguments,
                context=self.context_provider(context),
            )

        return guarded
