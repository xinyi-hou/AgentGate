from __future__ import annotations

from typing import Any, Protocol

from agentgate.events.models import RawToolCall, ToolExecutionResult
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.models import RuntimeOutcome


class ToolCallAdapter(Protocol):
    async def intercept_request(
        self,
        raw_call: Any,
        context: RuntimeContext,
    ) -> RawToolCall: ...

    async def execute(
        self,
        raw_call: RawToolCall,
        context: RuntimeContext | None = None,
    ) -> RuntimeOutcome: ...

    async def normalize_result(self, raw_result: Any) -> ToolExecutionResult: ...
