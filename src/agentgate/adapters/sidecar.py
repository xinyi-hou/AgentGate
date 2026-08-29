from __future__ import annotations

from typing import Any

import httpx

from agentgate.adapters.canonical import canonicalize_call
from agentgate.events.models import RawToolCall, ToolExecutionResult
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.runtime.models import RuntimeOutcome
from agentgate.semantics import CanonicalToolCall


class RemoteHttpExecutor:
    def __init__(self, url: str, *, timeout_seconds: float = 30.0):
        self.url = url
        self.timeout_seconds = timeout_seconds

    async def __call__(self, arguments: dict[str, Any]) -> Any:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(self.url, json={"arguments": arguments})
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                return response.text


class SidecarAdapter:
    def __init__(self, runtime: AgentGateRuntime):
        self.runtime = runtime

    async def intercept_request(
        self,
        raw_call: Any,
        context: RuntimeContext,
    ) -> CanonicalToolCall:
        return canonicalize_call(
            raw_call,
            context,
            source_framework="custom",
            source_transport="http_sidecar",
        )

    async def execute(
        self,
        raw_call: RawToolCall | CanonicalToolCall,
        context: RuntimeContext | None = None,
    ) -> RuntimeOutcome:
        return await self.runtime.execute(raw_call, context)

    async def normalize_result(self, raw_result: Any) -> ToolExecutionResult:
        return ToolExecutionResult(output=raw_result)
