from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from agentgate.capabilities.models import ToolCapability


class ToolExecutor(Protocol):
    async def __call__(self, arguments: dict[str, Any]) -> Any: ...


ExecutorCallable = Callable[[dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class ToolDefinition:
    capability: ToolCapability
    executor: ToolExecutor | None = None


class CapabilityRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, ToolDefinition] = {}

    def register(
        self,
        capability: ToolCapability,
        executor: ToolExecutor | None = None,
        *,
        replace: bool = False,
    ) -> ToolDefinition:
        if capability.tool_name in self._definitions and not replace:
            raise ValueError(f"tool already registered: {capability.tool_name}")
        definition = ToolDefinition(capability=capability, executor=executor)
        self._definitions[capability.tool_name] = definition
        return definition

    def get(self, tool_name: str) -> ToolDefinition:
        try:
            return self._definitions[tool_name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {tool_name}") from exc

    def capabilities(self) -> list[ToolCapability]:
        return [definition.capability for definition in self._definitions.values()]

    def __contains__(self, tool_name: str) -> bool:
        return tool_name in self._definitions

    def __len__(self) -> int:
        return len(self._definitions)
