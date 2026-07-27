from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from agentgate.models import ToolSpec
from agentgate.tools.backend import MockBackend

ToolHandler = Callable[[dict[str, Any]], Awaitable[Any]]


@dataclass
class ToolDefinition:
    spec: ToolSpec
    handler: ToolHandler


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        if definition.spec.name in self._tools:
            raise ValueError(f"duplicate tool: {definition.spec.name}")
        self._tools[definition.spec.name] = definition

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def definitions(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def specs(self) -> list[ToolSpec]:
        return [definition.spec for definition in self._tools.values()]

    def __len__(self) -> int:
        return len(self._tools)


def build_default_registry(backend: MockBackend | None = None) -> tuple[ToolRegistry, MockBackend]:
    from agentgate.tools.business.tools import business_tools
    from agentgate.tools.database.tools import database_tools
    from agentgate.tools.filesystem.tools import filesystem_tools
    from agentgate.tools.messaging.tools import messaging_tools
    from agentgate.tools.network.tools import network_tools

    backend = backend or MockBackend()
    registry = ToolRegistry()
    for definition in (
        filesystem_tools(backend)
        + database_tools(backend)
        + network_tools(backend)
        + messaging_tools(backend)
        + business_tools(backend)
    ):
        registry.register(definition)
    return registry, backend
