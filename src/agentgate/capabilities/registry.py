from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from agentgate.capabilities.models import ToolCapability
from agentgate.content import ContentAnalysis, ContentScanner
from agentgate.policy.models import Severity


class ToolExecutor(Protocol):
    async def __call__(self, arguments: dict[str, Any]) -> Any: ...


ExecutorCallable = Callable[[dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class ToolDefinition:
    capability: ToolCapability
    executor: ToolExecutor | None = None
    registration_analysis: ContentAnalysis | None = None


class CapabilityRegistry:
    def __init__(self, scanner: ContentScanner | None = None) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        self.scanner = scanner or ContentScanner()

    def register(
        self,
        capability: ToolCapability,
        executor: ToolExecutor | None = None,
        *,
        replace: bool = False,
    ) -> ToolDefinition:
        existing = self._definitions.get(capability.tool_name)
        if existing is not None and not replace:
            raise ValueError(f"tool already registered: {capability.tool_name}")
        analysis = self.scanner.scan(capability.description)
        if any(item.severity == Severity.CRITICAL for item in analysis.findings):
            raise ValueError(
                f"tool description contains control instructions: {capability.tool_name}"
            )
        if existing is not None and semantic_distance(existing.capability, capability) >= 0.5:
            raise ValueError(f"tool capability drift requires review: {capability.tool_name}")
        definition = ToolDefinition(
            capability=capability,
            executor=executor,
            registration_analysis=analysis,
        )
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


def semantic_distance(left: ToolCapability, right: ToolCapability) -> float:
    left_tokens = left.semantic_tokens()
    right_tokens = right.semantic_tokens()
    union = left_tokens | right_tokens
    return 1.0 - len(left_tokens & right_tokens) / len(union) if union else 0.0
