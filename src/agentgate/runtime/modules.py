from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentgate.authorization import TaskAuthorizer, TaskContract
from agentgate.capabilities.models import ToolCapability
from agentgate.capabilities.registry import CapabilityRegistry, ToolDefinition
from agentgate.content import ContentFinding, ContentScanner
from agentgate.detection.engine import DetectionEngine, merge_decisions
from agentgate.events.models import RawToolCall, ToolExecutionResult, ToolSecurityEvent
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.policy.models import SecurityDecision
from agentgate.state.models import SessionSecurityState


@dataclass(frozen=True)
class NormalizedToolResult:
    execution: ToolExecutionResult
    event: ToolSecurityEvent
    content_findings: list[ContentFinding]
    sanitized: bool


class ToolCallSecurityEventAbstraction:
    """Module 1: normalize heterogeneous calls and results into security facts."""

    def __init__(
        self,
        registry: CapabilityRegistry,
        event_builder: ToolEventBuilder,
        content_scanner: ContentScanner | None = None,
    ):
        self.registry = registry
        self.event_builder = event_builder
        self.content_scanner = content_scanner or ContentScanner()

    def build_request(
        self,
        call: RawToolCall,
        state: SessionSecurityState,
    ) -> tuple[ToolDefinition, ToolSecurityEvent]:
        definition = self.registry.get(call.tool_name)
        event = self.event_builder.build_request(
            call,
            definition.capability,
            state.sensitive_objects.values(),
        )
        return definition, event

    def build_result(
        self,
        request: ToolSecurityEvent,
        execution: ToolExecutionResult,
        capability: ToolCapability,
    ) -> NormalizedToolResult:
        findings: list[ContentFinding] = []
        sanitized = False
        normalized = execution
        if execution.success and (capability.untrusted_output or request.untrusted_context):
            analysis = self.content_scanner.scan(execution.output)
            findings = analysis.findings
            if findings:
                normalized = execution.model_copy(update={"output": analysis.sanitized})
                sanitized = True
        event = self.event_builder.build_result(request, normalized, capability)
        return NormalizedToolResult(
            execution=normalized,
            event=event,
            content_findings=findings,
            sanitized=sanitized,
        )


class StatefulRiskControl:
    """Module 3: map the current event and executed session facts to a control action."""

    def __init__(self, detector: DetectionEngine, authorizer: TaskAuthorizer | None = None):
        self.detector = detector
        self.authorizer = authorizer or TaskAuthorizer()

    async def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
        task_contract: dict[str, Any] | None = None,
    ) -> SecurityDecision:
        decisions = [await self.detector.evaluate(event, state)]
        if task_contract is not None:
            decisions.append(
                self.authorizer.evaluate(event, TaskContract.model_validate(task_contract))
            )
        return merge_decisions(decisions)
