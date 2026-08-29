from __future__ import annotations

from dataclasses import dataclass

from agentgate.authorization import (
    AuthorizationStore,
    MemoryAuthorizationStore,
    TaskAuthorizer,
)
from agentgate.capabilities.models import ToolCapability
from agentgate.capabilities.registry import CapabilityRegistry, ToolDefinition
from agentgate.content import ContentFinding, ContentMode, ContentScanner
from agentgate.detection.engine import DetectionEngine, merge_decisions
from agentgate.detection.graph_engine import GraphRiskEngine
from agentgate.detection.graph_models import GraphRiskEvaluation
from agentgate.detection.models import DetectionState
from agentgate.events.models import RawToolCall, ToolExecutionResult, ToolSecurityEvent
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.graph import (
    AgentTransitionGraph,
    AgentTransitionGraphBuilder,
    CandidateGraphExtension,
)
from agentgate.policy.models import DecisionAction, SecurityDecision, Severity
from agentgate.runtime.context import RuntimeContext
from agentgate.semantics import CanonicalToolCall
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
        content_mode: ContentMode = ContentMode.OBSERVE,
        graph_builder: AgentTransitionGraphBuilder | None = None,
    ):
        self.registry = registry
        self.event_builder = event_builder
        self.content_scanner = content_scanner or ContentScanner()
        self.content_mode = content_mode
        self.graph_builder = graph_builder or AgentTransitionGraphBuilder()

    def build_request(
        self,
        call: RawToolCall | CanonicalToolCall,
        state: SessionSecurityState | AgentTransitionGraph,
        runtime_context: RuntimeContext | None = None,
    ) -> tuple[ToolDefinition, ToolSecurityEvent]:
        definition = self.registry.get(call.tool_name)
        sensitive_objects = (
            self.graph_builder.sensitive_objects(state, call.arguments, call.task_id)
            if isinstance(state, AgentTransitionGraph)
            else list(state.sensitive_objects.values())
        )
        event = self.event_builder.build_request(
            call,
            definition.capability,
            sensitive_objects,
            runtime_context,
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
        if execution.success:
            analysis = self.content_scanner.scan(execution.output)
            findings = analysis.findings
            if findings and self.content_mode == ContentMode.SANITIZE:
                normalized = execution.model_copy(update={"output": analysis.sanitized})
                sanitized = True
        event = self.event_builder.build_result(request, normalized, capability)
        if findings:
            event = event.model_copy(
                update={
                    "untrusted_context": True,
                    "trust_evidence": [
                        *event.trust_evidence,
                        *(f"content_finding:{item.risk_type.value}" for item in findings),
                    ],
                }
            )
        return NormalizedToolResult(
            execution=normalized,
            event=event,
            content_findings=findings,
            sanitized=sanitized,
        )


class StatefulRiskControl:
    """Module 3: map the current event and executed session facts to a control action."""

    def __init__(
        self,
        detector: DetectionEngine | GraphRiskEngine,
        authorizer: TaskAuthorizer | None = None,
        authorization_store: AuthorizationStore | None = None,
    ):
        self.detector = detector
        self.graph_detector = (
            detector if isinstance(detector, GraphRiskEngine) else GraphRiskEngine(detector.policy)
        )
        self.authorizer = authorizer or TaskAuthorizer()
        self.authorization_store = authorization_store or MemoryAuthorizationStore()

    async def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState | AgentTransitionGraph,
        runtime_context: RuntimeContext,
        detection_state: DetectionState | CandidateGraphExtension | None = None,
    ) -> SecurityDecision | GraphRiskEvaluation:
        if isinstance(state, AgentTransitionGraph):
            if not isinstance(detection_state, CandidateGraphExtension):
                raise TypeError("graph risk control requires a candidate graph extension")
            graph_evaluation = await self.graph_detector.evaluate(state, detection_state)
            decisions = [graph_evaluation.decision]
        else:
            graph_evaluation = None
            decisions = [await self.detector.evaluate(event, state, detection_state)]
        if runtime_context.task_id is not None:
            authorization = await self.authorization_store.get(
                runtime_context.principal,
                runtime_context.task_id,
            )
            if authorization is not None and runtime_context.authorization_id in {
                None,
                authorization.authorization_id,
            }:
                decisions.append(self.authorizer.evaluate(event, authorization))
            elif runtime_context.authorization_id is not None:
                decisions.append(
                    SecurityDecision(
                        action=DecisionAction.BLOCK,
                        rule_ids=["task_authorization_binding"],
                        reasons=["The trusted authorization reference is missing or mismatched."],
                        severity=Severity.HIGH,
                    )
                )
        decision = merge_decisions(decisions)
        if graph_evaluation is None:
            return decision
        return graph_evaluation.model_copy(update={"decision": decision})
