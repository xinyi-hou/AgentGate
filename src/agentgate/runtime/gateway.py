from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentgate.audit.jsonl import event_summary
from agentgate.audit.models import AuditEventType, AuditRecord
from agentgate.audit.store import AuditStore
from agentgate.authorization import (
    AuthorizationStore,
    MemoryAuthorizationStore,
    TaskAuthorization,
    TaskAuthorizationCompiler,
    TaskAuthorizer,
    TaskIntent,
)
from agentgate.capabilities.registry import CapabilityRegistry, ToolDefinition
from agentgate.content import ContentMode, ContentScanner
from agentgate.detection.engine import DetectionEngine, merge_decisions
from agentgate.detection.graph_engine import GraphRiskEngine
from agentgate.enforcement.approval import ApprovalManager
from agentgate.enforcement.coordinator import (
    LocalSessionExecutionCoordinator,
    SessionExecutionCoordinator,
)
from agentgate.enforcement.rewrite import apply_restriction
from agentgate.events.models import RawToolCall, ToolExecutionResult, ToolSecurityEvent, utc_now
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.graph import (
    AgentTransitionGraph,
    AgentTransitionGraphBuilder,
    CandidateGraphExtension,
    GraphDelta,
    GraphStore,
    InMemoryGraphStore,
)
from agentgate.policy.models import DecisionAction, SecurityDecision, Severity
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.models import RuntimeOutcome
from agentgate.runtime.modules import StatefulRiskControl, ToolCallSecurityEventAbstraction
from agentgate.semantics import CanonicalToolCall
from agentgate.state.manager import StateManager
from agentgate.state.models import SessionSecurityState


@dataclass(frozen=True)
class _EvaluatedCall:
    outcome: RuntimeOutcome
    graph: AgentTransitionGraph
    candidate: CandidateGraphExtension


class AgentGateRuntime:
    """Reference monitor for structured tool calls routed through AgentGate."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        event_builder: ToolEventBuilder,
        state_manager: StateManager,
        detector: DetectionEngine,
        approvals: ApprovalManager,
        audit: AuditStore,
        authorizer: TaskAuthorizer | None = None,
        authorization_store: AuthorizationStore | None = None,
        content_scanner: ContentScanner | None = None,
        content_mode: ContentMode = ContentMode.OBSERVE,
        coordinator: SessionExecutionCoordinator | None = None,
        graph_store: GraphStore | None = None,
        graph_builder: AgentTransitionGraphBuilder | None = None,
        graph_detector: GraphRiskEngine | None = None,
        research_debug: bool = False,
    ):
        self.registry = registry
        self.event_builder = event_builder
        self.state_manager = state_manager
        self.detector = detector
        self.approvals = approvals
        self.audit = audit
        self.authorizer = authorizer or TaskAuthorizer()
        self.authorization_store = authorization_store or MemoryAuthorizationStore()
        self.content_scanner = content_scanner or ContentScanner()
        self.coordinator = coordinator or LocalSessionExecutionCoordinator()
        self.graph_store = graph_store or InMemoryGraphStore()
        self.graph_builder = graph_builder or AgentTransitionGraphBuilder()
        self.graph_detector = graph_detector or GraphRiskEngine(detector.policy)
        self.research_debug = research_debug
        self._decision_evidence: dict[str, dict[str, Any]] = {}
        self.event_abstraction = ToolCallSecurityEventAbstraction(
            registry,
            event_builder,
            self.content_scanner,
            content_mode,
            self.graph_builder,
        )
        self.risk_control = StatefulRiskControl(
            self.graph_detector,
            self.authorizer,
            self.authorization_store,
        )

    async def aclose(self) -> None:
        closed: set[int] = set()
        for component in (
            self.state_manager.store,
            self.detector.detection_store,
            self.graph_store,
            self.coordinator,
        ):
            if id(component) in closed:
                continue
            closed.add(id(component))
            close = getattr(component, "aclose", None)
            if close is not None:
                await close()

    async def authorize_task(
        self,
        *,
        principal: str,
        task_id: str,
        goal: str,
        entitlements: dict[str, Any],
        issuer: str,
        ttl_seconds: int | None = 3600,
    ) -> TaskAuthorization:
        """Compile trusted user intent into a control-plane authorization."""
        authorization = TaskAuthorizationCompiler().compile(
            TaskIntent(task_id=task_id, goal=goal),
            principal=principal,
            entitlements=entitlements,
            issuer=issuer,
            ttl_seconds=ttl_seconds,
        )
        await self.authorization_store.put(authorization)
        return authorization

    async def evaluate(
        self,
        call: RawToolCall | CanonicalToolCall,
        runtime_context: RuntimeContext | None = None,
    ) -> RuntimeOutcome:
        """Return an advisory preview; it has no side effect and provides no mediation guarantee."""
        context, trusted_call = _resolve_context(call, runtime_context)
        trusted_call = trusted_call.model_copy(update={"timestamp": utc_now()})
        evaluated = await self._evaluate(trusted_call, context)
        outcome = evaluated.outcome.model_copy(update={"advisory_only": True})
        self._remember_decision(evaluated.graph, evaluated.candidate, outcome.decision)
        return outcome

    async def execute(
        self,
        call: RawToolCall | CanonicalToolCall,
        runtime_context: RuntimeContext | None = None,
    ) -> RuntimeOutcome:
        context, trusted_call = _resolve_context(call, runtime_context)
        async with self.coordinator.lock(context.principal, context.session_id):
            trusted_call = trusted_call.model_copy(update={"timestamp": utc_now()})
            definition = self.registry.get(trusted_call.tool_name)
            if definition.executor is None:
                raise RuntimeError(f"tool has no executor: {trusted_call.tool_name}")

            evaluated = await self._evaluate(trusted_call, context)
            outcome = evaluated.outcome
            decision = outcome.decision
            request_event = outcome.request_event
            effective_call = trusted_call

            if decision.rewritten_arguments is not None and decision.action != DecisionAction.BLOCK:
                arguments = apply_restriction(
                    trusted_call.arguments,
                    decision.rewritten_arguments,
                )
                effective_call = trusted_call.model_copy(update={"arguments": arguments})
                evaluated = await self._evaluate(effective_call, context)
                restricted = evaluated.outcome
                decision = merge_decisions([decision, restricted.decision])
                request_event = restricted.request_event

            if decision.action == DecisionAction.REQUIRE_APPROVAL:
                approval_call = effective_call.to_raw()
                approved = await self.approvals.consume(approval_call)
                if approved:
                    decision = decision.model_copy(
                        update={
                            "action": DecisionAction.ALLOW,
                            "reasons": [
                                *decision.reasons,
                                "A bound one-time approval was consumed.",
                            ],
                        }
                    )
                    await self._log(
                        AuditEventType.APPROVAL,
                        request_event,
                        {"status": "CONSUMED"},
                    )
                elif effective_call.approval_token:
                    decision = decision.model_copy(
                        update={
                            "action": DecisionAction.BLOCK,
                            "rule_ids": [*decision.rule_ids, "invalid_approval"],
                            "reasons": [
                                *decision.reasons,
                                "The approval token is invalid or expired.",
                            ],
                            "severity": Severity.HIGH,
                        }
                    )
                else:
                    approval = await self.approvals.ensure_request(approval_call)
                    decision = decision.model_copy(update={"approval_id": approval.approval_id})
                    await self._log(
                        AuditEventType.APPROVAL,
                        request_event,
                        {"approval_id": approval.approval_id, "status": approval.status.value},
                    )
                await self._log_decision(request_event, decision)

            if not decision.permits_execution:
                blocked = outcome.model_copy(
                    update={
                        "decision": decision,
                        "request_event": request_event,
                        "advisory_only": False,
                        "graph_updated": False,
                    }
                )
                self._remember_decision(evaluated.graph, evaluated.candidate, decision)
                return blocked

            execution = (await _execute(definition, effective_call.arguments)).model_copy(
                update={"timestamp": utc_now()}
            )
            normalized = self.event_abstraction.build_result(
                request_event,
                execution,
                definition.capability,
            )
            result_event = normalized.event

            graph_delta = self.graph_builder.build_result_delta(
                evaluated.graph,
                evaluated.candidate,
                result_event,
            )
            committed_graph = await self.graph_store.apply_delta(
                evaluated.graph.graph_id,
                graph_delta,
            )

            # Compatibility mirrors remain for research APIs; the ATG is authoritative.
            state = await self.state_manager.observe(result_event)
            detection_updated = False
            if result_event.success is True:
                await self.detector.observe(result_event, state)
                detection_updated = True

            await self._log(
                AuditEventType.CALL_RESULT,
                result_event,
                {
                    "event": self._event_summary(result_event),
                    "result_sanitized": normalized.sanitized,
                    "content_findings": [
                        {
                            "risk_type": item.risk_type.value,
                            "severity": item.severity.value,
                            "path": item.path,
                            "source": item.source,
                        }
                        for item in normalized.content_findings
                    ],
                },
            )
            await self._log(
                AuditEventType.GRAPH_UPDATE,
                result_event,
                {
                    "graph": _graph_summary(committed_graph),
                    "delta": _graph_delta_summary(graph_delta),
                },
            )
            await self._log(
                AuditEventType.STATE_UPDATE,
                result_event,
                {
                    "state": _state_summary(state),
                    "detection_state_updated": detection_updated,
                },
            )
            completed = RuntimeOutcome(
                decision=decision,
                request_event=request_event,
                execution=normalized.execution,
                result_event=result_event,
                state_updated=True,
                detection_state_updated=detection_updated,
                content_findings=normalized.content_findings,
                result_sanitized=normalized.sanitized,
                advisory_only=False,
                graph_id=committed_graph.graph_id,
                graph_updated=True,
                llm_called=outcome.llm_called,
                llm_reason=outcome.llm_reason,
                llm_latency_ms=outcome.llm_latency_ms,
            )
            self._remember_decision(committed_graph, evaluated.candidate, decision)
            return completed

    async def _evaluate(
        self,
        call: CanonicalToolCall,
        context: RuntimeContext,
    ) -> _EvaluatedCall:
        graph = await self.graph_store.get_session_graph(
            context.principal,
            context.session_id,
        )
        _, event = self.event_abstraction.build_request(call, graph, context)
        candidate = await self.graph_builder.preview_request(graph, event)
        event = candidate.request_event
        await self._log(
            AuditEventType.CALL_REQUEST,
            event,
            {"event": self._event_summary(event)},
        )
        risk = await self.risk_control.evaluate(
            event,
            graph,
            context,
            candidate,
        )
        assert not isinstance(risk, SecurityDecision)
        decision = risk.decision
        candidate = risk.candidate
        await self._log_decision(event, decision)
        return _EvaluatedCall(
            graph=graph,
            candidate=candidate,
            outcome=RuntimeOutcome(
                decision=decision,
                request_event=event,
                advisory_only=False,
                graph_id=graph.graph_id,
                llm_called=risk.llm_called,
                llm_reason=risk.llm_reason,
                llm_latency_ms=risk.llm_latency_ms,
            ),
        )

    def get_decision_evidence(self, decision_id: str) -> dict[str, Any]:
        try:
            return self._decision_evidence[decision_id]
        except KeyError as exc:
            raise KeyError(f"unknown decision: {decision_id}") from exc

    def _remember_decision(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
        decision: SecurityDecision,
    ) -> None:
        candidate_nodes = {node.node_id: node for node in candidate.delta.nodes}
        nodes = {**graph.nodes, **candidate_nodes}
        candidate_edges = {edge.edge_id: edge for edge in candidate.delta.edges}
        edges = {**graph.edges, **candidate_edges}
        selected_nodes = set(decision.matched_node_ids) | {candidate.event_node_id}
        selected_edges = set(decision.matched_edge_ids)
        self._decision_evidence[decision.decision_id] = {
            "decision": decision.model_dump(mode="json"),
            "nodes": [
                nodes[node_id].model_dump(mode="json", exclude={"fingerprints"})
                for node_id in sorted(selected_nodes)
                if node_id in nodes
            ],
            "edges": [
                edges[edge_id].model_dump(mode="json")
                for edge_id in sorted(selected_edges)
                if edge_id in edges
            ],
            "candidate": True,
        }
        if len(self._decision_evidence) > 1000:
            self._decision_evidence.pop(next(iter(self._decision_evidence)))

    async def _log_decision(
        self,
        event: ToolSecurityEvent,
        decision: SecurityDecision,
    ) -> None:
        await self._log(
            AuditEventType.DECISION,
            event,
            {"decision": decision.model_dump(mode="json")},
        )
        if decision.rule_ids:
            await self._log(
                AuditEventType.RULE_MATCH,
                event,
                {"rule_ids": decision.rule_ids, "action": decision.action.value},
            )

    def _event_summary(self, event: ToolSecurityEvent) -> dict[str, Any]:
        include_payloads = bool(getattr(self.audit, "unsafe_debug_payloads", False))
        return event_summary(event, include_payloads=include_payloads)

    async def _log(
        self,
        event_type: AuditEventType,
        event: ToolSecurityEvent,
        payload: dict[str, Any],
    ) -> None:
        await self.audit.append(
            AuditRecord(
                event_type=event_type,
                principal=event.principal,
                session_id=event.session_id,
                call_id=event.call_id,
                payload=payload,
            )
        )


def _resolve_context(
    call: RawToolCall | CanonicalToolCall,
    supplied: RuntimeContext | None,
) -> tuple[RuntimeContext, CanonicalToolCall]:
    canonical = (
        call
        if isinstance(call, CanonicalToolCall)
        else CanonicalToolCall.from_raw(call, source_framework="legacy")
    )
    context = supplied or RuntimeContext(
        principal=canonical.principal_id,
        session_id=canonical.session_id,
        agent_id=canonical.agent_id,
        task_id=canonical.task_id,
        parent_call_id=canonical.parent_call_id,
    )
    trusted_call = canonical.model_copy(
        update={
            "principal_id": context.principal,
            "session_id": context.session_id,
            "agent_id": context.agent_id,
            "task_id": context.task_id,
            "parent_call_id": context.parent_call_id,
        }
    )
    return context, trusted_call


async def _execute(definition: ToolDefinition, arguments: dict[str, Any]) -> ToolExecutionResult:
    assert definition.executor is not None
    try:
        output = await definition.executor(arguments)
        if isinstance(output, ToolExecutionResult):
            return output
        return ToolExecutionResult(
            output=output,
            affected_count=len(output) if isinstance(output, list) else 1,
        )
    except Exception as exc:
        return ToolExecutionResult(
            success=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )


def _state_summary(state: SessionSecurityState) -> dict[str, Any]:
    return {
        "principal": state.principal,
        "session_id": state.session_id,
        "labels": sorted(item.value for item in state.labels),
        "label_fact_count": len(state.label_facts),
        "counters": state.counters,
        "sensitive_object_count": len(state.sensitive_objects),
        "sensitive_event_count": len(state.recent_sensitive_events),
        "updated_at": state.updated_at.isoformat(),
    }


def _graph_summary(graph: AgentTransitionGraph) -> dict[str, Any]:
    return {
        "graph_id": graph.graph_id,
        "principal_id": graph.principal_id,
        "session_id": graph.session_id,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "updated_at": graph.updated_at.isoformat(),
    }


def _graph_delta_summary(delta: GraphDelta) -> dict[str, Any]:
    return {
        "candidate": delta.candidate,
        "reason": delta.reason,
        "node_ids": [node.node_id for node in delta.nodes],
        "edge_ids": [edge.edge_id for edge in delta.edges],
    }
