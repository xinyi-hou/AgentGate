from __future__ import annotations

from typing import Any

from agentgate.audit.jsonl import event_summary
from agentgate.audit.models import AuditEventType, AuditRecord
from agentgate.audit.store import AuditStore
from agentgate.authorization import (
    AuthorizationStore,
    MemoryAuthorizationStore,
    TaskAuthorizer,
)
from agentgate.capabilities.registry import CapabilityRegistry, ToolDefinition
from agentgate.content import ContentMode, ContentScanner
from agentgate.detection.engine import DetectionEngine, merge_decisions
from agentgate.enforcement.approval import ApprovalManager
from agentgate.enforcement.coordinator import (
    LocalSessionExecutionCoordinator,
    SessionExecutionCoordinator,
)
from agentgate.enforcement.rewrite import apply_restriction
from agentgate.events.models import RawToolCall, ToolExecutionResult, ToolSecurityEvent, utc_now
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.policy.models import DecisionAction, SecurityDecision, Severity
from agentgate.runtime.context import RuntimeContext
from agentgate.runtime.models import RuntimeOutcome
from agentgate.runtime.modules import StatefulRiskControl, ToolCallSecurityEventAbstraction
from agentgate.state.manager import StateManager
from agentgate.state.models import SessionSecurityState


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
        self.research_debug = research_debug
        self.event_abstraction = ToolCallSecurityEventAbstraction(
            registry,
            event_builder,
            self.content_scanner,
            content_mode,
        )
        self.risk_control = StatefulRiskControl(
            detector,
            self.authorizer,
            self.authorization_store,
        )

    async def aclose(self) -> None:
        closed: set[int] = set()
        for component in (
            self.state_manager.store,
            self.detector.detection_store,
            self.coordinator,
        ):
            if id(component) in closed:
                continue
            closed.add(id(component))
            close = getattr(component, "aclose", None)
            if close is not None:
                await close()

    async def evaluate(
        self,
        call: RawToolCall,
        runtime_context: RuntimeContext | None = None,
    ) -> RuntimeOutcome:
        """Return an advisory preview; it has no side effect and provides no mediation guarantee."""
        context, trusted_call = _resolve_context(call, runtime_context)
        trusted_call = trusted_call.model_copy(update={"timestamp": utc_now()})
        outcome = await self._evaluate(trusted_call, context)
        return outcome.model_copy(update={"advisory_only": True})

    async def execute(
        self,
        call: RawToolCall,
        runtime_context: RuntimeContext | None = None,
    ) -> RuntimeOutcome:
        context, trusted_call = _resolve_context(call, runtime_context)
        async with self.coordinator.lock(context.principal, context.session_id):
            trusted_call = trusted_call.model_copy(update={"timestamp": utc_now()})
            definition = self.registry.get(trusted_call.tool_name)
            if definition.executor is None:
                raise RuntimeError(f"tool has no executor: {trusted_call.tool_name}")

            outcome = await self._evaluate(trusted_call, context)
            decision = outcome.decision
            request_event = outcome.request_event
            effective_call = trusted_call

            if decision.rewritten_arguments is not None and decision.action != DecisionAction.BLOCK:
                arguments = apply_restriction(
                    trusted_call.arguments,
                    decision.rewritten_arguments,
                )
                effective_call = trusted_call.model_copy(update={"arguments": arguments})
                restricted = await self._evaluate(effective_call, context)
                decision = merge_decisions([decision, restricted.decision])
                request_event = restricted.request_event

            if decision.action == DecisionAction.REQUIRE_APPROVAL:
                approved = await self.approvals.consume(effective_call)
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
                    decision = SecurityDecision(
                        action=DecisionAction.BLOCK,
                        rule_ids=[*decision.rule_ids, "invalid_approval"],
                        reasons=[
                            *decision.reasons,
                            "The approval token is invalid or expired.",
                        ],
                        severity=Severity.HIGH,
                        matched_event_ids=decision.matched_event_ids,
                        matched_object_ids=decision.matched_object_ids,
                        state_facts=decision.state_facts,
                        relation_evidence=decision.relation_evidence,
                    )
                else:
                    approval = await self.approvals.ensure_request(effective_call)
                    decision = decision.model_copy(update={"approval_id": approval.approval_id})
                    await self._log(
                        AuditEventType.APPROVAL,
                        request_event,
                        {"approval_id": approval.approval_id, "status": approval.status.value},
                    )
                await self._log_decision(request_event, decision)

            if not decision.permits_execution:
                return RuntimeOutcome(
                    decision=decision,
                    request_event=request_event,
                    advisory_only=False,
                )

            execution = (await _execute(definition, effective_call.arguments)).model_copy(
                update={"timestamp": utc_now()}
            )
            normalized = self.event_abstraction.build_result(
                request_event,
                execution,
                definition.capability,
            )
            result_event = normalized.event

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
                AuditEventType.STATE_UPDATE,
                result_event,
                {
                    "state": _state_summary(state),
                    "detection_state_updated": detection_updated,
                },
            )
            return RuntimeOutcome(
                decision=decision,
                request_event=request_event,
                execution=normalized.execution,
                result_event=result_event,
                state_updated=True,
                detection_state_updated=detection_updated,
                content_findings=normalized.content_findings,
                result_sanitized=normalized.sanitized,
                advisory_only=False,
            )

    async def _evaluate(
        self,
        call: RawToolCall,
        context: RuntimeContext,
    ) -> RuntimeOutcome:
        state = await self.state_manager.get(context.principal, context.session_id)
        detection_state = await self.detector.sequences.get_state(
            context.principal,
            context.session_id,
        )
        _, event = self.event_abstraction.build_request(call, state, context)
        await self._log(
            AuditEventType.CALL_REQUEST,
            event,
            {"event": self._event_summary(event)},
        )
        decision = await self.risk_control.evaluate(
            event,
            state,
            context,
            detection_state,
        )
        await self._log_decision(event, decision)
        return RuntimeOutcome(
            decision=decision,
            request_event=event,
            advisory_only=False,
        )

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
    call: RawToolCall,
    supplied: RuntimeContext | None,
) -> tuple[RuntimeContext, RawToolCall]:
    context = supplied or RuntimeContext(
        principal=call.principal,
        session_id=call.session_id,
        agent_id=call.agent_id,
        task_id=call.task_id,
        parent_call_id=call.parent_call_id,
    )
    trusted_call = call.model_copy(
        update={
            "principal": context.principal,
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
