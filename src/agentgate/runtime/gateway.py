from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from agentgate.audit.jsonl import event_summary
from agentgate.audit.models import AuditEventType, AuditRecord
from agentgate.audit.store import AuditStore
from agentgate.authorization import TaskAuthorizer, TaskContract
from agentgate.capabilities.registry import CapabilityRegistry, ToolDefinition
from agentgate.content import ContentScanner
from agentgate.detection.engine import DetectionEngine, merge_decisions
from agentgate.enforcement.approval import ApprovalManager
from agentgate.enforcement.rewrite import apply_restriction
from agentgate.events.models import RawToolCall, ToolExecutionResult, ToolSecurityEvent
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.policy.models import DecisionAction, SecurityDecision, Severity
from agentgate.runtime.models import RuntimeOutcome
from agentgate.state.manager import StateManager
from agentgate.state.models import SessionSecurityState


class AgentGateRuntime:
    """Reference monitor that mediates every supported tool execution path."""

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
        content_scanner: ContentScanner | None = None,
    ):
        self.registry = registry
        self.event_builder = event_builder
        self.state_manager = state_manager
        self.detector = detector
        self.approvals = approvals
        self.audit = audit
        self.authorizer = authorizer or TaskAuthorizer()
        self.content_scanner = content_scanner or ContentScanner()
        self._session_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._session_locks_guard = asyncio.Lock()

    async def aclose(self) -> None:
        close = getattr(self.state_manager.store, "aclose", None)
        if close is not None:
            await close()

    async def evaluate(self, call: RawToolCall) -> RuntimeOutcome:
        definition = self.registry.get(call.tool_name)
        state = await self.state_manager.get(call.principal, call.session_id)
        event = self.event_builder.build_request(
            call,
            definition.capability,
            state.sensitive_objects.values(),
        )
        await self._log(
            AuditEventType.CALL_REQUEST,
            event,
            {"event": self._event_summary(event)},
        )
        decision = await self.detector.evaluate(event, state)
        if call.task_contract is not None:
            contract_decision = self.authorizer.evaluate(
                event,
                TaskContract.model_validate(call.task_contract),
            )
            decision = merge_decisions([decision, contract_decision])
        await self._log_decision(event, decision)
        return RuntimeOutcome(decision=decision, request_event=event)

    async def execute(self, call: RawToolCall) -> RuntimeOutcome:
        async with self._session_lock(call.principal, call.session_id):
            definition = self.registry.get(call.tool_name)
            if definition.executor is None:
                raise RuntimeError(f"tool has no executor: {call.tool_name}")
            outcome = await self.evaluate(call)
            decision = outcome.decision
            request_event = outcome.request_event
            effective_call = call

            if decision.rewritten_arguments is not None and decision.action not in {
                DecisionAction.BLOCK,
                DecisionAction.ISOLATE,
            }:
                arguments = apply_restriction(call.arguments, decision.rewritten_arguments)
                effective_call = call.model_copy(update={"arguments": arguments})
                restricted = await self.evaluate(effective_call)
                decision = merge_decisions([decision, restricted.decision])
                request_event = restricted.request_event

            if decision.action == DecisionAction.REQUIRE_APPROVAL:
                approved = await self.approvals.consume(call)
                if approved:
                    decision = SecurityDecision(
                        action=DecisionAction.ALLOW,
                        rule_ids=decision.rule_ids,
                        reasons=[*decision.reasons, "A bound one-time approval was consumed."],
                        severity=decision.severity,
                        rewritten_arguments=decision.rewritten_arguments,
                    )
                    await self._log(
                        AuditEventType.APPROVAL,
                        request_event,
                        {"status": "CONSUMED"},
                    )
                elif call.approval_token:
                    decision = SecurityDecision(
                        action=DecisionAction.BLOCK,
                        rule_ids=[*decision.rule_ids, "invalid_approval"],
                        reasons=[*decision.reasons, "The approval token is invalid or expired."],
                        severity=Severity.HIGH,
                    )
                else:
                    approval = await self.approvals.ensure_request(call)
                    decision = decision.model_copy(update={"approval_id": approval.approval_id})
                    await self._log(
                        AuditEventType.APPROVAL,
                        request_event,
                        {"approval_id": approval.approval_id, "status": approval.status.value},
                    )
                await self._log_decision(request_event, decision)

            if decision.action == DecisionAction.ISOLATE:
                state = await self.state_manager.isolate(call.principal, call.session_id)
                await self._log(
                    AuditEventType.SESSION_ISOLATION,
                    request_event,
                    {"reason": decision.reasons, "state": _state_summary(state)},
                )
                return RuntimeOutcome(
                    decision=decision,
                    request_event=request_event,
                )

            if not decision.permits_execution:
                return RuntimeOutcome(
                    decision=decision,
                    request_event=request_event,
                )

            execution = await _execute(definition, effective_call.arguments)
            content_findings = []
            result_sanitized = False
            if execution.success and (
                definition.capability.untrusted_output or effective_call.untrusted_context
            ):
                analysis = self.content_scanner.scan(execution.output)
                content_findings = analysis.findings
                if content_findings:
                    execution = execution.model_copy(update={"output": analysis.sanitized})
                    result_sanitized = True
            result_event = self.event_builder.build_result(
                request_event,
                execution,
                definition.capability,
            )
            state = await self.state_manager.observe(result_event)
            await self._log(
                AuditEventType.CALL_RESULT,
                result_event,
                {
                    "event": self._event_summary(result_event),
                    "result_sanitized": result_sanitized,
                    "content_findings": [
                        {
                            "risk_type": item.risk_type.value,
                            "severity": item.severity.value,
                            "path": item.path,
                            "source": item.source,
                        }
                        for item in content_findings
                    ],
                },
            )
            await self._log(
                AuditEventType.STATE_UPDATE,
                result_event,
                {"state": _state_summary(state)},
            )
            return RuntimeOutcome(
                decision=decision,
                request_event=request_event,
                execution=execution,
                result_event=result_event,
                state_updated=True,
                content_findings=content_findings,
                result_sanitized=result_sanitized,
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

    @asynccontextmanager
    async def _session_lock(self, principal: str, session_id: str) -> AsyncIterator[None]:
        key = (principal, session_id)
        async with self._session_locks_guard:
            lock = self._session_locks.setdefault(key, asyncio.Lock())
        async with lock:
            yield


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
        "counters": state.counters,
        "sensitive_object_count": len(state.sensitive_objects),
        "sensitive_event_count": len(state.recent_sensitive_events),
        "isolated": state.isolated,
        "updated_at": state.updated_at.isoformat(),
    }
