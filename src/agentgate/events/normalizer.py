from __future__ import annotations

from collections.abc import Iterable

from agentgate.capabilities.models import ToolCapability
from agentgate.events.argument_binding import ArgumentBinder
from agentgate.events.models import (
    EventPhase,
    RawToolCall,
    SecurityAction,
    ToolExecutionResult,
    ToolSecurityEvent,
)
from agentgate.events.operation_classifier import select_operation
from agentgate.events.result_classifier import ResultClassifier
from agentgate.runtime.context import RuntimeContext
from agentgate.semantics.models import CanonicalToolCall
from agentgate.state.models import SensitiveObject


class ToolEventBuilder:
    def __init__(
        self,
        *,
        internal_domains: set[str] | None = None,
        trusted_external_domains: set[str] | None = None,
        binder: ArgumentBinder | None = None,
        result_classifier: ResultClassifier | None = None,
    ):
        self.binder = binder or ArgumentBinder(
            internal_domains=internal_domains,
            trusted_external_domains=trusted_external_domains,
        )
        self.result_classifier = result_classifier or ResultClassifier()

    def build_request(
        self,
        call: RawToolCall | CanonicalToolCall,
        capability: ToolCapability,
        sensitive_objects: Iterable[SensitiveObject] = (),
        runtime_context: RuntimeContext | None = None,
    ) -> ToolSecurityEvent:
        raw_call = call.to_raw() if isinstance(call, CanonicalToolCall) else call
        context = runtime_context or RuntimeContext(
            principal=raw_call.principal,
            session_id=raw_call.session_id,
            agent_id=raw_call.agent_id,
            task_id=raw_call.task_id,
            parent_call_id=raw_call.parent_call_id,
        )
        scoped_objects = [item for item in sensitive_objects if item.task_id == context.task_id]
        operation = select_operation(raw_call, capability)
        bound = self.binder.bind(raw_call, capability, operation, scoped_objects)
        hints = {item.upper() for item in raw_call.context_hints}
        trusted_labels = {item.upper() for item in context.trusted_source_labels}
        event = ToolSecurityEvent(
            phase=EventPhase.REQUEST,
            principal=context.principal,
            session_id=context.session_id,
            call_id=raw_call.call_id,
            agent_id=context.agent_id,
            task_id=context.task_id,
            parent_call_id=context.parent_call_id,
            tool_name=raw_call.tool_name,
            source_framework=(
                call.source_framework if isinstance(call, CanonicalToolCall) else "legacy"
            ),
            source_transport=(
                call.source_transport if isinstance(call, CanonicalToolCall) else None
            ),
            source_metadata=(call.metadata if isinstance(call, CanonicalToolCall) else {}),
            operation=operation,
            operation_subtype=capability.operation_subtypes.get(operation),
            resource_type=capability.resource_type,
            resource_id=bound.resource_id,
            scope=bound.scope,
            operand={
                "resource": bound.resource_id,
                "scope": bound.scope,
                "destination": bound.destination,
                "payload_fields": list(capability.payload_args),
            },
            data_objects=bound.object_ids,
            input_data_objects=bound.object_ids,
            data_types=bound.data_types,
            sensitivity=set(bound.data_types),
            destination=bound.destination,
            destination_type=bound.destination_type,
            trust_domain=bound.trust_domain,
            effects=bound.effects,
            arguments=raw_call.arguments,
            trusted_source_labels=trusted_labels,
            context_hints=hints,
            trust_evidence=[f"caller_hint:{item}" for item in sorted(hints)],
            untrusted_context=(
                bool(hints & {"UNTRUSTED", "UNTRUSTED_CONTENT", "PROMPT_INJECTION"})
                or "UNTRUSTED" in trusted_labels
                or "UNTRUSTED_CONTENT" in trusted_labels
            ),
            confidence=capability.confidence,
            evidence=list(capability.evidence),
            timestamp=raw_call.timestamp,
        )
        if capability.composite_operations:
            event.actions.extend(
                SecurityAction(
                    operation=item,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    data_objects=list(event.input_data_objects),
                    data_types=set(event.data_types),
                    destination=event.destination,
                    destination_type=event.destination_type,
                    trust_domain=event.trust_domain,
                    effects=set(event.effects),
                    confidence=event.confidence,
                    evidence=[*event.evidence, "capability_composite_operation"],
                )
                for item in capability.composite_operations
                if item != event.operation
            )
        return event

    def build_result(
        self,
        request: ToolSecurityEvent,
        execution: ToolExecutionResult,
        capability: ToolCapability,
    ) -> ToolSecurityEvent:
        return self.result_classifier.classify(request, execution, capability)
