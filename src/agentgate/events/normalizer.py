from __future__ import annotations

from collections.abc import Iterable

from agentgate.capabilities.models import ToolCapability
from agentgate.events.argument_binding import ArgumentBinder
from agentgate.events.models import (
    EventPhase,
    RawToolCall,
    ToolExecutionResult,
    ToolSecurityEvent,
)
from agentgate.events.operation_classifier import select_operation
from agentgate.events.result_classifier import ResultClassifier
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
        call: RawToolCall,
        capability: ToolCapability,
        sensitive_objects: Iterable[SensitiveObject] = (),
    ) -> ToolSecurityEvent:
        operation = select_operation(call, capability)
        bound = self.binder.bind(call, capability, operation, sensitive_objects)
        return ToolSecurityEvent(
            phase=EventPhase.REQUEST,
            principal=call.principal,
            session_id=call.session_id,
            call_id=call.call_id,
            agent_id=call.agent_id,
            task_id=call.task_id,
            parent_call_id=call.parent_call_id,
            tool_name=call.tool_name,
            operation=operation,
            operation_subtype=capability.operation_subtypes.get(operation),
            resource_type=capability.resource_type,
            resource_id=bound.resource_id,
            scope=bound.scope,
            data_objects=bound.object_ids,
            data_types=bound.data_types,
            sensitivity=set(bound.data_types),
            destination=bound.destination,
            destination_type=bound.destination_type,
            trust_domain=bound.trust_domain,
            effects=bound.effects,
            arguments=call.arguments,
            trusted_context=call.trusted_context,
            untrusted_context=call.untrusted_context,
            timestamp=call.timestamp,
        )

    def build_result(
        self,
        request: ToolSecurityEvent,
        execution: ToolExecutionResult,
        capability: ToolCapability,
    ) -> ToolSecurityEvent:
        return self.result_classifier.classify(request, execution, capability)
