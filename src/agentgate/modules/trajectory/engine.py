from __future__ import annotations

from agentgate.config import AgentGateSettings
from agentgate.llm import LLMAnalyzer
from agentgate.models import (
    Action,
    CallEffect,
    Decision,
    DecisionAction,
    Sensitivity,
    ToolCall,
    ToolProfile,
    ToolResult,
)
from agentgate.modules.trajectory.labels import (
    contains_tracked_data,
    label_output,
    track_fragments,
)
from agentgate.modules.trajectory.semantic_labels import SemanticSensitivityClassifier
from agentgate.modules.trajectory.state import (
    ExecutionReservation,
    GraphEdge,
    GraphNode,
    InMemoryStateStore,
    SessionState,
)


class TrajectoryModule:
    def __init__(
        self,
        settings: AgentGateSettings,
        store: InMemoryStateStore | None = None,
        sensitivity_classifier: SemanticSensitivityClassifier | None = None,
        llm: LLMAnalyzer | None = None,
    ):
        self.settings = settings
        self.store = store or InMemoryStateStore()
        self.sensitivity_classifier = sensitivity_classifier or SemanticSensitivityClassifier(
            llm,
            confidence_threshold=settings.semantic_confidence_threshold,
        )

    async def inspect_call(
        self, call: ToolCall, effect: CallEffect, profile: ToolProfile
    ) -> Decision:
        async with self.store.lock:
            state = self.store.get(call.session_id, call.principal)
            reasons, inherited = self._risk_reasons(state, call, effect, profile)

        if reasons:
            return Decision(
                action=DecisionAction.DENY,
                risk_types=reasons,
                reasons=reasons,
                evidence={"inherited_labels": sorted(label.value for label in inherited)},
                module="trajectory",
            )
        return Decision(
            action=DecisionAction.ALLOW,
            evidence={"inherited_labels": sorted(label.value for label in inherited)},
            module="trajectory",
        )

    async def reserve_call(
        self,
        call: ToolCall,
        effect: CallEffect,
        profile: ToolProfile,
    ) -> Decision:
        """Atomically recheck state and reserve approval/budget before side effects."""

        async with self.store.lock:
            state = self.store.get(call.session_id, call.principal)
            if call.call_id in state.reservations:
                return _deny("duplicate_call_id", "trajectory")
            reasons, inherited = self._risk_reasons(state, call, effect, profile)
            if reasons:
                return Decision(
                    action=DecisionAction.DENY,
                    risk_types=reasons,
                    reasons=reasons,
                    evidence={"inherited_labels": sorted(label.value for label in inherited)},
                    module="trajectory",
                )

            reservation = _reservation_for(call, effect, profile)
            state.personal_records_read += reservation.personal_records
            state.external_transmissions += reservation.external_transmissions
            state.privileged_operations += reservation.privileged_operations
            if reservation.approval_token:
                state.used_approvals.add(reservation.approval_token)
                self.store.used_approvals.add(reservation.approval_token)
            state.reservations[call.call_id] = reservation

        return Decision(
            action=DecisionAction.ALLOW,
            evidence={
                "reservation": {
                    "personal_records": reservation.personal_records,
                    "external_transmissions": reservation.external_transmissions,
                    "privileged_operations": reservation.privileged_operations,
                    "approval_reserved": reservation.approval_token is not None,
                }
            },
            module="trajectory",
        )

    async def observe_result(
        self,
        call: ToolCall,
        effect: CallEffect,
        profile: ToolProfile,
        result: ToolResult,
    ) -> ToolResult:
        deterministic_labels = set(result.data_labels) | label_output(result.output, profile)
        assessment = await self.sensitivity_classifier.classify(
            result.output,
            profile,
            deterministic_labels,
        )
        labels = assessment.labels
        result.data_labels = labels
        result.security_metadata["sensitivity"] = assessment.model_dump(mode="json")
        post_violations: list[str] = []
        async with self.store.lock:
            state = self.store.get(call.session_id, call.principal)
            reservation = state.reservations.pop(call.call_id, None)
            state.actions.append(effect.action)

            actual_personal = 0
            if labels & {Sensitivity.PERSONAL} and effect.action == Action.READ:
                actual_personal = max(1, result.record_count or effect.record_count)
            reserved_personal = reservation.personal_records if reservation else 0
            additional_personal = max(0, actual_personal - reserved_personal)
            if (
                additional_personal
                and state.personal_records_read + additional_personal
                > self.settings.personal_record_budget
            ):
                post_violations.append("personal_record_budget_exceeded_after_result")
                state.isolated = True
            state.personal_records_read += additional_personal

            if reservation is None:
                if effect.action == Action.TRANSMIT or "external_transmission" in effect.effects:
                    state.external_transmissions += 1
                if effect.action in {Action.DELETE, Action.EXECUTE, Action.CONFIGURE}:
                    state.privileged_operations += 1
                if call.approval_token:
                    state.used_approvals.add(call.approval_token)
                    self.store.used_approvals.add(call.approval_token)
            state.labels_by_value.update(track_fragments(result.output, labels))

            call_node = f"call:{call.call_id}"
            tool_node = f"tool:{call.tool_name}"
            resource_node = f"resource:{effect.resource}"
            state.nodes[call_node] = GraphNode(
                call_node,
                "call",
                {
                    "action": effect.action.value,
                    "sensitivity_source": assessment.source,
                    "sensitivity_confidence": assessment.confidence,
                },
            )
            state.nodes[tool_node] = GraphNode(tool_node, "tool")
            state.nodes[resource_node] = GraphNode(resource_node, "resource")
            state.edges.append(GraphEdge(tool_node, call_node, "invoked", labels))
            relation = "credential_read" if Sensitivity.CREDENTIAL in labels else "data_read"
            state.edges.append(GraphEdge(resource_node, call_node, relation, labels))
            if effect.destination not in {"agent_context", "internal"}:
                sink = f"sink:{effect.destination}"
                state.nodes[sink] = GraphNode(sink, "sink")
                state.edges.append(GraphEdge(call_node, sink, "transmitted", labels))
        if post_violations:
            result.security_metadata["trajectory_violations"] = post_violations
        return result

    def _risk_reasons(
        self,
        state: SessionState,
        call: ToolCall,
        effect: CallEffect,
        profile: ToolProfile,
    ) -> tuple[list[str], set[Sensitivity]]:
        if state.isolated:
            return ["session_isolated"], set()

        inherited = set(call.data_labels)
        inherited.update(contains_tracked_data(call.arguments, state.labels_by_value))
        reasons: list[str] = []
        if call.approval_token and (
            call.approval_token in state.used_approvals
            or call.approval_token in self.store.used_approvals
        ):
            reasons.append("approval_replay")

        external = _is_external(effect)
        if external and inherited & {
            Sensitivity.PERSONAL,
            Sensitivity.CREDENTIAL,
            Sensitivity.FINANCIAL,
            Sensitivity.RESTRICTED,
        }:
            reasons.append("sensitive_source_to_external_sink")
        if (
            Action.READ in state.actions
            and Action.EXECUTE == effect.action
            and (
                Sensitivity.CREDENTIAL in inherited
                or any("credential" in edge.relation for edge in state.edges)
            )
        ):
            reasons.append("credential_to_privileged_tool")

        reservation = _reservation_for(call, effect, profile)
        if (
            state.personal_records_read + reservation.personal_records
            > self.settings.personal_record_budget
        ):
            reasons.append("personal_record_budget_exceeded")
        if (
            state.external_transmissions + reservation.external_transmissions
            > self.settings.external_transmission_budget
        ):
            reasons.append("external_transmission_budget_exceeded")
        if (
            state.privileged_operations + reservation.privileged_operations
            > self.settings.privileged_operation_budget
        ):
            reasons.append("privileged_operation_budget_exceeded")
        return reasons, inherited


def _deny(reason: str, module: str) -> Decision:
    return Decision(
        action=DecisionAction.DENY,
        risk_types=[reason],
        reasons=[reason],
        module=module,
    )


def _is_external(effect: CallEffect) -> bool:
    return "external_transmission" in effect.effects or effect.destination not in {
        "agent_context",
        "internal",
    }


def _reservation_for(
    call: ToolCall,
    effect: CallEffect,
    profile: ToolProfile,
) -> ExecutionReservation:
    personal_records = 0
    if Sensitivity.PERSONAL in profile.output_sensitivity and effect.action == Action.READ:
        personal_records = effect.record_count
    return ExecutionReservation(
        personal_records=personal_records,
        external_transmissions=1 if _is_external(effect) else 0,
        privileged_operations=(
            1 if effect.action in {Action.DELETE, Action.EXECUTE, Action.CONFIGURE} else 0
        ),
        approval_token=call.approval_token,
    )
