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
from agentgate.modules.trajectory.state import GraphEdge, GraphNode, InMemoryStateStore


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
        state = self.store.get(call.session_id, call.principal)
        if state.isolated:
            return _deny("session_isolated", "trajectory")

        inherited = set(call.data_labels)
        inherited.update(contains_tracked_data(call.arguments, state.labels_by_value))
        reasons: list[str] = []

        if call.approval_token and (
            call.approval_token in state.used_approvals
            or call.approval_token in self.store.used_approvals
        ):
            reasons.append("approval_replay")

        external = "external_transmission" in effect.effects or effect.destination not in {
            "agent_context",
            "internal",
        }
        if external and inherited & {
            Sensitivity.PERSONAL,
            Sensitivity.CREDENTIAL,
            Sensitivity.FINANCIAL,
            Sensitivity.RESTRICTED,
        }:
            reasons.append("sensitive_source_to_external_sink")

        if Action.READ in state.actions and Action.EXECUTE == effect.action and (
            Sensitivity.CREDENTIAL in inherited
            or any("credential" in edge.relation for edge in state.edges)
        ):
            reasons.append("credential_to_privileged_tool")

        projected_personal = state.personal_records_read
        if profile.output_sensitivity & {Sensitivity.PERSONAL} and effect.action == Action.READ:
            projected_personal += effect.record_count
        if projected_personal > self.settings.personal_record_budget:
            reasons.append("personal_record_budget_exceeded")
        if (
            external
            and state.external_transmissions + 1 > self.settings.external_transmission_budget
        ):
            reasons.append("external_transmission_budget_exceeded")
        if effect.action in {Action.DELETE, Action.EXECUTE, Action.CONFIGURE} and (
            state.privileged_operations + 1 > self.settings.privileged_operation_budget
        ):
            reasons.append("privileged_operation_budget_exceeded")

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

    async def observe_result(
        self,
        call: ToolCall,
        effect: CallEffect,
        profile: ToolProfile,
        result: ToolResult,
    ) -> ToolResult:
        state = self.store.get(call.session_id, call.principal)
        deterministic_labels = set(result.data_labels) | label_output(result.output, profile)
        assessment = await self.sensitivity_classifier.classify(
            result.output,
            profile,
            deterministic_labels,
        )
        labels = assessment.labels
        result.data_labels = labels
        result.security_metadata["sensitivity"] = assessment.model_dump(mode="json")
        state.actions.append(effect.action)
        if labels & {Sensitivity.PERSONAL} and effect.action == Action.READ:
            state.personal_records_read += max(1, result.record_count or effect.record_count)
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
        return result


def _deny(reason: str, module: str) -> Decision:
    return Decision(
        action=DecisionAction.DENY,
        risk_types=[reason],
        reasons=[reason],
        module=module,
    )
