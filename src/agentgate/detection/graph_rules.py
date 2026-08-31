from __future__ import annotations

from datetime import timedelta

from agentgate.detection.conditions import event_matches
from agentgate.events import ToolSecurityEvent
from agentgate.graph import (
    AgentTransitionGraph,
    CandidateGraphExtension,
    DataObjectNode,
    GraphEdgeType,
    ToolEventNode,
    ToolEventStatus,
)
from agentgate.graph.models import data_node_id
from agentgate.policy import (
    AggregateMetric,
    AggregateRule,
    GraphPatternRule,
    SecurityDecision,
)


class GraphPatternEngine:
    def __init__(self, rules: list[GraphPatternRule]):
        self.rules = rules

    def evaluate(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
    ) -> list[SecurityDecision]:
        event = candidate.request_event
        consumed = self._consumed_nodes(graph, candidate)
        labels = {label for node in consumed for label in node.labels}
        decisions: list[SecurityDecision] = []
        for rule in self.rules:
            scoped = [node for node in consumed if self._in_scope(node, event, rule)]
            scoped_labels = {label for node in scoped for label in node.labels}
            if not event_matches(event, rule.trigger):
                continue
            if rule.consumed_labels and not rule.consumed_labels.issubset(scoped_labels):
                continue
            node_ids, edge_ids = _evidence_path(graph, scoped)
            decisions.append(
                SecurityDecision(
                    action=rule.action,
                    rule_ids=[rule.id],
                    reasons=[rule.reason],
                    severity=rule.severity,
                    matched_event_ids=[event.call_id],
                    matched_object_ids=[node.object_id for node in scoped],
                    matched_node_ids=[candidate.event_node_id, *node_ids],
                    matched_edge_ids=edge_ids,
                    propagated_labels=sorted(labels & scoped_labels, key=str),
                    relation_evidence=["atg_consumes", "atg_label_propagation"],
                )
            )
        return decisions

    @staticmethod
    def _consumed_nodes(
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
    ) -> list[DataObjectNode]:
        return [
            node
            for object_id in candidate.consumed_object_ids
            if isinstance((node := graph.nodes.get(data_node_id(object_id))), DataObjectNode)
        ]

    @staticmethod
    def _in_scope(
        node: DataObjectNode,
        event: ToolSecurityEvent,
        rule: GraphPatternRule,
    ) -> bool:
        if rule.scope.same_task and node.task_id != event.task_id:
            return False
        if rule.scope.same_agent and node.agent_id != event.agent_id:
            return False
        return True


class GraphAggregateEngine:
    def __init__(self, rules: list[AggregateRule]):
        self.rules = rules

    def evaluate(
        self,
        graph: AgentTransitionGraph,
        event: ToolSecurityEvent,
    ) -> list[SecurityDecision]:
        output: list[SecurityDecision] = []
        for rule in self.rules:
            if not event_matches(event, rule.condition):
                continue
            start = event.timestamp - timedelta(seconds=rule.window_seconds)
            matched = [
                node
                for operation in rule.condition.operations or {event.operation}
                for node_id in graph.index.events_by_operation.get(operation.value, set())
                if isinstance((node := graph.nodes.get(node_id)), ToolEventNode)
                and node.status == ToolEventStatus.SUCCESS
                and node.task_id == event.task_id
                and start <= node.timestamp <= event.timestamp
                and event_matches(node, rule.condition)
            ]
            if rule.metric == AggregateMetric.EVENT_COUNT:
                projected = len(matched) + 1
            else:
                previous = sum(max(1, node.affected_count) for node in matched)
                requested = int((event.scope or {}).get("count", event.affected_count or 1))
                projected = previous + max(1, requested)
            if projected <= rule.threshold:
                continue
            output.append(
                SecurityDecision(
                    action=rule.action,
                    rule_ids=[rule.id],
                    reasons=[
                        f"{rule.reason} Projected {rule.metric.value.lower()}={projected} "
                        f"within {rule.window_seconds}s exceeds {rule.threshold}."
                    ],
                    severity=rule.severity,
                    matched_node_ids=[node.node_id for node in matched],
                    matched_event_ids=[node.call_id for node in matched],
                    relation_evidence=["atg_event_window"],
                )
            )
        return output


def untrusted_context_decision(
    graph: AgentTransitionGraph,
    event: ToolSecurityEvent,
) -> SecurityDecision | None:
    """Return weak temporal evidence when no direct data/control dependency is known."""
    if event.operation.value not in {"SEND", "EXECUTE", "DELETE", "AUTH", "INSTALL"}:
        return None
    candidates = [
        node
        for node_id in graph.index.events_by_task.get(event.task_id or "", set())
        if isinstance((node := graph.nodes.get(node_id)), ToolEventNode)
        and node.status == ToolEventStatus.SUCCESS
        and node.operation.value == "READ"
        and (node.untrusted_context or node.trust_domain.value == "UNKNOWN_EXTERNAL")
    ]
    if not candidates:
        return None
    latest = max(candidates, key=lambda item: (item.timestamp, item.node_id))
    return SecurityDecision(
        action="AUDIT",
        rule_ids=["untrusted_context_high_risk"],
        reasons=[
            "A high-impact operation follows untrusted input; no direct dependency was proven."
        ],
        severity="HIGH",
        matched_event_ids=[latest.call_id, event.call_id],
        matched_node_ids=[latest.node_id],
        relation_evidence=["atg_same_task_temporal_context", "dependency_unresolved"],
    )


def _evidence_path(
    graph: AgentTransitionGraph,
    consumed: list[DataObjectNode],
) -> tuple[list[str], list[str]]:
    pending = [node.node_id for node in consumed]
    nodes: set[str] = set(pending)
    edges: set[str] = set()
    while pending:
        node_id = pending.pop()
        for edge_id in graph.index.outgoing.get(node_id, []):
            edge = graph.edges[edge_id]
            if edge.edge_type != GraphEdgeType.DERIVES_FROM:
                continue
            edges.add(edge_id)
            if edge.target_id not in nodes:
                nodes.add(edge.target_id)
                pending.append(edge.target_id)
        for edge_id in graph.index.incoming.get(node_id, []):
            edge = graph.edges[edge_id]
            if edge.edge_type == GraphEdgeType.PRODUCES:
                edges.add(edge_id)
                nodes.add(edge.source_id)
    return sorted(nodes), sorted(edges)
