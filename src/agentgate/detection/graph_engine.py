from __future__ import annotations

from time import perf_counter

from agentgate.detection.engine import merge_decisions
from agentgate.detection.graph_models import (
    GraphRiskEvaluation,
    GraphRiskResolver,
)
from agentgate.detection.graph_rules import (
    GraphAggregateEngine,
    GraphPatternEngine,
    untrusted_context_decision,
)
from agentgate.detection.single_call import SingleCallDetector
from agentgate.graph import AgentTransitionGraph, CandidateGraphExtension
from agentgate.policy import DecisionAction, SecurityDecision, SecurityPolicy, Severity
from agentgate.state import SessionSecurityState


class GraphRiskEngine:
    """Evaluate the committed ATG plus one non-committed request extension."""

    def __init__(
        self,
        policy: SecurityPolicy,
        resolver: GraphRiskResolver | None = None,
        *,
        resolver_confidence_threshold: float = 0.8,
    ):
        self.policy = policy
        self.single_call = SingleCallDetector(
            policy.single_call,
            policy.event_rules,
            policy.access_rules,
        )
        self.patterns = GraphPatternEngine(policy.graph_rules)
        self.aggregates = GraphAggregateEngine(policy.aggregate_rules)
        self.resolver = resolver
        self.resolver_confidence_threshold = resolver_confidence_threshold

    async def evaluate(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
    ) -> GraphRiskEvaluation:
        event = candidate.request_event
        decisions = [
            self.single_call.evaluate(
                event,
                SessionSecurityState(principal=event.principal, session_id=event.session_id),
            )
        ]
        decisions.extend(self.patterns.evaluate(graph, candidate))
        decisions.extend(self.aggregates.evaluate(graph, event))
        contextual = untrusted_context_decision(graph, event)
        if contextual is not None and not any(
            item.action == DecisionAction.BLOCK for item in decisions
        ):
            decisions.append(contextual)
        llm_called = False
        llm_reason = None
        llm_latency_ms = None
        if (
            candidate.unresolved_dependency
            and self.resolver is not None
            and not any(item.action == DecisionAction.BLOCK for item in decisions)
        ):
            llm_called = True
            llm_reason = "ambiguous_local_graph_dependency"
            started = perf_counter()
            resolution = await self.resolver.resolve(
                local_subgraph=_local_subgraph(graph, event.task_id),
                candidate_event=event.model_dump(mode="json", exclude={"arguments", "result"}),
                reason=llm_reason,
            )
            llm_latency_ms = (perf_counter() - started) * 1000
            if (
                resolution is not None
                and resolution.confidence >= self.resolver_confidence_threshold
            ):
                decisions.append(
                    SecurityDecision(
                        action=DecisionAction.AUDIT,
                        rule_ids=["llm_graph_relation_evidence"],
                        reasons=[resolution.explanation],
                        severity=Severity.MEDIUM,
                        matched_node_ids=resolution.evidence_node_ids,
                        relation_evidence=[
                            f"llm_relation_supported:{resolution.relation_supported}",
                            f"llm_confidence:{resolution.confidence:.3f}",
                        ],
                    )
                )
        return GraphRiskEvaluation(
            decision=merge_decisions(decisions),
            candidate=candidate,
            llm_called=llm_called,
            llm_reason=llm_reason,
            llm_latency_ms=llm_latency_ms,
        )


def _local_subgraph(graph: AgentTransitionGraph, task_id: str | None) -> dict:
    node_ids = set(graph.index.events_by_task.get(task_id or "", set()))
    node_ids.update(graph.index.data_by_task.get(task_id or "", set()))
    for node_id in list(node_ids):
        for edge_id in graph.index.incoming.get(node_id, []):
            node_ids.add(graph.edges[edge_id].source_id)
        for edge_id in graph.index.outgoing.get(node_id, []):
            node_ids.add(graph.edges[edge_id].target_id)
    selected = sorted(
        (graph.nodes[node_id] for node_id in node_ids),
        key=lambda item: (item.updated_at, item.node_id),
    )[-50:]
    nodes = [node.model_dump(mode="json", exclude={"fingerprints"}) for node in selected]
    node_ids = {node["node_id"] for node in nodes}
    edges = [
        edge.model_dump(mode="json")
        for edge in graph.edges.values()
        if edge.source_id in node_ids and edge.target_id in node_ids
    ][-100:]
    return {"graph_id": graph.graph_id, "nodes": nodes, "edges": edges}
