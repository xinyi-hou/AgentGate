from __future__ import annotations

from hashlib import sha256
from typing import Any

from agentgate.events import (
    DataType,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
)
from agentgate.graph.models import (
    AgentNode,
    AgentTransitionGraph,
    CandidateGraphExtension,
    DataObjectNode,
    GraphDelta,
    GraphEdge,
    GraphEdgeType,
    ResourceNode,
    ToolEventNode,
    ToolEventStatus,
    TrustDomainNode,
    data_node_id,
    event_node_id,
    execution_context_key,
    stable_id,
)
from agentgate.labels.engine import initial_data_labels, propagate_data_labels
from agentgate.provenance import DependencyResolver, DependencySource
from agentgate.state.models import SensitiveObject
from agentgate.state.provenance import (
    argument_fingerprints_for,
    fingerprints_for,
    sensitive_fragments,
)


class AgentTransitionGraphBuilder:
    def __init__(
        self,
        dependency_resolver: DependencyResolver | None = None,
        *,
        dependency_confidence_threshold: float = 0.8,
        max_dependency_candidates: int = 20,
    ):
        self.dependency_resolver = dependency_resolver
        self.dependency_confidence_threshold = dependency_confidence_threshold
        self.max_dependency_candidates = max_dependency_candidates

    async def preview_request(
        self,
        graph: AgentTransitionGraph,
        event: ToolSecurityEvent,
    ) -> CandidateGraphExtension:
        enriched, unresolved = await self._enrich_dependencies(graph, event)
        delta = self._base_delta(graph, enriched, ToolEventStatus.CANDIDATE, candidate=True)
        return CandidateGraphExtension(
            graph_id=graph.graph_id,
            event_node_id=event_node_id(enriched.event_id),
            request_event=enriched,
            delta=delta,
            consumed_object_ids=list(enriched.input_data_objects or enriched.data_objects),
            unresolved_dependency=unresolved,
        )

    def build_result_delta(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
        result_event: ToolSecurityEvent,
    ) -> GraphDelta:
        status = ToolEventStatus.SUCCESS if result_event.success else ToolEventStatus.FAILED
        delta = self._base_delta(graph, result_event, status, candidate=False)
        if not result_event.success:
            delta.reason = "failed_result"
            return delta

        produced = self._create_data_nodes(graph, result_event)
        event_id = event_node_id(result_event.event_id)
        parent_ids = list(result_event.input_data_objects or result_event.data_objects)
        for node in produced:
            delta.nodes.append(node)
            delta.edges.append(
                self._edge(
                    GraphEdgeType.PRODUCES,
                    event_id,
                    node.node_id,
                    result_event,
                    evidence=["successful_result"],
                )
            )
            for parent_id in parent_ids:
                parent_node_id = data_node_id(parent_id)
                if parent_node_id in graph.nodes:
                    delta.edges.append(
                        self._edge(
                            GraphEdgeType.DERIVES_FROM,
                            node.node_id,
                            parent_node_id,
                            result_event,
                            evidence=["input_output_dependency"],
                        )
                    )
        result_event.output_data_objects = [item.object_id for item in produced]
        result_event.data_objects = list(
            dict.fromkeys([*parent_ids, *result_event.output_data_objects])
        )
        delta.reason = "successful_result"
        return delta

    def sensitive_objects(
        self,
        graph: AgentTransitionGraph,
        arguments: dict[str, Any] | None = None,
        task_id: str | None = None,
    ) -> list[SensitiveObject]:
        node_ids = graph.index.data_by_task.get(task_id or "", set())
        if arguments:
            argument_fingerprints = argument_fingerprints_for(arguments)
            fingerprint_ids = {
                node_id
                for fingerprint in argument_fingerprints
                for node_id in graph.index.data_by_fingerprint.get(fingerprint, set())
            }
            node_ids = node_ids & fingerprint_ids
        return [
            SensitiveObject(
                object_id=node.object_id,
                data_type=next(iter(node.data_types), DataType.PUBLIC),
                sensitivity=next(iter(node.data_types), DataType.PUBLIC),
                source_resource=node.source_resource,
                source_field=node.source_field,
                producer_call_id=node.producer_call_id,
                task_id=node.task_id,
                agent_id=node.agent_id,
                parent_object_ids=self.parent_object_ids(graph, node.node_id),
                fingerprints=node.fingerprints,
                created_at=node.created_at,
                last_seen_at=node.last_seen_at,
            )
            for node_id in node_ids
            if isinstance((node := graph.nodes.get(node_id)), DataObjectNode)
        ]

    @staticmethod
    def parent_object_ids(graph: AgentTransitionGraph, node_id: str) -> list[str]:
        return [
            parent.object_id
            for edge_id in graph.index.outgoing.get(node_id, [])
            if (edge := graph.edges[edge_id]).edge_type == GraphEdgeType.DERIVES_FROM
            and isinstance((parent := graph.nodes[edge.target_id]), DataObjectNode)
        ]

    async def _enrich_dependencies(
        self,
        graph: AgentTransitionGraph,
        event: ToolSecurityEvent,
    ) -> tuple[ToolSecurityEvent, bool]:
        existing = list(event.input_data_objects or event.data_objects)
        if existing:
            return event.model_copy(update={"input_data_objects": existing}), False
        if event.operation not in {
            SecurityOperation.WRITE,
            SecurityOperation.SEND,
            SecurityOperation.EXECUTE,
            SecurityOperation.DELETE,
            SecurityOperation.AUTH,
            SecurityOperation.PRIVILEGE,
            SecurityOperation.INSTALL,
        }:
            return event, False
        candidate_ids = graph.index.data_by_task.get(event.task_id or "", set())
        candidates = sorted(
            (
                node
                for node_id in candidate_ids
                if isinstance((node := graph.nodes.get(node_id)), DataObjectNode)
            ),
            key=lambda item: (item.last_seen_at, item.node_id),
        )[-self.max_dependency_candidates :]
        if not candidates:
            return event, False
        if self.dependency_resolver is None:
            return event, True
        inferences = await self.dependency_resolver.resolve(
            sources=[
                DependencySource(
                    object_id=item.object_id,
                    source_resource=item.source_resource,
                    source_field=item.source_field,
                    labels=item.labels,
                    data_types={value.value for value in item.data_types},
                )
                for item in candidates
            ],
            target_arguments=event.arguments or {},
            target_tool=event.tool_name,
            target_operation=event.operation.value,
        )
        candidate_ids = {item.object_id for item in candidates}
        accepted = [
            item
            for item in inferences
            if item.object_id in candidate_ids
            and item.depends_on
            and item.confidence >= self.dependency_confidence_threshold
        ]
        if not accepted:
            return event, True
        object_ids = [item.object_id for item in accepted]
        data_types = set(event.data_types)
        for node in candidates:
            if node.object_id in object_ids:
                data_types.update(node.data_types)
        return event.model_copy(
            update={
                "data_objects": object_ids,
                "input_data_objects": object_ids,
                "data_types": data_types,
                "sensitivity": set(data_types),
                "evidence": [
                    *event.evidence,
                    *(
                        f"llm_dependency:{item.object_id}:{item.confidence:.3f}"
                        for item in accepted
                    ),
                ],
            }
        ), False

    def _base_delta(
        self,
        graph: AgentTransitionGraph,
        event: ToolSecurityEvent,
        status: ToolEventStatus,
        *,
        candidate: bool,
    ) -> GraphDelta:
        agent_id = stable_id("agent", event.principal, event.agent_id or "default")
        tool_event_id = event_node_id(event.event_id)
        nodes: list[Any] = [
            AgentNode(
                node_id=agent_id,
                principal_id=event.principal,
                session_id=event.session_id,
                task_id=event.task_id,
                agent_id=event.agent_id,
                created_at=event.timestamp,
                updated_at=event.timestamp,
            ),
            ToolEventNode(
                node_id=tool_event_id,
                principal_id=event.principal,
                session_id=event.session_id,
                task_id=event.task_id,
                agent_id=event.agent_id,
                event_id=event.event_id,
                call_id=event.call_id,
                parent_call_id=event.parent_call_id,
                tool_name=event.tool_name,
                operation=event.operation,
                phase=event.phase,
                status=status,
                resource_type=event.resource_type,
                trust_domain=event.trust_domain,
                data_types=event.data_types,
                effects=event.effects,
                affected_count=event.affected_count or 0,
                confidence=event.confidence,
                untrusted_context=event.untrusted_context,
                timestamp=event.timestamp,
                created_at=event.timestamp,
                updated_at=event.timestamp,
            ),
        ]
        edges = [self._edge(GraphEdgeType.PERFORMS, agent_id, tool_event_id, event)]
        records_effect_relations = status != ToolEventStatus.FAILED
        if records_effect_relations and event.resource_id:
            resource_id = stable_id("resource", event.resource_type.value, event.resource_id)
            nodes.append(
                ResourceNode(
                    node_id=resource_id,
                    principal_id=event.principal,
                    session_id=event.session_id,
                    task_id=event.task_id,
                    agent_id=event.agent_id,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    trust_domain=event.trust_domain,
                    created_at=event.timestamp,
                    updated_at=event.timestamp,
                )
            )
            edges.append(self._edge(GraphEdgeType.OPERATES_ON, tool_event_id, resource_id, event))
        for object_id in (
            event.input_data_objects or event.data_objects if records_effect_relations else []
        ):
            node_id = data_node_id(object_id)
            if node_id in graph.nodes:
                edges.append(
                    self._edge(
                        GraphEdgeType.CONSUMES,
                        tool_event_id,
                        node_id,
                        event,
                        evidence=["argument_fingerprint_or_semantic_dependency"],
                    )
                )
        if records_effect_relations and event.destination:
            domain_id = stable_id("trust", event.trust_domain.value, event.destination)
            nodes.append(
                TrustDomainNode(
                    node_id=domain_id,
                    principal_id=event.principal,
                    session_id=event.session_id,
                    task_id=event.task_id,
                    agent_id=event.agent_id,
                    domain_id=event.destination,
                    category=event.trust_domain,
                    created_at=event.timestamp,
                    updated_at=event.timestamp,
                )
            )
            edges.append(self._edge(GraphEdgeType.TARGETS, tool_event_id, domain_id, event))

        previous = self._previous_event(graph, event)
        if previous is not None:
            edges.append(self._edge(GraphEdgeType.NEXT, previous.node_id, tool_event_id, event))
        if event.parent_call_id:
            parent_node_id = graph.index.event_by_call.get(event.parent_call_id)
            if parent_node_id:
                edges.append(
                    self._edge(GraphEdgeType.PARENT_OF, parent_node_id, tool_event_id, event)
                )
                parent = graph.nodes[parent_node_id]
                if isinstance(parent, ToolEventNode) and parent.agent_id != event.agent_id:
                    parent_agent_id = stable_id(
                        "agent", event.principal, parent.agent_id or "default"
                    )
                    edges.append(
                        self._edge(
                            GraphEdgeType.DELEGATES_TO,
                            parent_agent_id,
                            agent_id,
                            event,
                            evidence=["cross_agent_parent_call"],
                        )
                    )
        return GraphDelta(
            graph_id=graph.graph_id,
            nodes=nodes,
            edges=edges,
            candidate=candidate,
            reason="request_preview" if candidate else "result",
        )

    def _create_data_nodes(
        self,
        graph: AgentTransitionGraph,
        event: ToolSecurityEvent,
    ) -> list[DataObjectNode]:
        if event.operation not in {SecurityOperation.READ, SecurityOperation.WRITE}:
            return []
        parents = [
            graph.nodes[data_node_id(object_id)]
            for object_id in event.input_data_objects or event.data_objects
            if data_node_id(object_id) in graph.nodes
            and isinstance(graph.nodes[data_node_id(object_id)], DataObjectNode)
        ]
        fragments = (
            sensitive_fragments(event.result, event.data_types)
            if event.operation == SecurityOperation.READ
            else []
        )
        candidates = [
            (path, value, data_type)
            for path, value, types in fragments
            for data_type in sorted(types, key=str)
        ]
        if not candidates:
            candidates = [
                (None, event.result, data_type)
                for data_type in sorted(event.data_types or {DataType.PUBLIC}, key=str)
                if data_type != DataType.PUBLIC or parents or self._external_read(event)
            ]
        nodes: list[DataObjectNode] = []
        for path, value, data_type in candidates:
            identity = f"{event.call_id}:{path or '$'}:{data_type.value}"
            object_id = f"D-{sha256(identity.encode()).hexdigest()[:16]}"
            fingerprints = fingerprints_for(value)
            if event.operation == SecurityOperation.WRITE and event.resource_id:
                fingerprints = sorted(set(fingerprints) | set(fingerprints_for(event.resource_id)))
            node = DataObjectNode(
                node_id=data_node_id(object_id),
                principal_id=event.principal,
                session_id=event.session_id,
                task_id=event.task_id,
                agent_id=event.agent_id,
                object_id=object_id,
                data_types={data_type},
                labels=initial_data_labels(event, {data_type}),
                source_resource=event.resource_id,
                source_field=path,
                producer_call_id=event.call_id,
                fingerprints=fingerprints,
                created_at=event.timestamp,
                updated_at=event.timestamp,
                last_seen_at=event.timestamp,
            )
            nodes.append(propagate_data_labels(node, parents))
        return nodes

    @staticmethod
    def _external_read(event: ToolSecurityEvent) -> bool:
        return event.operation == SecurityOperation.READ and (
            event.untrusted_context
            or event.trust_domain
            in {
                TrustDomain.TRUSTED_EXTERNAL,
                TrustDomain.UNKNOWN_EXTERNAL,
            }
        )

    @staticmethod
    def _previous_event(
        graph: AgentTransitionGraph,
        event: ToolSecurityEvent,
    ) -> ToolEventNode | None:
        node_id = graph.index.latest_event_by_context.get(
            execution_context_key(event.task_id, event.agent_id)
        )
        node = graph.nodes.get(node_id) if node_id else None
        return node if isinstance(node, ToolEventNode) else None

    @staticmethod
    def _edge(
        edge_type: GraphEdgeType,
        source_id: str,
        target_id: str,
        event: ToolSecurityEvent,
        *,
        evidence: list[str] | None = None,
        confidence: float = 1.0,
    ) -> GraphEdge:
        return GraphEdge(
            edge_id=stable_id("edge", edge_type.value, source_id, target_id, event.call_id),
            edge_type=edge_type,
            source_id=source_id,
            target_id=target_id,
            call_id=event.call_id,
            task_id=event.task_id,
            agent_id=event.agent_id,
            confidence=confidence,
            evidence=evidence or [],
            created_at=event.timestamp,
        )
