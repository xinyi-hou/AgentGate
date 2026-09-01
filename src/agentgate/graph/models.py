from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, Field

from agentgate.events import (
    DataType,
    EffectType,
    EventPhase,
    ResourceType,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
    utc_now,
)
from agentgate.labels.models import SecurityLabel


class GraphNodeType(StrEnum):
    AGENT = "AGENT"
    TOOL_EVENT = "TOOL_EVENT"
    RESOURCE = "RESOURCE"
    DATA = "DATA"
    TRUST_DOMAIN = "TRUST_DOMAIN"


class GraphEdgeType(StrEnum):
    NEXT = "NEXT"
    PERFORMS = "PERFORMS"
    OPERATES_ON = "OPERATES_ON"
    PRODUCES = "PRODUCES"
    CONSUMES = "CONSUMES"
    DERIVES_FROM = "DERIVES_FROM"
    TARGETS = "TARGETS"
    DELEGATES_TO = "DELEGATES_TO"
    PARENT_OF = "PARENT_OF"


class ToolEventStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class GraphNode(BaseModel):
    node_id: str
    node_type: GraphNodeType
    principal_id: str
    session_id: str
    task_id: str | None = None
    agent_id: str | None = None
    labels: set[SecurityLabel] = Field(default_factory=set)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AgentNode(GraphNode):
    node_type: Literal[GraphNodeType.AGENT] = GraphNodeType.AGENT
    role: str | None = None


class ToolEventNode(GraphNode):
    node_type: Literal[GraphNodeType.TOOL_EVENT] = GraphNodeType.TOOL_EVENT
    event_id: str
    call_id: str
    parent_call_id: str | None = None
    tool_name: str
    operation: SecurityOperation
    operations: set[SecurityOperation] = Field(default_factory=set)
    phase: EventPhase
    status: ToolEventStatus
    resource_type: ResourceType = ResourceType.UNKNOWN
    trust_domain: TrustDomain = TrustDomain.LOCAL
    data_types: set[DataType] = Field(default_factory=set)
    effects: set[EffectType] = Field(default_factory=set)
    affected_count: int = 0
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    untrusted_context: bool = False
    timestamp: datetime = Field(default_factory=utc_now)


class ResourceNode(GraphNode):
    node_type: Literal[GraphNodeType.RESOURCE] = GraphNodeType.RESOURCE
    resource_type: ResourceType
    resource_id: str
    trust_domain: TrustDomain | None = None


class DataObjectNode(GraphNode):
    node_type: Literal[GraphNodeType.DATA] = GraphNodeType.DATA
    object_id: str
    data_types: set[DataType] = Field(default_factory=set)
    source_resource: str | None = None
    source_field: str | None = None
    producer_call_id: str
    fingerprints: list[str] = Field(default_factory=list)
    last_seen_at: datetime = Field(default_factory=utc_now)


class TrustDomainNode(GraphNode):
    node_type: Literal[GraphNodeType.TRUST_DOMAIN] = GraphNodeType.TRUST_DOMAIN
    domain_id: str
    category: TrustDomain


GraphNodeUnion = Annotated[
    AgentNode | ToolEventNode | ResourceNode | DataObjectNode | TrustDomainNode,
    Field(discriminator="node_type"),
]


class GraphEdge(BaseModel):
    edge_id: str
    edge_type: GraphEdgeType
    source_id: str
    target_id: str
    call_id: str | None = None
    task_id: str | None = None
    agent_id: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class GraphIndex(BaseModel):
    events_by_operation: dict[str, set[str]] = Field(default_factory=dict)
    events_by_task: dict[str, set[str]] = Field(default_factory=dict)
    data_by_label: dict[str, set[str]] = Field(default_factory=dict)
    data_by_task: dict[str, set[str]] = Field(default_factory=dict)
    data_by_fingerprint: dict[str, set[str]] = Field(default_factory=dict)
    latest_event_by_agent: dict[str, str] = Field(default_factory=dict)
    latest_event_by_task: dict[str, str] = Field(default_factory=dict)
    latest_event_by_context: dict[str, str] = Field(default_factory=dict)
    event_by_call: dict[str, str] = Field(default_factory=dict)
    incoming: dict[str, list[str]] = Field(default_factory=dict)
    outgoing: dict[str, list[str]] = Field(default_factory=dict)


class GraphDelta(BaseModel):
    graph_id: str
    nodes: list[GraphNodeUnion] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    candidate: bool = False
    reason: str = ""


class CandidateGraphExtension(BaseModel):
    graph_id: str
    event_node_id: str
    request_event: ToolSecurityEvent
    delta: GraphDelta
    consumed_object_ids: list[str] = Field(default_factory=list)
    unresolved_dependency: bool = False


class AgentTransitionGraph(BaseModel):
    graph_id: str
    principal_id: str
    session_id: str
    nodes: dict[str, GraphNodeUnion] = Field(default_factory=dict)
    edges: dict[str, GraphEdge] = Field(default_factory=dict)
    index: GraphIndex = Field(default_factory=GraphIndex)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @classmethod
    def empty(cls, principal_id: str, session_id: str) -> AgentTransitionGraph:
        return cls(
            graph_id=stable_id("graph", principal_id, session_id),
            principal_id=principal_id,
            session_id=session_id,
        )

    def apply(self, delta: GraphDelta) -> None:
        if delta.graph_id != self.graph_id:
            raise ValueError("graph delta identity mismatch")
        for node in delta.nodes:
            existing = self.nodes.get(node.node_id)
            if existing is not None:
                self._unindex_node(existing)
            if existing is not None and existing.node_type == node.node_type:
                node = node.model_copy(
                    update={
                        "created_at": existing.created_at,
                        "labels": set(existing.labels) | set(node.labels),
                    }
                )
            self.nodes[node.node_id] = node.model_copy(deep=True)
            self._index_node(self.nodes[node.node_id])
        for edge in delta.edges:
            if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
                raise ValueError(f"graph edge references an unknown node: {edge.edge_id}")
            existing_edge = self.edges.get(edge.edge_id)
            if existing_edge is not None:
                self._unindex_edge(existing_edge)
            self.edges[edge.edge_id] = edge.model_copy(deep=True)
            self._index_edge(self.edges[edge.edge_id])
        self.updated_at = utc_now()

    def rebuild_index(self) -> None:
        index = GraphIndex()
        for node in self.nodes.values():
            self._index_node(node, index=index)
        for edge in sorted(self.edges.values(), key=lambda item: (item.created_at, item.edge_id)):
            self._index_edge(edge, index=index)
        self.index = index

    def _index_node(self, node: GraphNodeUnion, *, index: GraphIndex | None = None) -> None:
        target = index or self.index
        if isinstance(node, ToolEventNode):
            target.events_by_operation.setdefault(node.operation.value, set()).add(node.node_id)
            target.events_by_task.setdefault(node.task_id or "", set()).add(node.node_id)
            target.event_by_call[node.call_id] = node.node_id
            self._set_latest(target.latest_event_by_agent, node.agent_id or "", node)
            self._set_latest(target.latest_event_by_task, node.task_id or "", node)
            self._set_latest(
                target.latest_event_by_context,
                execution_context_key(node.task_id, node.agent_id),
                node,
            )
        elif isinstance(node, DataObjectNode):
            target.data_by_task.setdefault(node.task_id or "", set()).add(node.node_id)
            for label in node.labels:
                target.data_by_label.setdefault(label.value, set()).add(node.node_id)
            for fingerprint in node.fingerprints:
                target.data_by_fingerprint.setdefault(fingerprint, set()).add(node.node_id)

    def _unindex_node(self, node: GraphNodeUnion) -> None:
        if isinstance(node, ToolEventNode):
            _discard(self.index.events_by_operation, node.operation.value, node.node_id)
            _discard(self.index.events_by_task, node.task_id or "", node.node_id)
            if self.index.event_by_call.get(node.call_id) == node.node_id:
                self.index.event_by_call.pop(node.call_id, None)
            for mapping, key in (
                (self.index.latest_event_by_agent, node.agent_id or ""),
                (self.index.latest_event_by_task, node.task_id or ""),
                (
                    self.index.latest_event_by_context,
                    execution_context_key(node.task_id, node.agent_id),
                ),
            ):
                if mapping.get(key) == node.node_id:
                    mapping.pop(key, None)
        elif isinstance(node, DataObjectNode):
            _discard(self.index.data_by_task, node.task_id or "", node.node_id)
            for label in node.labels:
                _discard(self.index.data_by_label, label.value, node.node_id)
            for fingerprint in node.fingerprints:
                _discard(self.index.data_by_fingerprint, fingerprint, node.node_id)

    def _index_edge(self, edge: GraphEdge, *, index: GraphIndex | None = None) -> None:
        target = index or self.index
        target.outgoing.setdefault(edge.source_id, []).append(edge.edge_id)
        target.incoming.setdefault(edge.target_id, []).append(edge.edge_id)

    def _unindex_edge(self, edge: GraphEdge) -> None:
        _remove(self.index.outgoing, edge.source_id, edge.edge_id)
        _remove(self.index.incoming, edge.target_id, edge.edge_id)

    def _set_latest(
        self,
        mapping: dict[str, str],
        key: str,
        candidate: ToolEventNode,
    ) -> None:
        current = self.nodes.get(mapping.get(key, ""))
        if not isinstance(current, ToolEventNode) or (
            candidate.timestamp,
            candidate.node_id,
        ) >= (current.timestamp, current.node_id):
            mapping[key] = candidate.node_id


class GraphStore(Protocol):
    async def get_session_graph(
        self,
        principal_id: str,
        session_id: str,
    ) -> AgentTransitionGraph: ...

    async def apply_delta(self, graph_id: str, delta: GraphDelta) -> AgentTransitionGraph: ...

    async def delete(self, principal_id: str, session_id: str) -> None: ...


def stable_id(prefix: str, *parts: str | None) -> str:
    payload = "\0".join(part or "" for part in parts)
    return f"{prefix}:{hashlib.sha256(payload.encode()).hexdigest()[:24]}"


def event_node_id(event_id: str) -> str:
    return f"event:{event_id}"


def data_node_id(object_id: str) -> str:
    return f"data:{object_id}"


def execution_context_key(task_id: str | None, agent_id: str | None) -> str:
    return f"{task_id or ''}\0{agent_id or ''}"


def _discard(mapping: dict[str, set[str]], key: str, value: str) -> None:
    values = mapping.get(key)
    if values is None:
        return
    values.discard(value)
    if not values:
        mapping.pop(key, None)


def _remove(mapping: dict[str, list[str]], key: str, value: str) -> None:
    values = mapping.get(key)
    if values is None:
        return
    mapping[key] = [item for item in values if item != value]
    if not mapping[key]:
        mapping.pop(key, None)
