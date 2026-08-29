from __future__ import annotations

import asyncio
from datetime import timedelta

from agentgate.events import utc_now
from agentgate.graph.models import AgentTransitionGraph, GraphDelta


class InMemoryGraphStore:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._graphs: dict[tuple[str, str], AgentTransitionGraph] = {}
        self._graph_keys: dict[str, tuple[str, str]] = {}
        self._lock = asyncio.Lock()

    async def get_session_graph(
        self,
        principal_id: str,
        session_id: str,
    ) -> AgentTransitionGraph:
        async with self._lock:
            graph = self._get_or_create(principal_id, session_id)
            return graph.model_copy(deep=True)

    async def apply_delta(self, graph_id: str, delta: GraphDelta) -> AgentTransitionGraph:
        async with self._lock:
            key = self._graph_keys.get(graph_id)
            if key is None:
                raise KeyError(f"unknown graph: {graph_id}")
            graph = self._graphs[key].model_copy(deep=True)
            graph.apply(delta)
            self._graphs[key] = graph
            return graph.model_copy(deep=True)

    async def delete(self, principal_id: str, session_id: str) -> None:
        async with self._lock:
            graph = self._graphs.pop((principal_id, session_id), None)
            if graph is not None:
                self._graph_keys.pop(graph.graph_id, None)

    def _get_or_create(self, principal_id: str, session_id: str) -> AgentTransitionGraph:
        key = (principal_id, session_id)
        graph = self._graphs.get(key)
        if graph is not None and utc_now() - graph.updated_at > self.ttl:
            self._graphs.pop(key, None)
            self._graph_keys.pop(graph.graph_id, None)
            graph = None
        if graph is None:
            graph = AgentTransitionGraph.empty(principal_id, session_id)
            self._graphs[key] = graph
            self._graph_keys[graph.graph_id] = key
        return graph
