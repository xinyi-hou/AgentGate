from __future__ import annotations

from typing import Any

from agentgate.graph.models import AgentTransitionGraph, GraphDelta, stable_id


class RedisGraphStore:
    """Optimistically locked ATG storage with the same session TTL as runtime state."""

    def __init__(
        self,
        url: str,
        *,
        ttl_seconds: int = 3600,
        key_prefix: str = "agentgate:graph",
        client: Any = None,
    ):
        if client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError("install agentgate[redis] to use RedisGraphStore") from exc
            client = Redis.from_url(url, decode_responses=True)
        self.client = client
        self.ttl_seconds = ttl_seconds
        self.key_prefix = key_prefix

    async def get_session_graph(
        self,
        principal_id: str,
        session_id: str,
    ) -> AgentTransitionGraph:
        graph_id = stable_id("graph", principal_id, session_id)
        key = self._key(graph_id)
        raw = await self.client.get(key)
        if raw is not None:
            return AgentTransitionGraph.model_validate_json(raw)
        graph = AgentTransitionGraph.empty(principal_id, session_id)
        await self.client.set(key, graph.model_dump_json(), ex=self.ttl_seconds, nx=True)
        raw = await self.client.get(key)
        return AgentTransitionGraph.model_validate_json(raw) if raw else graph

    async def apply_delta(self, graph_id: str, delta: GraphDelta) -> AgentTransitionGraph:
        if delta.graph_id != graph_id:
            raise ValueError("graph delta identity mismatch")
        try:
            from redis.exceptions import WatchError
        except ImportError as exc:
            raise RuntimeError("install agentgate[redis] to use RedisGraphStore") from exc
        key = self._key(graph_id)
        while True:
            async with self.client.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        raise KeyError(f"unknown graph: {graph_id}")
                    graph = AgentTransitionGraph.model_validate_json(raw)
                    graph.apply(delta)
                    pipe.multi()
                    pipe.set(key, graph.model_dump_json(), ex=self.ttl_seconds)
                    await pipe.execute()
                    return graph.model_copy(deep=True)
                except WatchError:
                    continue

    async def delete(self, principal_id: str, session_id: str) -> None:
        graph_id = stable_id("graph", principal_id, session_id)
        await self.client.delete(self._key(graph_id))

    async def aclose(self) -> None:
        await self.client.aclose()

    def _key(self, graph_id: str) -> str:
        return f"{self.key_prefix}:{graph_id.removeprefix('graph:')}"
