from __future__ import annotations

import hashlib
import json
from typing import Any

from agentgate.detection.models import DetectionState, DetectionStateUpdater, RuleMatchState


class RedisDetectionStateStore:
    def __init__(
        self,
        url: str,
        *,
        ttl_seconds: int = 3600,
        key_prefix: str = "agentgate:detection",
        client: Any = None,
    ):
        if client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError(
                    "install agentgate[redis] to use RedisDetectionStateStore"
                ) from exc
            client = Redis.from_url(url, decode_responses=True)
        self.client = client
        self.ttl_seconds = ttl_seconds
        self.key_prefix = key_prefix

    async def get(self, principal: str, session_id: str, policy_version: str) -> DetectionState:
        raw = await self.client.get(self._key(principal, session_id, policy_version))
        return _decode(raw)

    async def update(
        self,
        principal: str,
        session_id: str,
        policy_version: str,
        updater: DetectionStateUpdater,
    ) -> DetectionState:
        try:
            from redis.exceptions import WatchError
        except ImportError as exc:
            raise RuntimeError("install agentgate[redis] to use RedisDetectionStateStore") from exc
        key = self._key(principal, session_id, policy_version)
        while True:
            async with self.client.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    updated = updater(_decode(await pipe.get(key)))
                    payload = {
                        rule_id: [item.model_dump(mode="json") for item in paths]
                        for rule_id, paths in updated.items()
                    }
                    pipe.multi()
                    pipe.set(key, json.dumps(payload), ex=self.ttl_seconds)
                    await pipe.execute()
                    return updated
                except WatchError:
                    continue

    async def delete(self, principal: str, session_id: str) -> None:
        pattern = self._key(principal, session_id, "*")
        async for key in self.client.scan_iter(match=pattern):
            await self.client.delete(key)

    async def aclose(self) -> None:
        await self.client.aclose()

    def _key(self, principal: str, session_id: str, policy_version: str) -> str:
        identity = hashlib.sha256(f"{principal}\0{session_id}".encode()).hexdigest()
        return f"{self.key_prefix}:{identity}:{policy_version}"


def _decode(raw: str | bytes | None) -> DetectionState:
    if raw is None:
        return {}
    payload = json.loads(raw)
    return {
        rule_id: [RuleMatchState.model_validate(item) for item in paths]
        for rule_id, paths in payload.items()
    }
