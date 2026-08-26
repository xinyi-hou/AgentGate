from __future__ import annotations

import hashlib
from typing import Any

from agentgate.events.models import utc_now
from agentgate.state.models import SessionSecurityState, StateUpdater


class RedisStateStore:
    def __init__(
        self,
        url: str,
        *,
        ttl_seconds: int = 3600,
        key_prefix: str = "agentgate:session",
        client: Any = None,
    ):
        if client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError("install agentgate[redis] to use RedisStateStore") from exc
            client = Redis.from_url(url, decode_responses=True)
        self.client = client
        self.ttl_seconds = ttl_seconds
        self.key_prefix = key_prefix

    async def get(self, principal: str, session_id: str) -> SessionSecurityState:
        raw = await self.client.get(self._key(principal, session_id))
        if raw is None:
            return SessionSecurityState(principal=principal, session_id=session_id)
        return SessionSecurityState.model_validate_json(raw)

    async def update(
        self,
        principal: str,
        session_id: str,
        updater: StateUpdater,
    ) -> SessionSecurityState:
        try:
            from redis.exceptions import WatchError
        except ImportError as exc:
            raise RuntimeError("install agentgate[redis] to use RedisStateStore") from exc
        key = self._key(principal, session_id)
        while True:
            async with self.client.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    current = (
                        SessionSecurityState.model_validate_json(raw)
                        if raw is not None
                        else SessionSecurityState(principal=principal, session_id=session_id)
                    )
                    updated = updater(current.model_copy(deep=True))
                    if updated.principal != principal or updated.session_id != session_id:
                        raise ValueError("state updater cannot change session identity")
                    updated.updated_at = utc_now()
                    pipe.multi()
                    pipe.set(key, updated.model_dump_json(), ex=self.ttl_seconds)
                    await pipe.execute()
                    return updated.model_copy(deep=True)
                except WatchError:
                    continue

    async def delete(self, principal: str, session_id: str) -> None:
        await self.client.delete(self._key(principal, session_id))

    async def aclose(self) -> None:
        await self.client.aclose()

    def _key(self, principal: str, session_id: str) -> str:
        identity = hashlib.sha256(f"{principal}\0{session_id}".encode()).hexdigest()
        return f"{self.key_prefix}:{identity}"
