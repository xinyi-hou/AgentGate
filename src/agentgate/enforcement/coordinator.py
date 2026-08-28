from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol


class SessionExecutionCoordinator(Protocol):
    def lock(self, principal: str, session_id: str) -> AsyncIterator[None]: ...


class LocalSessionExecutionCoordinator:
    def __init__(self) -> None:
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._guard = asyncio.Lock()

    @asynccontextmanager
    async def lock(self, principal: str, session_id: str) -> AsyncIterator[None]:
        key = (principal, session_id)
        async with self._guard:
            lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            yield


class RedisSessionExecutionCoordinator:
    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: int = 300,
        blocking_timeout_seconds: int = 300,
        key_prefix: str = "agentgate:lock",
        client: Any = None,
    ):
        if client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError(
                    "install agentgate[redis] to use RedisSessionExecutionCoordinator"
                ) from exc
            client = Redis.from_url(url, decode_responses=True)
        self.client = client
        self.timeout_seconds = timeout_seconds
        self.blocking_timeout_seconds = blocking_timeout_seconds
        self.key_prefix = key_prefix

    @asynccontextmanager
    async def lock(self, principal: str, session_id: str) -> AsyncIterator[None]:
        identity = hashlib.sha256(f"{principal}\0{session_id}".encode()).hexdigest()
        lock = self.client.lock(
            f"{self.key_prefix}:{identity}",
            timeout=self.timeout_seconds,
            blocking_timeout=self.blocking_timeout_seconds,
        )
        acquired = await lock.acquire()
        if not acquired:
            raise TimeoutError("timed out acquiring the AgentGate session lock")
        try:
            yield
        finally:
            await lock.release()

    async def aclose(self) -> None:
        await self.client.aclose()
