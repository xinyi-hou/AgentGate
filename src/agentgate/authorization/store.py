from __future__ import annotations

import asyncio
from typing import Protocol

from agentgate.authorization.models import TaskAuthorization
from agentgate.events.models import utc_now


class AuthorizationStore(Protocol):
    async def put(self, authorization: TaskAuthorization) -> None: ...

    async def get(self, principal: str, task_id: str) -> TaskAuthorization | None: ...


class MemoryAuthorizationStore:
    """Trusted control-plane store; ordinary tool-call requests cannot write it."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], TaskAuthorization] = {}
        self._lock = asyncio.Lock()

    async def put(self, authorization: TaskAuthorization) -> None:
        async with self._lock:
            key = (authorization.principal, authorization.task_id)
            self._items[key] = authorization.model_copy(deep=True)

    async def get(self, principal: str, task_id: str) -> TaskAuthorization | None:
        async with self._lock:
            item = self._items.get((principal, task_id))
            if item is None:
                return None
            if item.expires_at is not None and utc_now() >= item.expires_at:
                self._items.pop((principal, task_id), None)
                return None
            return item.model_copy(deep=True)

    async def delete(self, principal: str, task_id: str) -> None:
        async with self._lock:
            self._items.pop((principal, task_id), None)
