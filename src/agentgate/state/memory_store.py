from __future__ import annotations

import asyncio
from datetime import timedelta

from agentgate.events.models import utc_now
from agentgate.state.models import SessionSecurityState, StateUpdater


class MemoryStateStore:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._states: dict[tuple[str, str], SessionSecurityState] = {}
        self._lock = asyncio.Lock()

    async def get(self, principal: str, session_id: str) -> SessionSecurityState:
        async with self._lock:
            state = self._get_or_create(principal, session_id)
            return state.model_copy(deep=True)

    async def update(
        self,
        principal: str,
        session_id: str,
        updater: StateUpdater,
    ) -> SessionSecurityState:
        async with self._lock:
            current = self._get_or_create(principal, session_id).model_copy(deep=True)
            updated = updater(current)
            if updated.principal != principal or updated.session_id != session_id:
                raise ValueError("state updater cannot change session identity")
            updated.updated_at = utc_now()
            self._states[(principal, session_id)] = updated.model_copy(deep=True)
            return updated.model_copy(deep=True)

    async def delete(self, principal: str, session_id: str) -> None:
        async with self._lock:
            self._states.pop((principal, session_id), None)

    def _get_or_create(self, principal: str, session_id: str) -> SessionSecurityState:
        key = (principal, session_id)
        state = self._states.get(key)
        if state is not None and utc_now() - state.updated_at > self.ttl:
            self._states.pop(key, None)
            state = None
        if state is None:
            state = SessionSecurityState(principal=principal, session_id=session_id)
            self._states[key] = state
        return state
